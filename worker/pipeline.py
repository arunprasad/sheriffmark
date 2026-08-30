"""Daily pipeline orchestration.

The generated-variant/RDAP path and the CT-poll path run and fail
independently per brand — a crt.sh outage (a real, reproducible thing —
see core/ct_poller.py) must never block the RDAP path, and vice versa.
Everything here is plain, testable orchestration: core/ does the
actual detection work, adapters/ does the actual I/O, this module just
wires them together and decides what counts as "new" for the digest.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from adapters.ports import FindingSummary, Notifier
from adapters.storage_postgres import (
    create_finding_event,
    get_active_tenants,
    list_reference_images,
    sync_site_graph,
    update_ct_cursor,
    upsert_finding,
)
from core.browser_crawler import render_with_browser
from core.crawler import WebsiteSnapshot, crawl_website
from core.ct_poller import poll_ct_logs
from core.dns_snapshot import DnsSnapshot, get_dns_snapshot
from core.dnsbl import check_domain_blocklist
from core.registration import (
    RegistrationStatus,
    check_registration,
    has_mx_records,
    load_tld_nameservers,
    load_tld_whois_host,
)
from core.risk import RiskFactors, bucket_for_score, levenshtein, score_finding
from core.screenshot import capture_screenshot
from core.site_graph import crawl_site_graph
from core.variants import Candidate, generate_variants
from core.visual_similarity import compare_page_similarity, find_logo_in_screenshot
from shared.models import Brand, Finding, RateLimitState, Tenant

logger = logging.getLogger(__name__)

# Called between units of work (candidates, brands, tenants) to check for
# a requested graceful shutdown. Every external call in core/ already has
# its own bounded timeout, so checking between iterations — rather than
# trying to interrupt a call mid-flight — bounds shutdown latency to
# roughly the longest single in-flight call, which is good enough and far
# simpler than real mid-call cancellation. Defaults to "never stop" so
# every function here works unchanged when called without one (tests,
# and any future caller that doesn't care about graceful shutdown).
ShouldStop = Callable[[], bool]
_never_stop: ShouldStop = lambda: False  # noqa: E731

# Used when a 429 doesn't include a Retry-After header — long enough
# that we're not just hammering straight back into the same limit on
# the very next scheduled run, short enough that a brand isn't left
# unchecked for days over one throttled response.
DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 900.0  # 15 minutes

# How long a single scan pass is allowed to keep resuming before its
# progress is considered too stale to trust and gets discarded in favor
# of a fresh full pass — matches the worker's own daily cadence. A pass
# that's been dragging on across repeated interruptions for longer than
# this is defeating the point of daily monitoring: the candidates
# checked near the start of that pass are now running on day(s)-old
# DNS/RDAP state while the rest of the list is still unchecked.
MAX_SCAN_AGE = timedelta(hours=24)

# A domain whose own IP is already known to a public spam/abuse
# network (core/dnsbl.py) is a strong, independent signal — comparable
# to the highest existing weight (edit_distance<=1's 40, core/risk.py)
# rather than a minor tiebreaker.
BLOCKLIST_RISK_BONUS = 35


def _is_scan_stale(started_at: datetime | None) -> bool:
    if started_at is None:
        return False
    return datetime.now(UTC) - started_at > MAX_SCAN_AGE


class RateLimiter:
    """Tracks whether an external resource ("rdap", "ct") is currently
    rate-limited, persisted (`shared.models.RateLimitState`) so a
    suspension triggered by one worker invocation is honored by the
    next scheduled one, not just for the remainder of the current
    process.

    One instance is shared across an entire `run_daily_pipeline()` call
    and passed down to every brand/tenant that touches the same
    resource: tripping it for one tenant's brand immediately suspends
    every other tenant/brand's use of that resource for the rest of
    this run too. That's deliberate — a rate limit is a property of the
    resource (this worker's outbound IP hitting RDAP, say), not of any
    one brand, so there's no reason to let a second brand walk straight
    into the same wall a few seconds later.
    """

    def __init__(self, session: Session, resource: str):
        self._session = session
        self.resource = resource
        self.tripped = False

    def is_active(self) -> bool:
        if self.tripped:
            return True
        # isinstance-guarded rather than a bare truthiness check so a
        # test session that hasn't configured `.get()` (returning a
        # generic Mock, which is truthy) fails safe as "not rate
        # limited" instead of crashing on `.suspended_until` — real
        # session.get() calls always return a real RateLimitState or
        # None, so this changes nothing about production behavior.
        state = self._session.get(RateLimitState, self.resource)
        if (
            isinstance(state, RateLimitState)
            and state.suspended_until
            and state.suspended_until > datetime.now(UTC)
        ):
            self.tripped = True
            return True
        return False

    def trip(self, retry_after_seconds: float | None) -> None:
        self.tripped = True
        delay = (
            retry_after_seconds
            if retry_after_seconds is not None
            else DEFAULT_RATE_LIMIT_BACKOFF_SECONDS
        )
        suspended_until = datetime.now(UTC) + timedelta(seconds=delay)
        state = self._session.get(RateLimitState, self.resource)
        if isinstance(state, RateLimitState):
            state.suspended_until = suspended_until
        else:
            self._session.add(
                RateLimitState(resource=self.resource, suspended_until=suspended_until)
            )
        logger.warning(
            "%s rate limit hit — suspending %s checks until %s",
            self.resource,
            self.resource,
            suspended_until.isoformat(),
        )


def _detect_dns_changes(previous: DnsSnapshot, current: DnsSnapshot) -> dict | None:
    if previous == DnsSnapshot() or current == previous:
        return None  # no prior snapshot to compare, or nothing changed
    changes = {}
    if current.a_records != previous.a_records:
        changes["a"] = {"old": list(previous.a_records), "new": list(current.a_records)}
    if current.mx_records != previous.mx_records:
        changes["mx"] = {"old": list(previous.mx_records), "new": list(current.mx_records)}
    if current.ns_records != previous.ns_records:
        changes["ns"] = {"old": list(previous.ns_records), "new": list(current.ns_records)}
    return changes or None


def _detect_new_blocklist_hits(previous_hits: dict, current_hits: dict) -> dict | None:
    """Only the *newly*-listed IPs — an IP that was already flagged on
    the prior scan and still is isn't a new incident, just a
    continuing one. Returns None (no event) once nothing new turned
    up, same "nothing changed" contract as `_detect_dns_changes`."""
    new_hits = {ip: codes for ip, codes in current_hits.items() if ip not in previous_hits}
    return new_hits or None


def _record_finding(
    session: Session,
    brand: Brand,
    domain: str,
    source: str,
    status: str,
    registrar: str | None,
    created_date,
    risk_score: int | None,
    risk_factors: list[str],
    abuse_email: str | None = None,
) -> tuple[Finding, bool, bool]:
    """Shared by all three detection paths (generated/CT/manual) instead
    of each calling `upsert_finding` directly — this is where prior state
    gets diffed against newly-acquired data and `FindingEvent` rows get
    emitted. Returns (finding, is_new_row, had_incidents) — callers
    combine `is_new_row` with their own existing notability rule, and
    `had_incidents` is *always* notable on its own: an incident happening
    on a domain we already knew about (a form suddenly appearing on a
    long-parked lookalike) is exactly the kind of thing a single
    point-in-time snapshot would miss and a digest should surface.

    DNS/website acquisition only happens for `status == "registered"` —
    no point crawling a domain that doesn't exist.
    """
    previous = session.get(Finding, {"domain": domain, "brand_id": brand.brand_id})
    previously_registered = previous is not None and previous.status == "registered"
    previous_registrar = previous.registrar if previous else None
    previous_dns = DnsSnapshot.from_dict(previous.dns_snapshot) if previous else DnsSnapshot()
    previous_website = (
        WebsiteSnapshot.from_dict(previous.website_snapshot) if previous else WebsiteSnapshot()
    )

    events: list[tuple[str, dict]] = []
    dns_snapshot_dict: dict | None = None
    website_snapshot_dict: dict | None = None
    site_graph = None
    screenshot_data: bytes | None = None
    screenshot_content_type: str | None = None

    if status == "registered" and not previously_registered:
        events.append(("registered", {"registrar": registrar, "source": source}))
    elif (
        previously_registered
        and registrar
        and previous_registrar
        and registrar != previous_registrar
    ):
        events.append(("whois_change", {"old": previous_registrar, "new": registrar}))

    web_snap = WebsiteSnapshot()  # safe default if acquisition below fails before assignment

    if status == "registered":
        try:
            dns_snap = get_dns_snapshot(domain)
            dns_snapshot_dict = dns_snap.to_dict()
            dns_changes = _detect_dns_changes(previous_dns, dns_snap)
            if dns_changes:
                events.append(("dns_change", dns_changes))

            # Is this domain's own IP already known to a public abuse/
            # spam network? Checked here (not earlier, alongside the
            # rest of risk scoring) because it needs the A records this
            # same DNS acquisition just resolved — see core/dnsbl.py.
            previous_blocklist_hits = (
                (previous.dns_snapshot or {}).get("blocklist", {}) if previous else {}
            )
            blocklist_hits = check_domain_blocklist(dns_snap.a_records)
            if blocklist_hits:
                dns_snapshot_dict["blocklist"] = blocklist_hits
                # Folded into the score/factors here rather than at the
                # caller's earlier risk_score computation — a listed IP
                # is a strong, independent signal worth surfacing
                # regardless of how it was found. Every caller reads
                # the *returned* finding's risk_score back for its own
                # digest FindingSummary (rather than reusing its
                # pre-computed `risk.score`) specifically so this bump
                # is never missed by a same-run notification.
                if "ip_blocklisted" not in risk_factors:
                    risk_factors = [*risk_factors, "ip_blocklisted"]
                    risk_score = min(100, (risk_score or 0) + BLOCKLIST_RISK_BONUS)
            new_blocklist_hits = _detect_new_blocklist_hits(previous_blocklist_hits, blocklist_hits)
            if new_blocklist_hits:
                events.append(("ip_blocklisted", {"ips": new_blocklist_hits}))
        except Exception:
            logger.exception("DNS snapshot acquisition failed for %s", domain)

        try:
            web_snap = crawl_website(domain)
            if web_snap.is_spa:
                # The fast requests-based fetch can't render JS, so its
                # own content fields (forms, hash, text) are meaningless
                # for an SPA shell — re-render with a real browser and
                # use that instead. Root page only, not the full graph —
                # see core/browser_crawler.py's scope note.
                try:
                    browser_snap = render_with_browser(domain)
                    if browser_snap.reachable:
                        web_snap = browser_snap
                except Exception:
                    logger.exception("browser render failed for %s", domain)
            website_snapshot_dict = web_snap.to_dict()
            if web_snap.reachable:
                if (
                    previous_website.content_hash
                    and web_snap.content_hash != previous_website.content_hash
                ):
                    events.append(
                        (
                            "website_change",
                            {
                                "old_hash": previous_website.content_hash,
                                "new_hash": web_snap.content_hash,
                                "snippet": web_snap.text_snippet,
                            },
                        )
                    )
                if web_snap.has_forms and not previous_website.has_forms:
                    events.append(
                        (
                            "form_detected",
                            {
                                "form_count": web_snap.form_count,
                                "has_password_field": web_snap.has_password_field,
                            },
                        )
                    )
                if web_snap.redirect_target and web_snap.redirect_target != (
                    previous_website.redirect_target
                ):
                    events.append(("redirect_detected", {"target": web_snap.redirect_target}))
                if web_snap.is_spa and not previous_website.is_spa:
                    # Detect and log, don't try to crawl through it — see
                    # core/spa_detection.py. Surfaced as an incident too:
                    # "this domain needs the future browser-based crawler
                    # to actually see its content" is worth knowing about
                    # per-domain, not just in worker logs.
                    logger.warning(
                        "SPA detected for %s (server-rendered crawler can't see its "
                        "content — needs a browser-based crawler): %s",
                        domain,
                        list(web_snap.spa_signals),
                    )
                    events.append(("spa_detected", {"signals": list(web_snap.spa_signals)}))
        except Exception:
            logger.exception("website crawl failed for %s", domain)

        # Screenshot capture + visual similarity: only on first
        # registration or when content_hash actually changed — not
        # every scan, to keep Playwright launches bounded to "new or
        # changed sites." Compared against the brand's own uploaded
        # reference images (logos, real-site screenshots), not a fixed
        # catalog — see core/visual_similarity.py.
        should_capture_screenshot = web_snap.reachable and (
            not previously_registered
            or (
                previous_website.content_hash
                and web_snap.content_hash != previous_website.content_hash
            )
        )
        if should_capture_screenshot:
            try:
                screenshot_bytes = capture_screenshot(domain)
            except Exception:
                logger.exception("screenshot capture failed for %s", domain)
                screenshot_bytes = None

            if screenshot_bytes:
                screenshot_data = screenshot_bytes
                screenshot_content_type = "image/png"
                try:
                    for ref in list_reference_images(session, brand_id=brand.brand_id):
                        if ref.kind == "logo":
                            result = find_logo_in_screenshot(ref.image_data, screenshot_bytes)
                            event_type = "logo_match_detected"
                        elif ref.kind == "site_screenshot":
                            result = compare_page_similarity(ref.image_data, screenshot_bytes)
                            event_type = "site_clone_detected"
                        else:
                            continue
                        if result.is_match:
                            events.append(
                                (
                                    event_type,
                                    {
                                        "reference_image_id": str(ref.id),
                                        "reference_filename": ref.filename,
                                        "score": result.score,
                                        "detail": result.detail,
                                    },
                                )
                            )
                except Exception:
                    logger.exception("visual similarity comparison failed for %s", domain)

        # Site graph: a separate, bounded multi-page crawl (depth 2, ~25
        # pages — core/site_spider.py) alongside the single-page snapshot
        # above. Persisted directly, not diffed into FindingEvents here —
        # it's a structural map of the site (pages + links), not another
        # incident signal on top of what website_change/form_detected
        # above already cover. Crawled here (acquisition happens with
        # everything else), but *synced* after upsert_finding below —
        # crawled_pages/page_links composite-FK to findings(domain,
        # brand_id), which doesn't exist yet on a first-ever registration
        # until that upsert runs.
        try:
            site_graph = crawl_site_graph(domain)
            spa_pages = [p for p in site_graph.pages if p.is_spa]
            if spa_pages:
                logger.warning(
                    "SPA detected in site graph for %s (%d/%d pages — server-rendered "
                    "crawler can't see their content, needs a browser-based crawler)",
                    domain,
                    len(spa_pages),
                    len(site_graph.pages),
                )
        except Exception:
            logger.exception("site graph crawl failed for %s", domain)
            site_graph = None

    finding, is_new = upsert_finding(
        session,
        brand_id=brand.brand_id,
        domain=domain,
        source=source,
        status=status,
        registrar=registrar,
        created_date=created_date,
        abuse_email=abuse_email,
        risk_score=risk_score,
        risk_factors=risk_factors,
        dns_snapshot=dns_snapshot_dict,
        website_snapshot=website_snapshot_dict,
        screenshot_data=screenshot_data,
        screenshot_content_type=screenshot_content_type,
    )

    if site_graph is not None and (site_graph.pages or site_graph.links):
        try:
            sync_site_graph(
                session,
                brand_id=brand.brand_id,
                domain=domain,
                pages=[p.__dict__ for p in site_graph.pages],
                links=[link.__dict__ for link in site_graph.links],
            )
        except Exception:
            logger.exception("site graph sync failed for %s", domain)

    for event_type, details in events:
        create_finding_event(
            session, brand_id=brand.brand_id, domain=domain, event_type=event_type, details=details
        )

    return finding, is_new, len(events) > 0


def _owned_domain_seed_names(brand: Brand) -> list[str]:
    """Best-effort label extraction (not a full public-suffix-list
    lookup — good enough for a user-declared apex domain like
    'acme-shop.com') for feeding an owned domain into generate_variants
    the same way brand.name already is."""
    return [d.split(".")[0] for d in brand.owned_domains]


def _generate_all_candidates(brand: Brand) -> list[Candidate]:
    """Typosquat candidates for the brand name *and* for every domain
    the tenant has declared as already owned (Brand.owned_domains) — a
    squat of an owned secondary/defensive domain is worth catching too,
    not just a squat of the primary brand name. The owned domains
    themselves are filtered out of the result by the caller
    (process_brand_generated), since they're legitimate, not a threat."""
    seed_names = [brand.name, *_owned_domain_seed_names(brand)]
    merged: dict[str, str] = {}
    for name in seed_names:
        try:
            for c in generate_variants(name, keywords=brand.keywords, tlds=brand.tlds):
                merged.setdefault(c.domain, c.fuzzer)
        except Exception:
            logger.exception(
                "variant generation failed for seed %r (brand %s)", name, brand.brand_id
            )
    return [Candidate(domain=domain, fuzzer=fuzzer) for domain, fuzzer in sorted(merged.items())]


def _resume_index_str(domains: list[str], cursor: str | None) -> int:
    """Where to pick up in `domains` given a persisted cursor (the last
    one successfully checked last time). Falls back to the start if the
    cursor isn't in this run's list at all — config changed since the
    cursor was set, and there's no meaningful resume point in a list
    that no longer contains it."""
    if not cursor:
        return 0
    try:
        return domains.index(cursor) + 1
    except ValueError:
        return 0


def _resume_index(candidates: list[Candidate], cursor: str | None) -> int:
    return _resume_index_str([c.domain for c in candidates], cursor)


def process_brand_generated(
    session: Session,
    brand: Brand,
    should_stop: ShouldStop = _never_stop,
    rate_limiter: "RateLimiter | None" = None,
) -> list[FindingSummary]:
    """Variant generation + DNS/RDAP check path. Only registered domains
    become findings — an unregistered lookalike isn't a finding yet.

    Resumable: `brand.generated_scan_cursor` checkpoints the last
    candidate successfully checked, so a run that stops early (graceful
    shutdown or an RDAP rate limit — see RateLimiter) picks up from
    there next time instead of re-checking everything from the start,
    and a full completed pass clears the cursor so the next scheduled
    run still gets a fresh check of the whole list, not just whatever's
    new. The candidate list itself (core/variants.py's dnstwist output)
    is deterministic and sorted for a given brand config, which is what
    makes resuming by domain name — rather than a raw index — safe
    across separate runs.
    """
    new_findings: list[FindingSummary] = []
    rate_limiter = rate_limiter or RateLimiter(session, "rdap")

    if rate_limiter.is_active():
        logger.warning(
            "RDAP rate limit active — skipping generated-path scan for brand %s", brand.brand_id
        )
        return new_findings

    candidates = _generate_all_candidates(brand)
    if not candidates:
        return new_findings

    # Owned domains are legitimate, not squats — filtered out before the
    # network-check loop below, not after, so we don't spend an RDAP/DNS
    # check confirming what the tenant already told us they own.
    owned = set(brand.owned_domains)
    candidates = [c for c in candidates if c.domain not in owned]
    seed_names = [brand.name, *_owned_domain_seed_names(brand)]

    if _is_scan_stale(brand.generated_scan_started_at):
        logger.warning(
            "generated-path scan for brand %s has been resuming for over %s — "
            "discarding stale progress and starting a fresh pass",
            brand.brand_id,
            MAX_SCAN_AGE,
        )
        brand.generated_scan_cursor = None
        brand.generated_scan_started_at = None

    start = _resume_index(candidates, brand.generated_scan_cursor)
    if start:
        logger.info(
            "resuming generated-path scan for brand %s at candidate %d/%d",
            brand.brand_id,
            start,
            len(candidates),
        )
    else:
        brand.generated_scan_started_at = datetime.now(UTC)
    remaining = candidates[start:]

    ns_cache: dict[str, list[tuple[str, str]]] = {}
    whois_host_cache: dict[str, str | None] = {}

    for i, candidate in enumerate(remaining):
        if should_stop():
            logger.warning(
                "shutdown requested — stopping mid-scan for brand %s (%d/%d candidates checked)",
                brand.brand_id,
                start + i,
                len(candidates),
            )
            break

        tld = candidate.domain.rsplit(".", 1)[-1]
        if tld not in ns_cache:
            try:
                ns_cache[tld] = load_tld_nameservers(tld)
            except Exception:
                logger.exception("nameserver lookup failed for tld %s", tld)
                ns_cache[tld] = []
        if tld not in whois_host_cache:
            try:
                whois_host_cache[tld] = load_tld_whois_host(tld)
            except Exception:
                logger.exception("whois host lookup failed for tld %s", tld)
                whois_host_cache[tld] = None

        try:
            reg_status = check_registration(
                candidate.domain, ns_servers=ns_cache[tld], whois_host=whois_host_cache[tld]
            )
        except Exception:
            logger.exception("registration check failed for %s", candidate.domain)
            brand.generated_scan_cursor = candidate.domain
            continue

        if reg_status.rate_limited:
            # Deliberately don't advance the cursor past this candidate
            # — it wasn't actually checked, so the next run (once the
            # suspension lifts) should retry it, not skip it.
            rate_limiter.trip(reg_status.retry_after_seconds)
            break

        brand.generated_scan_cursor = candidate.domain

        if reg_status.status != "registered":
            continue

        has_mx = has_mx_records(candidate.domain)
        # Distance to whichever seed (brand name or an owned domain) the
        # candidate actually resembles most closely — a squat of an
        # owned domain scored against only brand.name would understate
        # how close a match it really is.
        candidate_label = candidate.domain.split(".")[0]
        edit_distance = min(levenshtein(name, candidate_label) for name in seed_names)
        risk = score_finding(
            RiskFactors(
                edit_distance=edit_distance,
                tld=tld,
                has_mx=has_mx,
                live_https=False,  # not checked on this path — see core/screenshot.py
                combosquat_keyword=candidate.fuzzer == "dictionary",
            )
        )

        finding, is_new, had_incidents = _record_finding(
            session,
            brand,
            candidate.domain,
            source="generated",
            status="registered",
            registrar=reg_status.registrar,
            created_date=reg_status.created_date,
            abuse_email=reg_status.abuse_email,
            risk_score=risk.score,
            risk_factors=risk.factors,
        )
        if is_new or had_incidents:
            # Read back from `finding`, not the pre-computed `risk`
            # above — _record_finding can still bump the score after
            # the fact (an IP-blocklist hit, discovered only once DNS
            # is acquired inside it), and the digest should never
            # report a lower score than what's actually stored.
            new_findings.append(
                FindingSummary(
                    domain=candidate.domain,
                    brand_name=brand.name,
                    source="generated",
                    status="registered",
                    risk_score=finding.risk_score,
                    risk_bucket=bucket_for_score(finding.risk_score),
                )
            )
    else:
        # Completed the whole remaining list without an early break —
        # a full pass is done, so the next scheduled run should start
        # fresh rather than perpetually resuming at the end.
        brand.generated_scan_cursor = None
        brand.generated_scan_started_at = None
        brand.last_scan_completed_at = datetime.now(UTC)

    return new_findings


def process_brand_ct(
    session: Session,
    brand: Brand,
    should_stop: ShouldStop = _never_stop,
    rate_limiter: "RateLimiter | None" = None,
) -> list[FindingSummary]:
    """CT log poll path. A cert being issued strongly implies the domain
    is registered and live — scored with live_https=True accordingly.

    Resumable via the existing `ct_last_cert_id` cursor, which already
    only advances past hits actually processed — a rate-limited or
    otherwise failed poll simply doesn't move it, so the next scheduled
    run naturally re-polls from the same point. No separate checkpoint
    needed here the way the generated path needs one.
    """
    new_findings: list[FindingSummary] = []
    rate_limiter = rate_limiter or RateLimiter(session, "ct")

    if should_stop():
        # Checked upfront (not just in the hits loop below) so a shutdown
        # requested while the generated-path scan for this same brand was
        # still running doesn't cost one more full CT poll round-trip —
        # found via a live shutdown test where crt.sh's own response time
        # was the last thing standing between signal and exit.
        logger.warning("shutdown requested — skipping CT poll for brand %s", brand.brand_id)
        return new_findings

    if rate_limiter.is_active():
        logger.warning("crt.sh rate limit active — skipping CT poll for brand %s", brand.brand_id)
        return new_findings

    try:
        result = poll_ct_logs(brand.name, since_cert_id=brand.ct_last_cert_id or 0)
    except Exception:
        logger.exception("CT poll raised for brand %s", brand.brand_id)
        return new_findings

    if result.rate_limited:
        rate_limiter.trip(result.retry_after_seconds)
        return new_findings

    if not result.success:
        logger.warning("CT poll failed for brand %s — will retry next run", brand.brand_id)
        return new_findings

    # Only advance the cursor as far as we actually persist — not blindly
    # to result.max_cert_id, which covers the whole batch regardless of
    # whether a graceful-shutdown break cut the loop short. Advancing past
    # unprocessed hits would silently skip them on the next run.
    highest_processed = brand.ct_last_cert_id or 0

    for hit in result.hits:
        if should_stop():
            logger.warning(
                "shutdown requested — stopping mid CT-hit processing for brand %s", brand.brand_id
            )
            break

        domain = hit.common_name.lstrip("*.").strip().lower()
        if not domain or "." not in domain:
            continue
        if domain in brand.owned_domains:
            # Legitimate — a cert for a domain the tenant already told
            # us they own, not a threat. Still counts toward cursor
            # advancement below (it was seen and handled), just isn't
            # recorded as a finding.
            highest_processed = max(highest_processed, hit.cert_id)
            continue

        tld = domain.rsplit(".", 1)[-1]
        risk = score_finding(
            RiskFactors(
                edit_distance=levenshtein(brand.name, domain.split(".")[0]),
                tld=tld,
                has_mx=has_mx_records(domain),
                live_https=True,
                combosquat_keyword=any(k in domain for k in brand.keywords),
            )
        )

        finding, is_new, had_incidents = _record_finding(
            session,
            brand,
            domain,
            source="ct",
            status="registered",
            registrar=None,
            created_date=None,
            risk_score=risk.score,
            risk_factors=risk.factors,
        )
        if is_new or had_incidents:
            # Read back from `finding`, not `risk` — see the matching
            # comment in process_brand_generated.
            new_findings.append(
                FindingSummary(
                    domain=domain,
                    brand_name=brand.name,
                    source="ct",
                    status="registered",
                    risk_score=finding.risk_score,
                    risk_bucket=bucket_for_score(finding.risk_score),
                )
            )

        highest_processed = max(highest_processed, hit.cert_id)

    if highest_processed > (brand.ct_last_cert_id or 0):
        update_ct_cursor(session, brand, highest_processed)

    return new_findings


def process_brand_custom(
    session: Session,
    brand: Brand,
    should_stop: ShouldStop = _never_stop,
    rate_limiter: "RateLimiter | None" = None,
) -> list[FindingSummary]:
    """Manual watchlist path — exact domains a user explicitly added
    because dnstwist's algorithmic generation missed something they were
    worried about. Checked the same way as generated candidates
    (`core/registration.py`, `core/risk.py`), tagged `source="manual"`.

    Unlike the generated path, **both registered and unregistered status
    get persisted here** — the list is small (a handful of user-added
    entries, not thousands of algorithmic candidates), and "watching,
    not registered yet" is itself useful confirmation the system is
    actually tracking what was asked, rather than looking like nothing
    happened.

    Because unregistered entries are persisted, a plain "is this a new
    row" check (as the generated/CT paths use) isn't the right
    notability signal here — a domain sitting unregistered for weeks
    would only ever be "new" once, the day it was added, when there's
    nothing actually alert-worthy yet. `_record_finding`'s own
    "registered" event (fired on transition into registered status) is
    exactly the right notability signal and is used directly below —
    also means a manually-watched domain gets the same incident timeline
    (DNS/website change detection) as an algorithmically-found one.
    """
    new_findings: list[FindingSummary] = []
    rate_limiter = rate_limiter or RateLimiter(session, "rdap")

    if rate_limiter.is_active():
        logger.warning(
            "RDAP rate limit active — skipping custom-domain scan for brand %s", brand.brand_id
        )
        return new_findings

    domains = [d for d in brand.custom_domains if d not in brand.owned_domains]

    if _is_scan_stale(brand.custom_scan_started_at):
        logger.warning(
            "custom-domain scan for brand %s has been resuming for over %s — "
            "discarding stale progress and starting a fresh pass",
            brand.brand_id,
            MAX_SCAN_AGE,
        )
        brand.custom_scan_cursor = None
        brand.custom_scan_started_at = None

    start = _resume_index_str(domains, brand.custom_scan_cursor)
    if not start:
        brand.custom_scan_started_at = datetime.now(UTC)
    remaining = domains[start:]

    ns_cache: dict[str, list[tuple[str, str]]] = {}
    whois_host_cache: dict[str, str | None] = {}

    for i, domain in enumerate(remaining):
        if should_stop():
            logger.warning(
                "shutdown requested — stopping mid-scan for brand %s "
                "(%d/%d custom domains checked)",
                brand.brand_id,
                start + i,
                len(domains),
            )
            break

        if "." not in domain:
            logger.warning(
                "skipping malformed custom domain %r for brand %s", domain, brand.brand_id
            )
            brand.custom_scan_cursor = domain
            continue

        tld = domain.rsplit(".", 1)[-1]

        if tld not in ns_cache:
            try:
                ns_cache[tld] = load_tld_nameservers(tld)
            except Exception:
                logger.exception("nameserver lookup failed for tld %s", tld)
                ns_cache[tld] = []
        if tld not in whois_host_cache:
            try:
                whois_host_cache[tld] = load_tld_whois_host(tld)
            except Exception:
                logger.exception("whois host lookup failed for tld %s", tld)
                whois_host_cache[tld] = None

        try:
            reg_status = check_registration(
                domain, ns_servers=ns_cache[tld], whois_host=whois_host_cache[tld]
            )
        except Exception:
            logger.exception("registration check failed for custom domain %s", domain)
            brand.custom_scan_cursor = domain
            continue

        if reg_status.rate_limited:
            rate_limiter.trip(reg_status.retry_after_seconds)
            break

        brand.custom_scan_cursor = domain

        if reg_status.status == "unknown":
            continue  # transient failure — try again next run, not a real status yet

        status = "registered" if reg_status.status == "registered" else "unregistered"
        has_mx = has_mx_records(domain) if status == "registered" else False
        risk = score_finding(
            RiskFactors(
                edit_distance=levenshtein(brand.name, domain.split(".")[0]),
                tld=tld,
                has_mx=has_mx,
                live_https=False,
                combosquat_keyword=any(k in domain for k in brand.keywords),
            )
        )

        # _record_finding's own "registered" event (fired on transition
        # into registered status, from either no-prior-row or a prior
        # "unregistered" row) exactly matches what notability means for
        # a manual watchlist entry — no separate transition check needed
        # here anymore.
        finding, is_new, had_incidents = _record_finding(
            session,
            brand,
            domain,
            source="manual",
            status=status,
            registrar=reg_status.registrar,
            created_date=reg_status.created_date,
            abuse_email=reg_status.abuse_email,
            risk_score=risk.score,
            risk_factors=risk.factors,
        )

        if (is_new and status == "registered") or had_incidents:
            # Read back from `finding`, not `risk` — see the matching
            # comment in process_brand_generated.
            new_findings.append(
                FindingSummary(
                    domain=domain,
                    brand_name=brand.name,
                    source="manual",
                    status=status,
                    risk_score=finding.risk_score,
                    risk_bucket=bucket_for_score(finding.risk_score),
                )
            )
    else:
        brand.custom_scan_cursor = None
        brand.custom_scan_started_at = None

    return new_findings


def run_on_demand_scan(session: Session, brand: Brand, domain: str) -> RegistrationStatus:
    """The ad hoc counterpart to `process_brand_custom`'s per-domain
    check — started immediately by an API request
    (web/api/routes/on_demand_scans.py) for a caller who already has a
    specific domain in mind ("i tell the domain, you give me the
    evidence"), not the daily cron working through a watchlist.

    Writes a real `Finding` via the same `_record_finding` every other
    detection path uses (`source="on_demand"`), so the result shows up
    in the regular Findings UI — incident timeline, resolution
    workflow, CSV export, all of it — with no separate evidence viewer
    needed. Deliberately does *not* add `domain` to
    `brand.custom_domains`: a one-off check doesn't imply "watch this
    forever" — that's the existing, separate, explicit action.

    Respects the same global RDAP rate limiter as every other path —
    an ad hoc lookup doesn't get to bypass a suspension the daily
    worker is already honoring. Returns the raw `RegistrationStatus`
    (rather than the Finding) so the caller can distinguish "rate
    limited, try later" and "genuinely couldn't tell" from an actual
    recorded result — mirrors `check_registration`'s own fail-closed
    contract, never raises.
    """
    rate_limiter = RateLimiter(session, "rdap")
    if rate_limiter.is_active():
        return RegistrationStatus(status="unknown", rate_limited=True)

    tld = domain.rsplit(".", 1)[-1]
    try:
        ns_servers = load_tld_nameservers(tld)
    except Exception:
        logger.exception("nameserver lookup failed for tld %s", tld)
        ns_servers = []
    try:
        whois_host = load_tld_whois_host(tld)
    except Exception:
        logger.exception("whois host lookup failed for tld %s", tld)
        whois_host = None

    reg_status = check_registration(domain, ns_servers=ns_servers, whois_host=whois_host)

    if reg_status.rate_limited:
        rate_limiter.trip(reg_status.retry_after_seconds)
        session.commit()  # persist the trip — this call is its own unit of work,
        return reg_status  # unlike process_tenant's callers, which commit once per tenant

    if reg_status.status == "unknown":
        return reg_status

    status = "registered" if reg_status.status == "registered" else "unregistered"
    has_mx = has_mx_records(domain) if status == "registered" else False
    risk = score_finding(
        RiskFactors(
            edit_distance=levenshtein(brand.name, domain.split(".")[0]),
            tld=tld,
            has_mx=has_mx,
            live_https=False,
            combosquat_keyword=any(k in domain for k in brand.keywords),
        )
    )

    _record_finding(
        session,
        brand,
        domain,
        source="on_demand",
        status=status,
        registrar=reg_status.registrar,
        created_date=reg_status.created_date,
        abuse_email=reg_status.abuse_email,
        risk_score=risk.score,
        risk_factors=risk.factors,
    )
    session.commit()

    return reg_status


def process_tenant(
    session: Session,
    tenant: Tenant,
    should_stop: ShouldStop = _never_stop,
    rdap_limiter: "RateLimiter | None" = None,
    ct_limiter: "RateLimiter | None" = None,
) -> list[FindingSummary]:
    # Defaults here (rather than only in run_daily_pipeline) so a
    # direct call to process_tenant — as every existing test does —
    # still gets correctly-scoped limiters instead of silently skipping
    # them; callers that DO want one suspension shared across many
    # tenants (the real run_daily_pipeline path) pass their own in.
    rdap_limiter = rdap_limiter or RateLimiter(session, "rdap")
    ct_limiter = ct_limiter or RateLimiter(session, "ct")

    new_findings: list[FindingSummary] = []
    for brand in tenant.brands:
        if should_stop():
            logger.warning(
                "shutdown requested — stopping before further brands for tenant %s",
                tenant.tenant_id,
            )
            break
        if not brand.active:
            continue
        new_findings.extend(process_brand_generated(session, brand, should_stop, rdap_limiter))
        new_findings.extend(process_brand_ct(session, brand, should_stop, ct_limiter))
        new_findings.extend(process_brand_custom(session, brand, should_stop, rdap_limiter))
    return new_findings


# Maps a notification channel key to how its destination is read off a
# tenant. "email" uses the existing `contact_email` column (predates
# multi-channel support); the rest read from `notification_channels`
# JSONB (see shared/models.py, migrations/versions/20260823_010000_*).
_CHANNEL_DESTINATIONS: dict[str, Callable[[Tenant], str | None]] = {
    "email": lambda tenant: tenant.contact_email,
    "slack": lambda tenant: (tenant.notification_channels or {}).get("slack_webhook_url"),
    "discord": lambda tenant: (tenant.notification_channels or {}).get("discord_webhook_url"),
    "webhook": lambda tenant: (tenant.notification_channels or {}).get("webhook_url"),
}


def dispatch_notifications(
    tenant: Tenant, findings: list[FindingSummary], notifiers: dict[str, Notifier]
) -> int:
    """Sends the digest to every channel `tenant` has a destination
    configured for. Each channel fails independently — a bad Slack
    webhook URL doesn't block email, or vice versa. Returns how many
    channels actually sent successfully."""
    sent = 0
    for channel, notifier in notifiers.items():
        get_destination = _CHANNEL_DESTINATIONS.get(channel)
        if get_destination is None:
            continue
        destination = get_destination(tenant)
        if not destination:
            continue
        try:
            notifier.send_digest(destination, tenant.name, findings)
            sent += 1
        except Exception:
            logger.exception("digest send failed for tenant %s via %s", tenant.tenant_id, channel)
    return sent


def run_daily_pipeline(
    session: Session, notifiers: dict[str, Notifier], should_stop: ShouldStop = _never_stop
) -> dict:
    """Entry point called by worker/main.py. Commits per tenant so one
    tenant's failure can't roll back another's already-processed work.

    `notifiers` maps channel key ("email", "slack", "discord", "webhook")
    to a `Notifier` implementation — which channels actually fire per
    tenant depends on what that tenant has configured a destination for
    (see `dispatch_notifications`), not on which keys are present here.

    `should_stop` is checked between tenants and threaded down into every
    inner loop, so a graceful-shutdown request (SIGTERM) stops the run at
    the next safe point — bounded by whatever single call is in flight —
    and still commits whatever was completed before the request arrived,
    rather than discarding it.

    One `RateLimiter` each for "rdap" and "ct" is created here and
    shared across every tenant/brand this run touches — see
    `RateLimiter`'s docstring for why a rate limit tripped for one
    tenant's brand should suspend every other tenant's use of the same
    resource for the rest of this run too, not just that one brand's.
    """
    summary = {"tenants_processed": 0, "new_findings": 0, "digests_sent": 0}
    rdap_limiter = RateLimiter(session, "rdap")
    ct_limiter = RateLimiter(session, "ct")

    for tenant in get_active_tenants(session):
        if should_stop():
            logger.warning("shutdown requested — stopping before processing further tenants")
            break

        try:
            new_findings = process_tenant(session, tenant, should_stop, rdap_limiter, ct_limiter)
            session.commit()
        except Exception:
            logger.exception("pipeline failed for tenant %s", tenant.tenant_id)
            session.rollback()
            continue

        summary["tenants_processed"] += 1
        summary["new_findings"] += len(new_findings)

        if new_findings:
            summary["digests_sent"] += dispatch_notifications(tenant, new_findings, notifiers)

    # Surfaced in the run summary (worker/main.py logs this) so an
    # operator can tell "we stopped early because of a rate limit" from
    # a glance at the log line, without needing to query
    # rate_limit_state directly.
    summary["rate_limited_resources"] = [
        limiter.resource for limiter in (rdap_limiter, ct_limiter) if limiter.tripped
    ]

    return summary
