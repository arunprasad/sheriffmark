"""Risk scoring: a simple, explainable weighted heuristic — not a model.

Each factor contributes a fixed number of points and is named in the
result, so a customer-facing "why is this High risk?" is just listing
`RiskResult.factors` rather than explaining a black box.
"""

from dataclasses import dataclass, field

HIGH_RISK_TLDS = {"com", "net", "org"}

_SCORE_WEIGHTS = {
    "edit_distance<=1": 40,
    "edit_distance=2": 20,
    "high_risk_tld": 15,
    "medium_risk_tld": 5,
    "mx_configured": 20,
    "live_https": 15,
    "combosquat_keyword": 10,
}


@dataclass(frozen=True)
class RiskFactors:
    edit_distance: int | None = None
    tld: str | None = None
    has_mx: bool = False
    live_https: bool = False
    combosquat_keyword: bool = False


@dataclass(frozen=True)
class RiskResult:
    score: int
    bucket: str  # "low" | "medium" | "high"
    factors: list[str] = field(default_factory=list)


def tld_risk_bucket(tld: str) -> str:
    return "high" if tld.lower() in HIGH_RISK_TLDS else "medium"


def bucket_for_score(score: int) -> str:
    """Same thresholds `score_finding` uses internally, exposed
    standalone for a caller that ends up with an *already-final* score
    computed outside `score_finding` itself — e.g.
    worker/pipeline.py's `_record_finding`, which can bump a
    caller's pre-computed score (an IP-blocklist hit) after the
    caller already derived its own bucket from the pre-bump number."""
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def levenshtein(a: str, b: str) -> int:
    """Plain DP implementation — domain-length strings, no need for an
    external dependency."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row.append(
                min(
                    previous_row[j] + 1,  # deletion
                    current_row[j - 1] + 1,  # insertion
                    previous_row[j - 1] + cost,  # substitution
                )
            )
        previous_row = current_row
    return previous_row[-1]


def score_finding(factors: RiskFactors) -> RiskResult:
    score = 0
    reasons: list[str] = []

    if factors.edit_distance is not None:
        if factors.edit_distance <= 1:
            score += _SCORE_WEIGHTS["edit_distance<=1"]
            reasons.append("edit_distance<=1")
        elif factors.edit_distance == 2:
            score += _SCORE_WEIGHTS["edit_distance=2"]
            reasons.append("edit_distance=2")

    if factors.tld:
        bucket = tld_risk_bucket(factors.tld)
        if bucket == "high":
            score += _SCORE_WEIGHTS["high_risk_tld"]
            reasons.append("high_risk_tld")
        else:
            score += _SCORE_WEIGHTS["medium_risk_tld"]

    if factors.has_mx:
        score += _SCORE_WEIGHTS["mx_configured"]
        reasons.append("mx_configured")

    if factors.live_https:
        score += _SCORE_WEIGHTS["live_https"]
        reasons.append("live_https")

    if factors.combosquat_keyword:
        score += _SCORE_WEIGHTS["combosquat_keyword"]
        reasons.append("combosquat_keyword")

    score = min(score, 100)
    return RiskResult(score=score, bucket=bucket_for_score(score), factors=reasons)
