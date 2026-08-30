"""Typosquat/lookalike domain variant generation.

Wraps dnstwist's `Fuzzer` (permutation engine — homoglyphs, keyboard
adjacency, transposition, hyphenation, TLD swaps, combosquat dictionary
terms, etc.) rather than reimplementing those tables from scratch. Pure
function: brand config in, deduplicated candidate list out. No network
calls — dnstwist's permutation generation is offline; only its optional
live-scan features (which we don't use here) touch the network.

Includes full IDN/Unicode homograph attacks (e.g. Cyrillic characters
that render visually identical to Latin ones) automatically, via
dnstwist's `cyrillic` and `homoglyph` fuzzer categories — no extra
config needed. Output is valid Punycode (`xn--...`), ready for real
DNS/RDAP queries. See `tests/test_variants.py`'s IDN tests for a
concrete example (a Cyrillic lookalike of "apple").
"""

from dataclasses import dataclass

import dnstwist

# Merged into whatever keywords a brand configures — these are the
# generic combosquat terms that show up across most phishing/abuse
# campaigns regardless of brand.
DEFAULT_COMBOSQUAT_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "support",
    "account",
    "signin",
    "portal",
]

DEFAULT_TLDS = ["com", "net", "org"]


@dataclass(frozen=True)
class Candidate:
    domain: str  # full domain, e.g. "examp1e.com"
    fuzzer: str  # dnstwist category, e.g. "homoglyph", "dictionary", "tld-swap"


def generate_variants(
    brand_name: str,
    keywords: list[str] | None = None,
    tlds: list[str] | None = None,
) -> list[Candidate]:
    """Generate deduplicated typosquat/combosquat candidates for `brand_name`.

    `keywords` extend the built-in combosquat keyword list (e.g. brand +
    "login"). `tlds` controls both which TLD each typosquat fuzzer runs
    against and which TLDs are considered for TLD-swap variants.

    Runs the fuzzer once per TLD and merges/dedupes rather than a full
    variants × TLDs cross product, to keep candidate volume bounded —
    important both for RDAP/DNS check politeness and for plan limits to
    meaningfully cap "variant depth".
    """
    merged_keywords = list(dict.fromkeys([*DEFAULT_COMBOSQUAT_KEYWORDS, *(keywords or [])]))
    merged_tlds = list(dict.fromkeys(tlds or DEFAULT_TLDS))

    seen: dict[str, str] = {}  # domain -> fuzzer category (first hit wins)
    for tld in merged_tlds:
        seed_domain = f"{brand_name}.{tld}"
        fuzzer = dnstwist.Fuzzer(
            seed_domain, dictionary=merged_keywords, tld_dictionary=merged_tlds
        )
        fuzzer.generate()
        for perm in fuzzer.permutations(registered=False):
            if perm["fuzzer"] == "*original":
                continue
            seen.setdefault(perm["domain"], perm["fuzzer"])

    return [
        Candidate(domain=domain, fuzzer=fuzzer_name) for domain, fuzzer_name in sorted(seen.items())
    ]
