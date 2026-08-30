"""Domain string validation/normalization — shared by every place that
accepts a raw domain typed in by a user (custom/owned domains, ad hoc
dossier requests), so they all reject the same malformed input the
same way instead of drifting apart.
"""

import re

# Deliberately permissive enough to accept Punycode (xn--...) labels, so
# a manually-added IDN homograph domain (see core/variants.py's
# homograph coverage) works here too, not just algorithmically generated.
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def normalize_domain(raw: str) -> str:
    domain = raw.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"{raw!r} doesn't look like a valid domain")
    return domain
