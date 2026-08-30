"""Plan-limit enforcement — the single source of truth both `web` and
`worker` call so what's sold and what's enforced never drift apart.

The open-source build ships one plan ("Self-Hosted") with no
`max_brands` key at all, so every check here returns True — usage is
unlimited by default (see shared/models.py's `Plan.limits`). The
mechanism itself stays real rather than stubbed out: a future paid tier
could reintroduce a cap (or add new resource types — CT-poll frequency,
variant depth) by seeding a `limits` value, with zero code change here.
"""

from shared.models import Tenant


def check_limit(tenant: Tenant, resource: str) -> bool:
    """Return True if `tenant` is allowed to use `resource` right now.

    Reads `tenant.plan.limits` and, where relevant, `tenant.brands` —
    both SQLAlchemy relationships, so `tenant` must be attached to a live
    session (true for every caller: this is only ever invoked from
    within a request/worker-run's session scope).
    """
    limits = tenant.plan.limits or {}

    if resource == "brand_create":
        max_brands = limits.get("max_brands")
        if max_brands is None:
            return True
        return len(tenant.brands) < max_brands

    return True
