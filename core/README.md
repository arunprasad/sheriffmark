# core/

Pure detection logic: variant generation, DNS/RDAP registration checks, CT
log polling, risk scoring.

**Rules for this package** (what keeps it from ever needing a rewrite as
the SaaS layer changes around it):

- No imports from `shared/`, `web/`, `worker/`, or any ORM/tenant/plan
  concept. Functions take plain values in, return plain dataclasses out.
- No cloud SDKs, no database access.
- Network calls (DNS, RDAP, crt.sh) are allowed — this is where the
  product's actual work happens — but every call site accepts an
  injectable `session`/timeout and fails closed (`status="unknown"`,
  `success=False`) rather than raising, so callers can retry/skip without
  the whole pipeline crashing on one flaky external service.
- Every module is unit-testable with the network mocked out.
