# Security Policy – MedVault

## Supported versions

| Version | Supported |
|---|---|
| `main` (hardened) | ✅ |
| Commit `98478ce` (vulnerable baseline) | ❌ Lab demonstration only – never deploy |

## Reporting a vulnerability

Please do **not** open a public issue. Email the maintainers with:
- a description of the issue and its impact,
- steps to reproduce,
- the affected file or endpoint.

We aim to acknowledge reports within 48 hours and fix critical issues within 7 days.

## Security controls in place

| Threat | Control |
|---|---|
| T-01 Buffer overflow | Length check before every copy in `native/parser.c`; `-fstack-protector-strong -D_FORTIFY_SOURCE=2`, full RELRO; ASAN check in CI |
| T-02 Command injection | Allow-list `^[A-Za-z0-9_-]{1,40}$`; `subprocess.run([...], shell=False)` |
| T-03 IDOR | Central `get_report_for_user()` object-level authorization, 404 on denial |
| T-04 CSRF | Per-session synchronizer token on every POST; `SameSite=Strict`, `HttpOnly` cookies |
| T-05 Clickjacking | `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` |
| T-06 Hard-coded secret | `SECRET_KEY` from environment variable `MEDVAULT_SECRET_KEY` |
| T-07 Debug mode | Debug off; production served by gunicorn as a non-root user |
| T-08 Repudiation | Audit log of login, upload, share, compress and denied access |

## Automated security gates

Every push and pull request runs `.github/workflows/ci-cd.yml`: security regression tests, Bandit (fails on High),
Semgrep, Trivy (fails on fixable Critical) and an OWASP ZAP baseline scan.
