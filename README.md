# MedVault – Secure Diagnostic Lab Report Portal

CYC386 Secure Software Design and Development – Midterm Lab DevSecOps Sprint (Fall 2026)

MedVault lets patients upload lab reports (`.lab` files), view them, compress them and share them with their doctors.
A native C library (`native/parser.c`) reads each report header and checks the lab's "verified" signature.

> ⚠️ Commit `98478ce` (main before PR #6) is the deliberately vulnerable baseline used for the lab demonstration
> (Buffer Overflow, Command Injection, IDOR, CSRF, Clickjacking). Run it only on your own machine.
> The current `main` branch contains all fixes.

## Team

- Zojaja Naveed – Developer / Security Tester / DevOps
- Tayyeba Usman (tayyebacodes) – Developer / Security Tester / DevOps

## Tech stack

Python 3.12 · Flask · SQLite · C (shared library via `ctypes`) · Docker · GitHub Actions

## Run with Docker (recommended)

```bash
docker build -t medvault .
docker run --rm -p 5000:5000 --name medvault medvault
```

Open http://localhost:5000

## Test accounts (lab data only)

| Username | Password | Role |
|---|---|---|
| alice | alice123 | patient (owns report 1) |
| bob | bob123 | patient (owns report 2) |
| drkhan | doctor123 | doctor |
| drevil | evil123 | doctor (attacker's account) |

## Project structure

| Path | Purpose |
|---|---|
| `app.py` | Flask application |
| `native/parser.c` | Native report-header parser (`libparser.so`) |
| `native/demo.c` | Command-line driver to test the parser |
| `templates/` | HTML pages |
| `samples/` | Sample `.lab` reports, including overflow payloads |
| `attacker/` | Attacker pages for the CSRF and clickjacking demos |
| `docs/` | PNE report, threat model, diagrams |

## Run the security tests

```bash
gcc -shared -fPIC -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o native/libparser.so native/parser.c
pip install -r requirements.txt pytest
pytest -v tests
```

The same exploit-replay tests, plus AddressSanitizer, Bandit, Semgrep, Trivy and OWASP ZAP, run automatically in
GitHub Actions (`.github/workflows/ci-cd.yml`) on every push and pull request. Merging into `main` requires all checks to pass.

## Documentation

| Document | Contents |
|---|---|
| `Final_Report.pdf` | Final IEEE-style report (editable: `docs/Final_Report.docx`) |
| `PNE_Report.pdf` | Assets, protection needs, CIA mapping |
| `THREAT_MODEL.pdf` | DFDs, STRIDE, attack trees, CVSS v3.1, risk register |
| `SECURITY_IMPLEMENTATION.md` | Each vulnerability: vulnerable code, exploit evidence, fix, verification |
| `SECURITY_TEST_REPORT.md` | SAST/DAST configuration and before/after results |
| `SECURITY.md` / `CONTRIBUTING.md` | Security policy and contribution workflow |
| `docs/screenshots/` | All evidence screenshots |
