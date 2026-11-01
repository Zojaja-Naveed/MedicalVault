# MedVault – Secure Diagnostic Lab Report Portal

CYC386 Secure Software Design and Development – Midterm Lab DevSecOps Sprint (Fall 2026)

MedVault lets patients upload lab reports (`.lab` files), view them, compress them and share them with their doctors.
A native C library (`native/parser.c`) reads each report header and checks the lab's "verified" signature.

> ⚠️ The `v0-vulnerable` tag contains five deliberate vulnerabilities for the lab demonstration
> (Buffer Overflow, Command Injection, IDOR, CSRF, Clickjacking). Run it only on your own machine.

## Team

- Zojaja Naveed – Developer / Security Tester / DevOps
- tayyebacodes – Developer / Security Tester / DevOps

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

## Documentation

- `PNE_Report.pdf` – protection needs and CIA mapping
- `THREAT_MODEL.pdf` – DFDs, STRIDE, attack trees, CVSS, risk register
