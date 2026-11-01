# Contributing to MedVault

1. Never push to `main` directly – it is protected.
2. Create a branch: `feature/<name>` for features, `fix/<name>` for security fixes, `docs/<name>` for documentation.
3. Put the Jira key in every commit message and PR title, e.g. `MV-16: enforce object-level authorization`.
4. Open a Pull Request into `main`. It must be reviewed and all pipeline checks must be green before merging.
5. Every security fix must include a regression test in `tests/test_security.py` that fails on the vulnerable code.
6. Never commit secrets, `.env` files, databases or uploaded reports.
7. Record the PR link as a comment on the Jira issue after merging.
