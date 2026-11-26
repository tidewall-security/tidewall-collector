# Collector CI

Collector CI runs on GitHub-hosted Ubuntu 24.04 with Python 3.13.14 for pull
requests and pushes to `main`. It also supports manual dispatch. The job runs the
full Collector suite against current Server
`a7fa9b81172c75427210bc23d2306129a08b66fe` and the backend and installed foundation
tests against Phase 1 Server `e1a8fd55e3109664ac781189f78007a56ea0f39e`.

The two public Server checkouts share one environment installed from the current
Server lockfile. The workflow verifies that each interpreter imports the
receiver from the intended checkout and that only current Server has native
decisions. The dependency sync includes Server's existing hash-pinned spaCy
model wheel. The tests use offline model flags, temporary SQLite, a local
simulated classifier and simulated Claude callbacks. They require no Claude
account, native inference, classifier weight downloads or user secrets.

Both suites run even if the first returns nonzero. The check fails if either
pytest step fails to finish successfully or if either JUnit report is missing,
invalid, empty or contains skips, failures or errors. Test totals can grow
without editing the workflow. The job logs the Server revisions, build tool
versions and SHA256 of the wheel built by each installed-test fixture. An
intentional change to the wheel requires requalifying its digest in
`workflows/ci.yml`. CI retains the JUnit XML reports for seven days.

To replay the suites from the Collector repository, use a test environment with
the versions pinned in `workflows/ci.yml` and point each command at a local checkout
of the corresponding Server revision. The Phase 1 checkout can link its
`.venv` to the current Server environment.

```bash
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TIDEWALL_SERVER_ROOT="$SERVER_CURRENT" \
  python -m pytest -q
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TIDEWALL_SERVER_ROOT="$SERVER_PHASE1" \
  python -m pytest -q tests/test_backend.py tests/test_foundation_roundtrip.py
```
