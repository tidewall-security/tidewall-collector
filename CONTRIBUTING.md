# Contributing to Tidewall Collector

Issues and pull requests are welcome for the Python/POSIX fixture collector.

## Code of Conduct

Be respectful and constructive. Personal attacks, harassment, or
discriminatory behaviour are not tolerated in any project channel.
By participating, you agree to abide by the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Reporting Bugs

Include the following details in a bug report.

- A short title that names the symptom.
- The exact command or code that triggers it.
- What you expected to happen.
- The observed result and diagnostic code using synthetic input.
- The collector version, Python and SQLite versions, OS and architecture.
  Keep registration and recovery credentials, codes, and private inputs out of
  issues and logs.

## Suggesting Features

Open an issue describing the use case before opening a PR — features
are easier to discuss when there's a problem statement to anchor to.

## Pull Requests

1. Fork the repo and create a topic branch from `main`.
2. Make your change in the smallest reasonable diff. Multiple unrelated
   changes belong in separate PRs.
3. Add or update tests for any behavioural change. Tests live in
   `tests/` and run from the repository root.
4. Update documentation if you change anything user-facing
   (env vars, CLI flags, config keys, error messages).
5. Run the development checks below. For transport changes include the
   installed-client roundtrip against the paired receiver checkout.
6. Open the PR with a clear description of the problem and the change.

## Development Setup

Use a POSIX Python 3.13+ environment with SQLite serialization support.
For development install pytest, pip, setuptools 77+ and wheel in the build
environment. The wheel has zero third-party runtime dependencies. From the
repository root, run the local collector suite and build the wheel.

```sh
python -m pytest -q
python -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir dist .
```

Standalone socket and TLS fixtures use loopback. To run the installed-client
tests too, set `TIDEWALL_SERVER_ROOT` to the compatible receiver checkout with
its native `.venv` and run the suite again.

```sh
TIDEWALL_SERVER_ROOT="$SERVER_CHECKOUT" python -m pytest -q
```

The README includes the private wheel installation and fixture workflow.
Preserve Apache 2.0 attribution in LICENSE, NOTICE and the vendored source
lock when changing extracted upstream code. [Development and installation](README.md)

## Style

- Code should be type-annotated and pass `mypy` cleanly.
- Comments explain *why*, not *what* — the code already shows what it does.
- Keep public API surface area small. New symbols added to a module's
  top level should be added to `__all__`.

## Security Findings

Don't open a public issue for a security vulnerability — see
[SECURITY.md](./SECURITY.md) for the disclosure process.
