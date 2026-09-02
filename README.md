# Tidewall Collector

An OpenTelemetry Collector distribution that reports AI coding-agent activity
from the machines where it happens.

> **Status: early. Nothing is implemented yet.** This repository currently holds
> its licence and contribution guidance. The design is settled; the build is not
> started. Treat anything below as intent, not capability.

## The problem

Tidewall inspects AI traffic that is routed through it. It has no view of what
runs on a host that never routed anything to it.

This collector reports **which AI coding tools have produced session activity on
an endpoint, and how much**. It is a posture signal, not a detection one.

"Produced session activity" is deliberate: the input is session logs on disk, so
this shows recorded activity within a window. It does not show which tools are
currently running, nor which are merely installed and unused.

**It does not report whether that activity was guarded.** Answering that needs a
correlation key that does not currently exist, so this reports what is running —
not what escaped.

## What it will collect

Session activity from AI coding agents, read directly from wherever each stores
it — JSONL files, JSON trees, or SQLite databases.

**Claude Code is the first target and the reference implementation.** The others
follow: Codex CLI, Claude Desktop, Cursor, Warp, opencode, Cline.

Nothing here is implemented yet, so this is a target list rather than a support
matrix. A platform is listed as supported in this README only once it is.

## What it will not collect

**Prompt and response content never leaves the machine.**

The exported record carries metadata only — which tool, when, which model, how
many turns.

Content is not stripped out of the record. **A record containing it is never
built.** The collector reads each session store, extracts the fields it needs and
constructs the export from those — so there is no filtering step to
misconfigure, and no copy left behind in a field somebody forgot to clear.

This is a deliberate boundary. Reporting that a coding agent ran forty sessions
on a host is asset posture. Collecting what was typed into it is not, and this
component is not built to do it.

It runs as a per-user agent, not a system service. It reads the files of the user
running it, needs no elevated privileges, and that user can stop it.

## How it fits

- **[tidewall-server](https://github.com/tidewall-security/tidewall-server)** —
  the guard that inspects traffic routed to it.
- **[tidewall-otel](https://github.com/tidewall-security/tidewall-otel)** —
  zero-code-change instrumentation for applications calling AI provider SDKs.
- **This repository** — endpoint telemetry for agent activity that reaches
  neither of the above.

The three are independent. This one is an OpenTelemetry Collector distribution
carrying a purpose-built receiver, so it ships as a static binary with the usual
platform packages, works with any OTLP-compatible backend, and is managed by the
same fleet tooling as any other collector.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
