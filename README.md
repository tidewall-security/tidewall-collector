# Tidewall Collector

An OpenTelemetry Collector distribution that reports AI coding-agent activity
from the machines where it happens.

> **Status: early. Nothing is implemented yet.** This repository currently holds
> its licence and contribution guidance. The design is settled; the build is not
> started. Treat anything below as intent, not capability.

## The problem

Tidewall inspects AI traffic that is routed through it. It has no view of
activity on a host that never was — a developer running a coding agent locally,
outside any guarded path.

This collector is meant to see that activity: which AI coding tools are running
on an endpoint, and how much. It is a posture signal, not a detection one.

## What it will collect

Session activity from agents that write append-only JSONL:

| agent | source |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` |
| OpenAI Codex CLI | `~/.codex/sessions/**/*.jsonl` |
| Claude Desktop | local agent-mode session audit log |

Agents that store sessions in SQLite — Cursor, Warp, opencode — are **not
covered**, because the collector's SQL receiver has no SQLite driver. Supporting
them needs additional work and is not part of the first release. This list is
what the tool does, not a roadmap of what it aspires to.

## What it will not collect

**Prompt and response content never leaves the machine.**

The exported record is metadata about a session — which tool, when, how many
turns, which model — and the log body is dropped before export. This is enforced
by an allowlist rather than by pattern-matching sensitive strings: the set of
exported fields is closed, so content cannot escape through a pattern nobody
thought to write.

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

The three are independent. This one is a Collector distribution built with the
OpenTelemetry Collector Builder, so it ships as a static binary with the usual
platform packages, and it works with any OTLP-compatible backend.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
