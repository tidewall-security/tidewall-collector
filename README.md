# Tidewall Collector

Tidewall Collector is a private Python package for projecting explicitly
selected Claude Code fixtures into the Tidewall v1 metadata format. The current
fixture capability covers Claude JSONL transcript observations and supplied
`UserPromptSubmit`, `PreToolUse`, and `PostToolUse` hook payloads.

The projection carries an allowlisted event kind, provenance, availability,
gaps and optional verified metadata. Session, tool call, record, stream and
parser identities are projected with an enrollment-local HMAC key. Transcript
and hook rows can correlate through the same native IDs within that enrollment.
Prompt bodies, tool arguments and results, file paths, URLs, and raw identifiers
stay in transient input.

The package has no runtime dependencies beyond Python's standard library.
The fixture path is local and explicit. Live transcript discovery, hook
installation, background collection, delivery, and assessment are outside the
current package capability.

## Development

Use a dedicated environment with pytest, setuptools and wheel.

```sh
python -m pytest -q
python -m pip wheel --no-deps --no-build-isolation .
```

Selected public OpenAIDR source and its upstream record are under
[vendor/openaidr](vendor/openaidr). See the [source lock](vendor/openaidr/source-lock.json)
for upstream paths, hashes and local modifications.

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
