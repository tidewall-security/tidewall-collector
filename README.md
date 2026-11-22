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

An explicitly enrolled collector can ship this metadata and its health counters
directly to one approved Tidewall origin. The operator selects the synthetic
inputs and runs each pass. The package uses the Python standard library and
POSIX file descriptors and locking. The cross-process fixture workflow has been
verified on macOS. Live agent integrations, unattended collection, enforcement
and assessment are outside this fixture release.

## Install the private wheel

From this checkout, use a Python 3.13 or later build environment containing pip,
setuptools 77 or later and wheel. These commands create a separate runtime with
only the collector distribution installed.

```sh
python -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir dist .
python -m venv --without-pip .fixture-runtime
python -m pip --python .fixture-runtime/bin/python install --no-index --no-deps dist/tidewall_collector-1.0.0-py3-none-any.whl
collector=.fixture-runtime/bin/tidewall-collector
"$collector" --help
"$collector" recover --help
```

## Enroll and ship a synthetic fixture

Supply `ORIGIN` as the administrator's HTTPS Tidewall origin. Set `STATE_A` to a
fresh dedicated state directory under an existing parent, using a canonical
path with no symlink components. Give each enrollment a disjoint directory.
A sibling of an existing enrollment is suitable. Set `FIXTURE_DIR` to the dedicated two-file
directory described below. Use a receiver with the collector routes and its
database migrated to head.

1. Have a policy-bound administrator issue a `collector_write` registration
   token for the intended policy with code approval. Receive it out of band
   in a caller-owned mode-0600 file named by `REGISTRATION_FILE`. In these
   commands the shell supplies the credential through an inherited descriptor.
2. Enroll and give the returned device ID and confirmation code to that
   administrator for approval. Keep the installation ID for future recovery.
   The code is displayed at enrollment and omitted from subsequent status.
3. Read the selected fixture, send a bounded pass and inspect local status.

```sh
"$collector" enrol --origin "$ORIGIN" --state-root "$STATE_A" --registration-fd 3 3<"$REGISTRATION_FILE"
# After the administrator approves the device using its confirmation code
"$collector" fixture --state-root "$STATE_A" --fixture-dir "$FIXTURE_DIR"
"$collector" ship --state-root "$STATE_A"
"$collector" status --state-root "$STATE_A"
```

Each ship pass can acknowledge one batch of up to 32 rows and send a heartbeat.
Repeat it while the local heartbeat reports pending rows. An unknown commit or
retryable failure keeps the original queued metadata for a later pass. Exit 75
indicates a retryable condition, 3 indicates pending approval and 2 reports an
invalid operation, refusal or hold. A contract mismatch retains the rows.
Once the receiver is compatible, `ship --state-root "$STATE_A" --resume-contract`
releases that hold and rechecks the original rows. A revoked device stays
suspended. Its state belongs to its original origin and device.

For an isolated cleartext fixture receiver, add `--fixture-loopback-http` to
each command that uses that enrollment. It accepts literal 127.0.0.1 or [::1].
HTTPS uses certificate and hostname verification. The collector sends directly
to the selected origin and rejects redirects.

## Recover or offboard a device

**Successful same-installation recovery deletes the old device’s server-side
collection history.** Its replacement starts empty and requires new approval.
Keep A’s state isolated in `STATE_A` while deciding how to dispose of its local
pending rows. Have the scoped administrator revoke A, authorize recovery for A
and mint a fresh same-policy collector registration. Receive the fresh
registration and single-use recovery secret through separate protected inputs.

Set `INSTALLATION_ID` to A’s original installation UUID and `STATE_B` to a
fresh dedicated directory. Set `FRESH_REGISTRATION_FILE` and `RECOVERY_FILE`
to separate caller-owned mode-0600 files. B receives a different device ID
and a new confirmation code. After the administrator approves that code,
use B’s state for its own fixture and ship commands.

```sh
"$collector" recover --origin "$ORIGIN" --installation-id "$INSTALLATION_ID" \
  --state-root "$STATE_B" --registration-fd 3 --recovery-fd 4 \
  3<"$FRESH_REGISTRATION_FILE" 4<"$RECOVERY_FILE"
```

If a confirmed enrollment or recovery reports a busy queue or interrupted local
setup, rerun the same command with the same state root, origin and original
protected inputs. Keep those inputs until you have received the confirmation
code. The collector verifies them against the protected local handoff, completes
queue creation or reopens the existing queue, and returns the original device
and code without another enrollment request. During setup, fixture collection,
refresh and shipping report `setup_incomplete`. The collector records the
original queue directory and generation before publication. If storage fills
during preparation, the same command can resume after space becomes available.
A missing or damaged initialized queue needs local investigation. The protected
handoff is removed on the first successful refresh.

To explicitly erase A’s local credentials, pseudonym key, queue, checkpoints
and counters, supply its original device UUID. Interrupted erasure can be
resumed with the same command. Remote revocation and recovery are separate
administrative operations.

```sh
"$collector" offboard --state-root "$STATE_A" --device-id "$DEVICE_A_ID"
```

## Fixture queue

Pass a dedicated directory containing exactly `claude-session.jsonl` and
`claude-hooks.json` to `tidewall_collector.reader.read_fixture`. The reader
checkpoints complete frames and waits for an unterminated JSONL tail to grow.
Replacement, truncation or a same-size rewrite seals the old generation.
Use the keyword argument `independent=frozenset({"transcript"})` or
`independent=frozenset({"hook"})` only for a confirmed independent synthetic
input. An unchanged active fixture keeps its stream and checkpoints.

`QueueState.create` creates a private directory for one verified origin and
device. `QueueState.open` acquires the exclusive writer lock for its context.
Keep that context open through receipt verification. Seven-day expiry and
capacity losses have separate cumulative counters in the enrollment heartbeat.
Expiry physically reclaims the consumed prefix of a mixed-age segment while
preserving the logical positions used to verify receipts.

For queue-only code, call `queue.offboard(owner)` to erase that local queue. After an interrupted
erasure, `QueueState.resume_offboard(path, owner)` verifies the original owner
and finishes deleting that queue. It returns `True` after completing a pending
erasure and `False` when it finds no matching erasure in progress. Selection,
creation and final removal briefly lock the parent directory. Lock contention
raises `QueueError("busy")` and can be retried. The CLI coordinates credential and queue erasure using a separate credential
lock file.

## Development

Use a dedicated environment with pytest, setuptools and wheel. For the
installed-client roundtrip, set `SERVER_CHECKOUT` to the compatible receiver
checkout with its native `.venv` and enable local loopback sockets.

```sh
python -m pytest -q
TIDEWALL_SERVER_ROOT="$SERVER_CHECKOUT" python -m pytest -q tests/test_backend.py tests/test_foundation_roundtrip.py
```

Selected public OpenAIDR source and its upstream record are under
[vendor/openaidr](vendor/openaidr). See the [source lock](vendor/openaidr/source-lock.json)
for upstream paths, hashes and local modifications.

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
