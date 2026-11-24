# Run the isolated Claude prompt demo

The demo observes a single synthetic prompt submission with Claude Code 2.1.330, an installed Collector, a fresh Tidewall Server database and the standalone Qwen classifier. Each case starts its own loopback Server, policy, scoped administrator, device enrollment and 0700 working directory. Its only allowed tool invocation is `/usr/bin/touch accepted.marker` in that directory.

## Select the release artifacts

Build the Collector from commit `f4dedbd506a947ff3ab60259ce702adc4a0f16df` in this checkout. The qualified macOS arm64 build used CPython 3.13.14, pip 26.1.2, setuptools 84.2.1, wheel 0.48.0 and packaging 26.3. Use an existing build environment with those exact versions. The installed runtime contains only the Collector distribution. Run these commands in one shell from the checkout.

```sh
set -eu
BUILD_PY="$PWD/.venv/bin/python"
SOURCE_REV=f4dedbd506a947ff3ab60259ce702adc4a0f16df
BUILD_ROOT=$(mktemp -d /private/tmp/tw-wheel-XXXXXXXX)
export SOURCE_DATE_EPOCH=315532800 PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1
mkdir "$BUILD_ROOT/src" "$BUILD_ROOT/dist"
git archive "$SOURCE_REV" | tar -xf - -C "$BUILD_ROOT/src"
"$BUILD_PY" -c 'from importlib.metadata import version; import sys; assert sys.version_info[:3] == (3,13,14) and [version(p) for p in ("pip","setuptools","wheel","packaging")] == ["26.1.2","84.2.1","0.48.0","26.3"]'
"$BUILD_PY" -m pip wheel --no-deps --no-cache-dir --no-build-isolation -w "$BUILD_ROOT/dist" "$BUILD_ROOT/src"
COLLECTOR_WHEEL="$BUILD_ROOT/dist/tidewall_collector-1.0.0-py3-none-any.whl"
"$BUILD_PY" -m venv --without-pip "$BUILD_ROOT/runtime"
"$BUILD_PY" -m pip --python "$BUILD_ROOT/runtime/bin/python" install --no-deps --no-index "$COLLECTOR_WHEEL"
COLLECTOR="$BUILD_ROOT/runtime/bin/tidewall-collector"
shasum -a 256 "$COLLECTOR_WHEEL"
```

The wheel SHA-256 is `d599ba7d5154d0f0b1e2664cd0b78deb025c7adf0083b898e9acdcdd21527cb8`. Keep `BUILD_ROOT`, `COLLECTOR` and `COLLECTOR_WHEEL` for the run. The verifier checks the complete pip console script, including a direct `#!` line containing the absolute path to its own runtime’s Python. Use a short, physical final install path with no spaces, as in the recipe. Relocation, shell-trampoline shebangs and alternate console wrappers fall outside this qualification. The helper compares installed module bytes to the wheel and runs the audited interpreter in isolated import mode.

Set `SERVER` to the paired Server checkout, with its dependencies already installed in `.venv`. The harness uses its real migration, authentication, application lifespan, classifier client and decision routes. It seeds an input rule set with generic malicious-prompt detection, threshold 0.5 and report-on-failure. The chosen case sets report mode or adds one access rule for `app_id=claude-code`.

Use the standalone `tidewall-lora-inference==0.1.0a1` wheel from detector commit `334e17151b1a569f7f2617c5e27d289b5f4d40f3`, SHA-256 `d47671f52ad2d5e689aa6b1fade8a35ab4e19bacc620be3e94d6a78bc74db077`. Set `MODEL_PYTHON` to its interpreter with the pinned model dependencies. Choose a new external `SERVICE_STATE`, the existing read-only `MODEL_DIRECTORY`, a free literal loopback `CLASSIFIER_PORT` and the selected `MODEL_DEVICE`. Keep the serving process running for the demonstration.

```sh
"$MODEL_PYTHON" -m tidewall_lora.prepare --state "$SERVICE_STATE" \
  --models-from "$MODEL_DIRECTORY" --device "$MODEL_DEVICE"
"$MODEL_PYTHON" -m tidewall_lora --config "$SERVICE_STATE/service.json" \
  --host 127.0.0.1 --port "$CLASSIFIER_PORT"
```

Preparation hashes all 12 manifest files and generates a private tenant and key for this service. The demo checks readiness outside the callback budget. The browser and agent have no classifier credential. Keep the service state private.

## Renew local authority and recover a selection

Run `"$COLLECTOR" refresh --state-root "$STATE_ROOT"` outside the hook to refresh approved device access. Include `--fixture-loopback-http` for the selected loopback receiver. Credentials created before access lifetimes were recorded also need this explicit refresh for native assessment. An expired grant requires an administrator-issued replacement.

After full Server retention expiry, prepare the same selected session in its original working directory with `--new-session` and the usual protected session-ID descriptor. This operation requires the previous grant to have expired. It clears capture consent, the old capability, the selected Server UUID and pending reports. The journal counts discarded rows and unreported outcomes. Import a fresh metadata-only grant, run a metadata-only callback to establish the new Server UUID, then issue and explicitly opt in to capture for that UUID.

When offboard returns `offboard_unverified_native_journal` or `offboard_unverified_native_config`, it has removed independently authenticated native artifacts. The enrollment remains suspended. Inspect the named artifact and any corresponding `.next` entry under the enrollment directory. Move each unverified entry itself to a private location outside enrollment without following symlinks, then rerun offboard with the same device ID. Treat isolated files as potentially sensitive until their owner determines their disposition.

## Select the native session

Set `CLAUDE` to the absolute versioned 2.1.330 executable. Its required SHA-256 is `f7c5093b9dd6560d08af28bc27b123fb55091deae3180ac39df199522da86815`. The harness checks its bytes and version before **each** invocation. Set `AUTH_CONTEXT` to a new, physically resolved directory you own, with mode 0700 and three 0700 children named `home`, `config` and `tmp`. Sign in directly to that selected context before running Claude. From a separate owned working directory, run the following with the versioned executable.

```sh
env -i PATH=/usr/bin:/bin HOME="$AUTH_CONTEXT/home" \
  CLAUDE_CONFIG_DIR="$AUTH_CONTEXT/config" TMPDIR="$AUTH_CONTEXT/tmp" \
  DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  "$CLAUDE" auth login
```

The demo sets the same limited environment, an explicit session UUID, restricted mode, empty settings sources, empty strict MCP configuration, no Chrome, disabled slash commands and disabled session persistence. Its settings file registers one synchronous UserPromptSubmit command. It inspects reported runtime tools, hook events and managed plugin counts. Account or platform customization outside these reported fields can remain. Only synthetic prompt bytes go to Claude, through stdin. It parses native streams in memory.

```sh
python3 scripts/native_prompt_demo.py \
  --collector "$COLLECTOR" --collector-wheel "$COLLECTOR_WHEEL" \
  --server-root "$SERVER" --service-config "$SERVICE_STATE/service.json" \
  --classifier-port "$CLASSIFIER_PORT" --claude "$CLAUDE" \
  --auth-context "$AUTH_CONTEXT" --case benign
```

Each case first submits a metadata-only bootstrap prompt through the selected real Claude session, checks its keyed server session and fresh decision, then grants transient capture to that device and session. The installed Collector imports both grants through protected pipes. The second invocation requires explicit local capture unless the case selects disabled capture. The verified bootstrap marker is removed before the second invocation. Both invocations use a 3 s outer hook limit, a 1.8 s Collector budget and a 100 ms output reserve. The Server caps classifier I/O at 1.2 s with a 150 ms reserve.

| Case | Expected observation on the second prompt |
| --- | --- |
| `benign` | A validated score below 0.5, an allow decision and one successful exact marker action. |
| `denied` | A score at or above 0.5, a prepared deny, the fixed block bytes, hook acknowledgement and zero tool or marker effects. |
| `report` | The same prompt as `denied`, evaluated deny and prepared allow, with the exact marker action. |
| `outage` | A controlled loopback provider disconnect, unavailable assessment, configured fallback and the exact marker action. |
| `rule-outage` | The provider endpoint is unavailable. The access rule denies before inference. |
| `disabled` | Server capability is available and local capture is off. The metadata-only decision records capture disabled. |
| `transport-outage` | Only the owned Server is stopped after setup. The callback emits no bytes and Claude can perform the marker action. |
| `late-reply` | An outer test transport delays the real decision reply by 2.1 s. The callback emits no bytes and Claude can perform the marker action. |

Success prints a content-free JSON receipt. For a block, the observer requires one correlated committed decision, its actual forwarded stdout, the matching UserPromptSubmit hook response, and Claude’s session-bound informational `blocked_by_hook` acknowledgement with the fixed reason and prevented continuation. The complete trace must show four zero token counters, zero tool calls, and no marker directory entry. For an allow it requires the exact tool invocation, its matching successful result and a fresh empty marker. After the reporter acknowledges each observed stage, the demo reads the decision again and checks the exact stage, source, count and effect fields. The transport-outage case requires a newly reserved invocation under the second grant and the explicit offline outcome. An unavailable account, missing acknowledgement or partial trace leaves native qualification open. The paired pytest cases use synthetic envelopes and an explicitly simulated HTTP classifier.

The harness reaps the Server and removes its temporary database, Collector credentials, private settings and marker. The operator owns the selected auth context, classifier process and private service state. Stop that process when finished. Preserve the selected model directory for its other users.
