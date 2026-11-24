# Run the isolated Claude prompt demo

The demo observes a single synthetic prompt submission with Claude Code 2.1.330, an installed Collector, a fresh Tidewall Server database and the standalone Qwen classifier. Each case starts its own loopback Server, policy, scoped administrator, device enrollment and 0700 working directory. Its only allowed tool invocation is `/usr/bin/touch accepted.marker` in that directory.

## Select the release artifacts

Use Python 3.13 for the Collector. Install the reviewed wheel with `pip install --no-index --no-deps` into a separate pipless virtual environment using another interpreter's `pip --python`. The expected wheel is `tidewall_collector-1.0.0-py3-none-any.whl`, SHA-256 `a977cd41dc698e79448665d74ff737ed59dab99c257944bff64517fb08f4b5e4`. The script verifies the installed modules against it. Set `COLLECTOR` to that environment's absolute `bin/tidewall-collector` path and `COLLECTOR_WHEEL` to the wheel path. Run the script from this Collector source checkout.

Set `SERVER` to the paired Server checkout, with its dependencies already installed in `.venv`. The harness uses its real migration, authentication, application lifespan, classifier client and decision routes. It seeds an input rule set with generic malicious-prompt detection, threshold 0.5 and report-on-failure. The chosen case sets report mode or adds one access rule for `app_id=claude-code`.

Use the standalone `tidewall-lora-inference==0.1.0a1` wheel from detector commit `334e17151b1a569f7f2617c5e27d289b5f4d40f3`, SHA-256 `d47671f52ad2d5e689aa6b1fade8a35ab4e19bacc620be3e94d6a78bc74db077`. Set `MODEL_PYTHON` to its interpreter with the pinned model dependencies. Choose a new external `SERVICE_STATE`, the existing read-only `MODEL_DIRECTORY`, a free literal loopback `CLASSIFIER_PORT` and the selected `MODEL_DEVICE`. Keep the serving process running for the demonstration.

```sh
"$MODEL_PYTHON" -m tidewall_lora.prepare --state "$SERVICE_STATE" \
  --models-from "$MODEL_DIRECTORY" --device "$MODEL_DEVICE"
"$MODEL_PYTHON" -m tidewall_lora --config "$SERVICE_STATE/service.json" \
  --host 127.0.0.1 --port "$CLASSIFIER_PORT"
```

Preparation hashes all 12 manifest files and generates a private tenant and key for this service. The demo checks readiness outside the callback budget. The browser and agent have no classifier credential. Keep the service state private.

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

Success prints a content-free JSON receipt. For a block, the observer requires one correlated committed decision, its actual forwarded stdout, a complete Claude trace with `blocked_by_hook`, four zero token counters, zero tool calls and no marker. For an allow it requires the exact tool invocation, its matching successful result and a fresh empty marker. Delivery facts are reported separately after output. An unavailable account, missing acknowledgement or partial trace leaves native qualification open. The paired pytest cases use synthetic envelopes and an explicitly simulated HTTP classifier.

The harness reaps the Server and removes its temporary database, Collector credentials, private settings and marker. The operator owns the selected auth context, classifier process and private service state. Stop that process when finished. Preserve the selected model directory for its other users.
