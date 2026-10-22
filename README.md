# CORDON Phase 1–4

CORDON is a deterministic, offline tool-calling demo. It includes `MockLLM`,
fake email and web tools, sandboxed file operations, a bounded tool loop, a
CLI, and an optional local tool firewall. There is no real LLM provider,
network access, or mail service. The local firewall also tracks copied content
from untrusted tool outputs and detects common prompt-injection indicators.

## Windows setup

From PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
```

If PowerShell blocks activation, run the commands without activating the
environment by replacing `py` with `.\.venv\Scripts\python.exe`.

## Run the leak demo with CORDON off

```powershell
py -m cordon --cordon off --gullible
```

`MockLLM` reads a fixed fake inbox, follows the malicious email's instruction
in gullible mode, reads a fake `secrets.txt`, and writes the result only to a
fake outbox inside a temporary sandbox. The CLI prints the outbox contents;
the temporary sandbox is then removed.

Run the non-gullible behavior with:

```powershell
py -m cordon --cordon off
```

## Run the demo with CORDON on

```powershell
py -m cordon --cordon on --gullible
```

The local firewall intercepts model-requested tool calls before dispatch. It
denies reads and writes to protected filenames (`secrets.txt`, `.env`,
`credentials.json`, `id_rsa`, and `id_ed25519`) and blocks outbound fake email
unless a recipient is explicitly approved. Blocked calls are reported in
the CLI. An approved fake recipient can be added with
`--allow-recipient user@example.test`; the option can be repeated. Approval
does not override taint policies.

### Taint tracking (Phase 3)

The firewall records each allowed tool output under a source ID. Before
dispatch, it applies policy R3 to block `send_email` when either `to` or `body`
contains an exact or fuzzy-matched substring copied from those outputs, and
policy R4 to block `delete_file` when its `path` contains such a substring.
Matching is case-insensitive, uses Unicode NFKC normalization, and defaults to
a minimum copied fragment of 12 characters with a similarity threshold of 0.85.
Blocked decisions display their rule and taint source IDs.

Taint tracking is intentionally substring-based: heavy paraphrasing can remove
the copied fragments and evade a match. It is a heuristic, not a hardened
security boundary or a substitute for a semantic information-flow policy.

### Injection detection and R5 approvals (Phase 4)

The heuristic detector looks for instruction overrides, send/forward/
exfiltration requests, sensitive-data references, invisible Unicode, long
base64-like strings, and hidden HTML styles. Its configured score threshold
sets whether tool output makes the accumulated context suspicious. When it is,
R5 prompts for approval before `send_email`, `delete_file`, or `read_file`.
Declining blocks the call; approving R5 does not bypass protected-file, taint,
or recipient-approval rules.

Inspect the bundled, deterministic sample rates or tune the threshold with:

```powershell
py -m cordon --evaluate-detector
py -m cordon --evaluate-detector --detector-threshold 0.4
```

Detection and benign-flag rates are heuristic results on these small bundled
samples, not general accuracy guarantees. Heavy paraphrasing can evade
substring-based taint matching, and benign text that resembles injection
indicators can be flagged.

The protected-filename checks and recipient approval policy remain in effect.
Phase 1's deliberate leak remains available with `--cordon off`.

To inspect files left in a sandbox, specify a directory:

```powershell
py -m cordon --cordon on --gullible --sandbox-dir .\demo-sandbox
```

## Tests

```powershell
py -m pytest
```

The loop passes conversation history to the mock model, checks each requested
tool call against the firewall when enabled, executes allowed tools, and
appends results for the next turn. It stops when the model returns a final
response or raises an error if it exceeds the configured tool-call limit.
