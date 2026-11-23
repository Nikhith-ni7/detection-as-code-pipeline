# Detection-as-code pipeline

A small Windows detection lab that runs on macOS. Each Sigma rule has example
process events that should trigger it and examples that should pass without an
alert. The pipeline checks those expectations and builds Splunk SPL, Defender
XDR KQL, and an ATT&CK Navigator layer.

## Run on macOS

Use Python 3.13 from the project root.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python pipeline.py
```

Open `build/attack-layer.json` in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
Each marked technique has at least one rule with passing synthetic fixtures.
The layer records that evidence level in its description.

| Rule | What it flags | Scope |
| --- | --- | --- |
| ClickFix candidate | Explorer launches PowerShell with the explicit encoded-command flag | Explorer parentage is a proxy for Run-dialog activity |
| LOLBin candidate | Certutil URL cache invocation with an HTTP marker | Legitimate administration can match |
| Credential dumping candidate | ProcDump invocation referencing LSASS by name | A process creation event cannot establish whether a dump succeeded |

Add one `.yml` rule under `rules/` and a same-stem JSON fixture under
`fixtures/`. Each fixture must contain positive and negative examples. The
local matcher supports a single selection, case-insensitive string equality,
`contains`, `endswith`, and literal lists with optional `all`. It fails on
unsupported detection shapes. Sigma CLI handles linting and conversion. The
pipeline excludes the network-backed ATT&CK and D3FEND tag validators, and
extracts ATT&CK technique IDs for the layer by tag format.

SPL assumes the extracted Sysmon-style field names `Image`, `ParentImage`, and
`CommandLine`. Scope queries to the appropriate Windows index and source when
integrating them. KQL targets the Defender XDR `DeviceProcessEvents` table.
The included fixtures are authored samples. Public captures and execution of
generated queries inside either SIEM remain separate validation steps.

GitHub Actions is configured for pushes and pull requests. It uses pinned
actions, read-only repository permissions, and uploads the generated queries and
layer as a downloadable artifact.
