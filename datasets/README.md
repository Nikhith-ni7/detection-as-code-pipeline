# Datasets

Telemetry exported from the Windows lab VM with `tools/Export-LabEvents.ps1`.
One JSON object per line: `Channel`, `EventID`, `TimeCreated`, `Computer`, then every
EventData field (`Image`, `CommandLine`, `ParentImage`, `TargetObject`, `Details`, ...).

- `attack/<technique>.jsonl` - events captured while simulating that ATT&CK technique,
  for example `attack/T1003.001.jsonl`. CI fails if no rule tagged with the technique fires.
- `benign/*.jsonl` - normal activity. Every rule hit here counts as a false positive.

See [docs/VALIDATION.md](../docs/VALIDATION.md) for how to collect them.
