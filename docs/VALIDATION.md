# Validating the rules with real telemetry

Synthetic test events prove the rule logic. This guide produces the evidence that the rules
catch real attacks and stay quiet on normal activity. Budget about two evenings.

## 1. Lab VM (once)

- Windows 11 VM: VMware Fusion or UTM on Apple Silicon (Windows 11 ARM), VMware Fusion on Intel.
- Take a snapshot named `clean` before anything else.
- Install Sysmon with the lab config (copy `tools/` into the VM):

  ```powershell
  .\Sysmon64.exe -accepteula -i .\sysmon-lab.xml     # Windows 11 ARM: Sysmon64a.exe
  ```


## 2. Benign baseline first

Use the VM normally for a few hours: browse, install an app or two, run Windows Update,
open Office files, use PowerShell for ordinary admin tasks. Then:

```powershell
.\Export-LabEvents.ps1 -Since (Get-Date).AddHours(-4) -OutFile ..\datasets\benign\day1.jsonl
```

Do this before any attack simulation so the baseline is clean.

## 3. Recorded security telemetry

Use sanitized Windows event captures that are already available. Record the source
and ATT&CK technique for each capture and place the normalized JSONL in
`datasets/attack/`. See the dataset README for the expected format.

## 4. Replay on the Mac

Copy `datasets/` back to the repo (shared folder or git), then:

```sh
.venv/bin/python pipeline.py --max-fp 0
```

- A technique with no rule firing fails the run: inspect the captured events and improve the rule (or add a fixture case explaining the gap).
- A false positive fails the run with `--max-fp 0`: add a narrow filter to the rule, add the
  benign event as a negative fixture case, and document it under `falsepositives`.

Commit each fix separately so the history shows the tuning work.

## 5. Prove it in a SIEM

Pick one:

- **Splunk Cloud trial** (works from any Mac): upload `datasets/*.jsonl` as JSON
  (sourcetype `_json`), then paste each `build/queries/*.spl` query.
- **Elastic** (Docker on the Mac): ingest the JSONL, convert rules with
  `sigma convert -t lucene` (install `pySigma-backend-elasticsearch`), and add them as
  detection rules.
- **Microsoft Sentinel** (free trial): the `.sentinel.kql` queries run against
  `SecurityEvent`; endpoint `.xdr.kql` queries need Defender for Endpoint data.

Save one screenshot per rule firing as `docs/screenshots/<rule>.png` and link them from the
README Results table.

## 6. Update the README

Replace the "to be collected" rows in the README Results table with the numbers from
`build/report.md`, for example:

> 12 rules · 11 ATT&CK techniques · 10/10 techniques detected in recorded telemetry ·
> 0 false positives across 18,400 benign events

Only publish numbers that the report actually shows.
