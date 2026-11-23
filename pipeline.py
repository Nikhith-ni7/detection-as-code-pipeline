"""Lint Sigma rules, test them against events, convert them, and report coverage.

Steps:
1. sigma check            - lint every rule in rules/
2. synthetic fixtures     - fixtures/<rule>.json must contain cases that should and
                            should not alert, and every case must behave as labelled
3. attack datasets        - datasets/attack/<technique>.jsonl holds events captured
                            while running Atomic Red Team for that technique; at least
                            one rule tagged with the technique must fire on it
4. benign datasets        - datasets/benign/*.jsonl holds normal activity; every hit
                            is counted as a false positive
5. conversion             - Splunk SPL, plus KQL for Defender XDR (endpoint rules) or
                            Microsoft Sentinel SecurityEvent (Windows Security log rules)
6. outputs in build/      - queries, ATT&CK Navigator layer, report.md, report.json
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from sigma_match import compile_rule, logsource_filter

RULES = Path("rules")
FIXTURES = Path("fixtures")
ATTACK_DATA = Path("datasets/attack")
BENIGN_DATA = Path("datasets/benign")
TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)")


class PipelineError(Exception):
    pass


def sigma_cli():
    path = shutil.which("sigma") or str(Path(sys.executable).with_name("sigma"))
    if not Path(path).exists():
        raise PipelineError("sigma CLI not found; run pip install -r requirements.txt")
    return path


def load_rule(path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule["_stem"] = path.stem
    rule["_path"] = path
    rule["_match"] = compile_rule(rule)
    rule["_applies"] = logsource_filter(rule["logsource"])
    rule["_techniques"] = sorted(
        m.group(1).upper() for t in rule.get("tags", []) if (m := TECHNIQUE_TAG.fullmatch(t))
    )
    if not rule["_techniques"]:
        raise PipelineError(f"{path.stem}: no ATT&CK technique tag")
    return rule


def check_fixtures(rule):
    path = FIXTURES / f"{rule['_stem']}.json"
    if not path.exists():
        raise PipelineError(f"{rule['_stem']}: missing fixture file {path}")
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise PipelineError(f"{path}: expected a non-empty list of cases")

    failures = []
    for number, case in enumerate(cases, start=1):
        if set(case) - {"note", "event", "expected"} or not isinstance(case.get("expected"), bool):
            raise PipelineError(f"{path} case {number}: needs 'event' and boolean 'expected'")
        if rule["_match"](case["event"]) != case["expected"]:
            label = case.get("note", f"case {number}")
            failures.append(f"  expected {case['expected']}: {label}")
    if failures:
        raise PipelineError(f"{rule['_stem']}: fixture mismatches\n" + "\n".join(failures))
    if {c["expected"] for c in cases} != {True, False}:
        raise PipelineError(f"{path}: needs at least one alerting and one non-alerting case")
    return len(cases)


def read_jsonl(path):
    events = []
    with path.open(encoding="utf-8-sig") as source:
        for number, line in enumerate(source, start=1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise PipelineError(f"{path}:{number}: {error}") from error
    return events


def count_hits(rule, events):
    return sum(1 for e in events if rule["_applies"](e) and rule["_match"](e))


def convert(sigma, rule):
    is_security_log = rule["logsource"].get("service") == "security"
    targets = [("splunk", ["-p", "splunk_windows"], "spl")]
    if is_security_log:
        targets.append(
            ("kusto", ["-p", "pipelines/sentinel_security_event.yml", "-p", "azure_monitor"], "sentinel.kql")
        )
    else:
        targets.append(("kusto", ["-p", "microsoft_xdr"], "xdr.kql"))
    queries = {}
    for backend, pipeline_args, extension in targets:
        result = subprocess.run(
            [sigma, "convert", "-t", backend, *pipeline_args, str(rule["_path"])],
            capture_output=True, text=True,
        )
        query = result.stdout.strip()
        if result.returncode or not query:
            raise PipelineError(f"{rule['_stem']}: {extension} conversion failed\n{result.stderr}")
        queries[extension] = query
    return queries


def build_layer(rows):
    techniques = {}
    for row in rows:
        for technique in row["techniques"]:
            entry = techniques.setdefault(technique, {"rules": [], "validated": False})
            entry["rules"].append(row["title"])
            entry["validated"] |= bool(row["attack_hits"])
    return {
        "name": "Windows Sigma detections",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "description": "Score 1 = passes synthetic fixtures. Score 2 = also fired on captured Atomic Red Team telemetry.",
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 1, "maxValue": 2},
        "techniques": [
            {"techniqueID": t, "score": 2 if e["validated"] else 1, "comment": "\n".join(e["rules"])}
            for t, e in sorted(techniques.items())
        ],
    }


def write_report(output, rows, attack_sets, benign_total):
    def cell(value, available):
        return str(value) if available else "not collected"

    lines = [
        "# Detection report",
        "",
        f"Rules: {len(rows)} · Techniques: {len({t for r in rows for t in r['techniques']})} · "
        f"Synthetic cases: {sum(r['synthetic_cases'] for r in rows)} · "
        f"Benign events replayed: {benign_total}",
        "",
        "| Rule | ATT&CK | Level | Synthetic cases | Hits on attack data | False positives on benign data |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        has_attack = any(t in attack_sets for t in r["techniques"])
        lines.append(
            f"| {r['title']} | {', '.join(r['techniques'])} | {r['level']} | {r['synthetic_cases']} | "
            f"{cell(r['attack_hits'], has_attack)} | {cell(r['benign_hits'], benign_total)} |"
        )
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output / "report.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def run(output, max_fp):
    sigma = sigma_cli()
    rule_paths = sorted(RULES.glob("*.yml"))
    if not rule_paths:
        raise PipelineError("no rules found in rules/")

    subprocess.run([sigma, "check", "-i", "-x", "attacktag", "-x", "d3_fendtag", str(RULES)], check=True)
    rules = [load_rule(p) for p in rule_paths]

    attack_sets = {p.stem.upper(): read_jsonl(p) for p in sorted(ATTACK_DATA.glob("*.jsonl"))}
    benign = [e for p in sorted(BENIGN_DATA.glob("*.jsonl")) for e in read_jsonl(p)]

    output.mkdir(parents=True, exist_ok=True)
    queries_dir = output / "queries"
    queries_dir.mkdir(exist_ok=True)

    rows = []
    for rule in rules:
        cases = check_fixtures(rule)
        attack_events = [e for t in rule["_techniques"] for e in attack_sets.get(t, [])]
        row = {
            "rule": rule["_stem"],
            "title": rule["title"],
            "level": rule.get("level", ""),
            "techniques": rule["_techniques"],
            "synthetic_cases": cases,
            "attack_hits": count_hits(rule, attack_events),
            "benign_hits": count_hits(rule, benign),
        }
        for extension, query in convert(sigma, rule).items():
            (queries_dir / f"{rule['_stem']}.{extension}").write_text(query + "\n", encoding="utf-8")
        rows.append(row)
        print(f"{rule['_stem']}: {cases} synthetic cases passed, "
              f"{row['attack_hits']} attack hits, {row['benign_hits']} benign hits", flush=True)

    problems = []
    for technique in attack_sets:
        if not any(r["attack_hits"] for r in rows if technique in r["techniques"]):
            problems.append(f"no rule fired on datasets/attack/{technique}.jsonl")
    if max_fp is not None:
        problems += [
            f"{r['rule']}: {r['benign_hits']} false positives (limit {max_fp})"
            for r in rows if r["benign_hits"] > max_fp
        ]

    (output / "attack-layer.json").write_text(json.dumps(build_layer(rows), indent=2) + "\n")
    write_report(output, rows, attack_sets, len(benign))
    if problems:
        raise PipelineError("\n".join(problems))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=Path("build"))
    parser.add_argument("--max-fp", type=int, default=None,
                        help="fail if any rule has more false positives than this on benign data")
    args = parser.parse_args()
    try:
        run(args.output, args.max_fp)
    except (PipelineError, subprocess.CalledProcessError, ValueError, KeyError, yaml.YAMLError) as error:
        parser.exit(1, f"Pipeline failed.\n{error}\n")
    print(f"Done. See {args.output}/report.md")


if __name__ == "__main__":
    main()
