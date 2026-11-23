"""Validate detection rules and replay synthetic event fixtures."""

import argparse
import json
from pathlib import Path

MAX_BYTES = 256 * 1024
MAX_CASES = 1000


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("invalid JSON constant")


def read_json(path):
    with path.open("rb") as source:
        content = source.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("JSON file exceeds 256 KiB")
    return json.loads(content, object_pairs_hook=unique_object, parse_constant=reject_constant)


def replay(rule, path):
    detection = rule["detection"]
    selection = detection.get("selection")
    if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
        raise ValueError("fixture replay supports one selection")
    if not isinstance(selection, dict) or not selection:
        raise ValueError("selection must map fields to string patterns")

    comparisons = []
    for expression, patterns in selection.items():
        field, _, modifier = expression.partition("|")
        require_all = modifier.endswith("|all")
        modifier = modifier.removesuffix("|all")
        if isinstance(patterns, str):
            patterns = [patterns]
        if (
            modifier not in {"", "contains", "endswith"}
            or not field
            or not isinstance(patterns, list)
            or not patterns
            or any(not isinstance(p, str) or not p or "*" in p or "?" in p for p in patterns)
        ):
            raise ValueError("unsupported fixture comparison")
        comparisons.append((field, modifier, [p.lower() for p in patterns], require_all))

    cases = read_json(path)
    if not isinstance(cases, list) or not 0 < len(cases) <= MAX_CASES:
        raise ValueError("expected 1 to 1000 fixture cases")
    outcomes = set()
    for index, case in enumerate(cases, start=1):
        if (
            not isinstance(case, dict)
            or case.keys() != {"event", "expected"}
            or not isinstance(case["event"], dict)
            or not all(isinstance(v, str) for v in case["event"].values())
            or type(case["expected"]) is not bool
        ):
            raise ValueError(f"invalid fixture case {index}")
        event = case["event"]
        matched = all(
            field in event and (all if require_all else any)(
                compare(event[field].lower(), modifier, pattern) for pattern in patterns
            )
            for field, modifier, patterns, require_all in comparisons
        )
        if matched != case["expected"]:
            raise ValueError(f"unexpected result in fixture case {index}")
        outcomes.add(matched)
    if outcomes != {True, False}:
        raise ValueError("each rule needs a positive and negative fixture")
    return len(cases)


def compare(value, modifier, pattern):
    if modifier == "contains":
        return pattern in value
    if modifier == "endswith":
        return value.endswith(pattern)
    return value == pattern


def main():
    import re
    import subprocess
    import sys
    import tempfile

    import yaml

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("build"))
    args = parser.parse_args()
    sigma = Path(sys.executable).with_name("sigma")
    rules = sorted(Path("rules").glob("*.yml"))
    if not rules:
        parser.exit(1, "No Sigma rules found.\n")

    try:
        subprocess.run(
            [sigma, "check", "-i", "-x", "attacktag", "-x", "d3_fendtag", "rules"],
            check=True,
        )
        coverage = {}
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch)
            for path in rules:
                with path.open(encoding="utf-8") as source:
                    rule = yaml.safe_load(source.read(MAX_BYTES + 1))
                count = replay(rule, Path("fixtures") / f"{path.stem}.json")
                print(f"{path.stem}: {count} fixture cases passed", flush=True)
                for tag in rule["tags"]:
                    if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag):
                        coverage.setdefault(tag[7:].upper(), []).append(rule["title"])
                for backend, pipeline, extension in (
                    ("splunk", "splunk_windows", "spl"),
                    ("kusto", "microsoft_xdr", "kql"),
                ):
                    query = subprocess.check_output(
                        [sigma, "convert", "-t", backend, "-p", pipeline, path],
                        text=True,
                    ).strip()
                    if not query:
                        raise ValueError(f"empty {extension} conversion")
                    (output / f"{path.stem}.{extension}").write_text(query + "\n", encoding="utf-8")
            layer = {
                "name": "Windows Sigma detections",
                "domain": "enterprise-attack",
                "versions": {"layer": "4.5", "navigator": "4.9.1"},
                "description": "Technique mappings for rules verified against synthetic fixtures.",
                "techniques": [
                    {"techniqueID": technique, "score": 1, "comment": "\n".join(titles)}
                    for technique, titles in sorted(coverage.items())
                ],
            }
            if not coverage:
                raise ValueError("no ATT&CK techniques mapped")
            args.output.mkdir(parents=True, exist_ok=True)
            (output / "attack-layer.json").write_text(json.dumps(layer, indent=2) + "\n")
            for artifact in output.iterdir():
                (args.output / artifact.name).write_bytes(artifact.read_bytes())
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        parser.exit(1, f"Pipeline failed. {error}\n")


if __name__ == "__main__":
    main()
