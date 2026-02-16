#!/usr/bin/env python3
"""
Export manually-created Little Snitch rules to the incoming/ folder.

Extracts rules that were created via connection alert prompts (origin=alert)
or the network monitor (origin=monitor), filtering out rules that belong to
remote rule groups, factory groups, or built-in groups.

Usage:
    python3 export_new_rules.py [--force]

Options:
    --force     Overwrite the output file if it already exists for today.

Requires sudo (the Little Snitch CLI needs root to export the data model).
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime

LITTLESNITCH_CLI = (
    "/Applications/Little Snitch.app/Contents/Components/littlesnitch"
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INCOMING_DIR = os.path.join(PROJECT_ROOT, "incoming")

MANUAL_ORIGINS = {"alert", "monitor"}

LSRULES_FIELDS = {
    "action",
    "process",
    "remote-domains",
    "remote-addresses",
    "remote-hosts",
    "remote",
    "ports",
    "protocol",
    "direction",
    "via",
    "disabled",
    "notes",
    "requiresTrustedSignatureForAnyProcess",
}


def check_littlesnitch_installed():
    if not os.path.isfile(LITTLESNITCH_CLI):
        print(
            "Error: Little Snitch CLI not found at:\n"
            f"  {LITTLESNITCH_CLI}\n"
            "Is Little Snitch installed?",
            file=sys.stderr,
        )
        sys.exit(1)


def export_model():
    """Run the Little Snitch CLI to export the full data model."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        subprocess.run(
            ["sudo", LITTLESNITCH_CLI, "export-model", tmp_path],
            check=True,
        )
        with open(tmp_path, "r") as f:
            return json.load(f)
    except subprocess.CalledProcessError as exc:
        print(
            f"Error: Little Snitch export-model failed (exit code {exc.returncode}).",
            file=sys.stderr,
        )
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Failed to parse export-model output as JSON.", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def extract_manual_rules(model):
    """Filter for manually-created rules and strip metadata fields."""
    manual_rules = []
    for rule in model.get("rules", []):
        if rule.get("origin") not in MANUAL_ORIGINS:
            continue
        clean = {k: v for k, v in rule.items() if k in LSRULES_FIELDS}
        manual_rules.append(clean)
    return manual_rules


def sort_rules(rules):
    """Sort rules by process identifier, then by action, then by remote target."""
    def sort_key(rule):
        process = rule.get("process", "")
        action = 0 if rule.get("action") == "deny" else 1
        remote = (
            rule.get("remote-domains", "")
            or rule.get("remote-addresses", "")
            or rule.get("remote-hosts", "")
            or rule.get("remote", "")
        )
        if isinstance(remote, list):
            remote = remote[0] if remote else ""
        return (process, action, remote)

    return sorted(rules, key=sort_key)


def format_lsrules_json(data):
    """Format JSON to match Little Snitch's style (2-space indent, ' : ' separators)."""
    raw = json.dumps(data, indent=2, ensure_ascii=False)
    raw = re.sub(r'": ', '" : ', raw)
    return raw + "\n"


def print_summary(rules):
    """Print a human-readable summary of exported rules."""
    by_process = {}
    for rule in rules:
        proc = rule.get("process", "(any process)")
        by_process.setdefault(proc, []).append(rule)

    print(f"\nExported {len(rules)} manual rule(s):\n")
    for proc in sorted(by_process):
        proc_rules = by_process[proc]
        label = proc.split("/")[-1] if "/" in proc else proc
        print(f"  {label} ({len(proc_rules)} rule(s))")
        for r in proc_rules:
            action = r.get("action", "?")
            target = (
                r.get("remote-domains")
                or r.get("remote-addresses")
                or r.get("remote-hosts")
                or r.get("remote", "any")
            )
            if isinstance(target, list):
                target = ", ".join(target)
            print(f"    {action:5s}  {target}")
    print()


def main():
    force = "--force" in sys.argv

    check_littlesnitch_installed()

    print("Exporting Little Snitch data model (sudo required)...")
    model = export_model()

    manual_rules = extract_manual_rules(model)
    if not manual_rules:
        print("No manually-created rules found. Nothing to export.")
        sys.exit(0)

    manual_rules = sort_rules(manual_rules)

    today = datetime.now().strftime("%Y%m%d")
    os.makedirs(INCOMING_DIR, exist_ok=True)
    output_path = os.path.join(INCOMING_DIR, f"{today}.lsrules")

    if os.path.exists(output_path) and not force:
        print(
            f"Error: {output_path} already exists.\n"
            "Use --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    lsrules = {
        "description": "Manually created rules exported from Little Snitch",
        "name": f"New Rules {datetime.now().strftime('%Y-%m-%d')}",
        "rules": manual_rules,
    }

    with open(output_path, "w") as f:
        f.write(format_lsrules_json(lsrules))

    print(f"Written to: {output_path}")
    print_summary(manual_rules)


if __name__ == "__main__":
    main()
