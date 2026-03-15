#!/usr/bin/env python3
"""
Smart reconciliation of Little Snitch rules using Claude.

Loads the incoming export and all golden rule files, sends them to Claude
for intelligent analysis: consolidation, domain hierarchy simplification,
CIDR grouping, telemetry assessment, and logical re-grouping.

Usage:
    python3 export/reconcile_rules.py [incoming_file]
    python3 export/reconcile_rules.py --dry-run [incoming_file]

Options:
    --dry-run   Show Claude's analysis without writing any changes.

Requires ANTHROPIC_API_KEY in .env or environment.
"""

import json
import os
import re
import shutil
import sys
from datetime import datetime

try:
    from anthropic import Anthropic
except ImportError:
    print(
        "Error: anthropic package not installed.\n"
        "Run: pip install anthropic python-dotenv",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INCOMING_DIR = os.path.join(PROJECT_ROOT, "incoming")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "processed")

GOLDEN_FILES = {
    "Custom Apps": os.path.join(PROJECT_ROOT, "Custom Apps.lsrules"),
    "Trusted Domains": os.path.join(PROJECT_ROOT, "Trusted Domains.lsrules"),
    "Low Data": os.path.join(PROJECT_ROOT, "Low Data.lsrules"),
}

SYSTEM_PROMPT = """\
You are a network security analyst specialising in macOS Little Snitch firewall rules.

## Context

The user maintains three "golden" rule-group files that are published on GitHub and consumed by Little Snitch as remote rule groups:

1. **Custom Apps.lsrules** — Per-app allow/deny rules. Each rule targets a specific `process` identifier.
2. **Trusted Domains.lsrules** — Globally trusted domains and IP ranges (no `process` field). These apply to *all* apps.
3. **Low Data.lsrules** — Deny rules for data-heavy background processes (direction: both, remote: any).

Periodically, new local rules accumulate on the machine via connection-alert prompts. These are exported and need to be **reconciled** into the golden files.

## Your task

You receive:
- The current content of all three golden files.
- A freshly exported set of incoming local rules.

Produce an **updated version of each golden file** that incorporates the incoming rules intelligently. Specifically:

### Analysis rules

1. **Coverage check** — Identify which incoming rules are already fully covered by existing golden rules (exact match, or subdomain of an already-trusted domain, or IP within an existing range).
2. **Domain consolidation** — When multiple subdomain rules exist (incoming + golden combined), consider replacing them with a single parent-domain rule if all observed subdomains belong to the same organisation. For example, if you see rules for `sub1.example.com`, `sub2.example.com`, and `example.com` is clearly a single organisation, consolidate to `example.com`. Be conservative: don't consolidate if the parent domain could match unrelated services.
3. **IP / CIDR consolidation** — When multiple individual IP addresses belong to the same /24 or /16 block of a known provider, consider replacing them with a CIDR range. Only do this when you're confident about the ownership.
4. **Telemetry / tracking assessment** — Flag domains that look like telemetry, analytics, or tracking (e.g. sentry.io, crashlytics.com, statsigapi.net, posthog.com). Recommend deny for these unless the user has explicitly allowed them. If an existing golden rule already allows them for a specific app, keep that decision but note it.
5. **Logical grouping** — Within each golden file, keep rules grouped logically (by app/vendor in Custom Apps, by category in Trusted Domains). Maintain the existing `notes` field style.
6. **Deny-vs-allow sanity** — If an incoming rule allows something that the golden file explicitly denies (or vice versa), flag the conflict and recommend a resolution.
7. **Low Data candidates** — If you see incoming deny rules that block an entire process with `remote: any` and `direction: both`, those belong in Low Data.
8. **Via-specific fidelity** — Treat rules with a `via` field as distinct execution contexts. Do NOT consider a non-`via` app rule as coverage for a `via` rule. If incoming contains `via` rules, keep them explicitly unless an equivalent golden rule already exists with the same `process`, `action`, `via`, and target.

### Output format

Return a single JSON object with this structure:

```json
{
  "analysis": "Human-readable summary of what changed, what was consolidated, any concerns or recommendations.",
  "golden_files": {
    "Custom Apps": { <full updated lsrules content> },
    "Trusted Domains": { <full updated lsrules content> },
    "Low Data": { <full updated lsrules content> }
  }
}
```

The `golden_files` values must be complete, valid lsrules JSON objects (with `description`, `name`, and `rules` fields).

### Important constraints

- Preserve existing rules that are still valid. Don't remove golden rules unless they are clearly redundant after consolidation.
- Keep the `notes` field on every rule. When merging, write a clear descriptive note.
- Sort rules logically within each file (by process, then action).
- Use the same JSON field names as Little Snitch (`action`, `process`, `remote-domains`, `remote-addresses`, `remote-hosts`, `remote`, `ports`, `protocol`, `direction`, `via`, `disabled`, `notes`).
- Only include fields that have values; don't add empty or null fields.
- Target selectors are mutually exclusive per rule: use only one of `remote-domains`, `remote-addresses`, `remote-hosts`, or `remote`. If a process needs both an IP and domains, emit separate rules.
- For `remote-domains` and similar array fields: use a bare string when there's only one value, use an array when there are multiple.
- Return ONLY the JSON object, no markdown fences, no extra text.
"""


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def format_lsrules_json(data):
    """Format JSON to match the project's style (4-space indent)."""
    raw = json.dumps(data, indent=4, ensure_ascii=False)
    raw = re.sub(r'": ', '" : ', raw)
    return raw + "\n"


def find_incoming_file(args):
    explicit = [a for a in args if not a.startswith("--")]
    if explicit:
        path = explicit[0]
        if not os.path.isabs(path):
            path = os.path.join(PROJECT_ROOT, path)
        return path

    if not os.path.isdir(INCOMING_DIR):
        print("No incoming/ directory found. Run export_new_rules.py first.", file=sys.stderr)
        sys.exit(1)
    files = sorted(f for f in os.listdir(INCOMING_DIR) if f.endswith(".lsrules"))
    if not files:
        print("No files in incoming/. Run export_new_rules.py first.", file=sys.stderr)
        sys.exit(1)
    return os.path.join(INCOMING_DIR, files[-1])


def archive_incoming(incoming_path):
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    dest = os.path.join(PROCESSED_DIR, os.path.basename(incoming_path))
    if os.path.exists(dest):
        base, ext = os.path.splitext(os.path.basename(incoming_path))
        dest = os.path.join(PROCESSED_DIR, f"{base}_{datetime.now().strftime('%H%M%S')}{ext}")
    shutil.move(incoming_path, dest)
    print(f"\nArchived to: {dest}")


def build_user_message(incoming_data, golden_data):
    parts = ["## Incoming rules (newly exported from Little Snitch)\n"]
    parts.append("```json")
    parts.append(json.dumps(incoming_data, indent=2, ensure_ascii=False))
    parts.append("```\n")

    for name in ("Custom Apps", "Trusted Domains", "Low Data"):
        parts.append(f"## Current golden file: {name}.lsrules\n")
        parts.append("```json")
        parts.append(json.dumps(golden_data[name], indent=2, ensure_ascii=False))
        parts.append("```\n")

    return "\n".join(parts)


def call_claude(user_message):
    client = Anthropic()
    print("Sending to Claude for analysis... (this may take a minute)\n")

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=16000,
        thinking={
            "type": "enabled",
            "budget_tokens": 10000,
        },
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    for block in response.content:
        if block.type == "text":
            return block.text

    print("Error: No text response from Claude.", file=sys.stderr)
    sys.exit(1)


def parse_response(raw_text):
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"Error parsing Claude's response as JSON: {e}", file=sys.stderr)
        print("Raw response:", file=sys.stderr)
        print(raw_text[:2000], file=sys.stderr)
        sys.exit(1)


TARGET_SELECTORS = ("remote-domains", "remote-addresses", "remote-hosts", "remote")


def split_mixed_target_rules(data):
    """
    Ensure each rule has at most one target selector.
    Little Snitch import behaves inconsistently when target selectors are mixed.
    """
    rules = data.get("rules", [])
    normalized = []

    for rule in rules:
        selectors_present = [k for k in TARGET_SELECTORS if k in rule]
        if len(selectors_present) <= 1:
            normalized.append(rule)
            continue

        # Keep non-target fields and emit one rule per selector.
        base = {k: v for k, v in rule.items() if k not in TARGET_SELECTORS}
        for selector in selectors_present:
            split_rule = dict(base)
            split_rule[selector] = rule[selector]
            normalized.append(split_rule)

    data["rules"] = normalized
    return data


def main():
    if load_dotenv:
        load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "Error: ANTHROPIC_API_KEY not set.\n"
            "Add it to .env in the project root or export it.",
            file=sys.stderr,
        )
        sys.exit(1)

    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    auto_yes = "--yes" in args

    incoming_path = find_incoming_file(args)
    print(f"Incoming file: {incoming_path}")

    incoming_data = load_json(incoming_path)
    print(f"Incoming rules: {len(incoming_data.get('rules', []))}")

    golden_data = {}
    for name, path in GOLDEN_FILES.items():
        golden_data[name] = load_json(path)
        print(f"Golden {name}: {len(golden_data[name].get('rules', []))} rules")

    print()

    user_message = build_user_message(incoming_data, golden_data)
    raw_response = call_claude(user_message)
    result = parse_response(raw_response)

    # Show analysis
    analysis = result.get("analysis", "")
    if analysis:
        print("=" * 70)
        print("ANALYSIS")
        print("=" * 70)
        print(analysis)
        print()

    if dry_run:
        print("[DRY RUN] No files will be written.")
        print("\nFull proposed golden files are in the response above.")
        # Optionally dump to stdout
        for name in ("Custom Apps", "Trusted Domains", "Low Data"):
            updated = result.get("golden_files", {}).get(name)
            if updated:
                count = len(updated.get("rules", []))
                old_count = len(golden_data[name].get("rules", []))
                diff = count - old_count
                sign = "+" if diff >= 0 else ""
                print(f"  {name}: {old_count} -> {count} rules ({sign}{diff})")
        return

    # Confirm
    if auto_yes:
        answer = "y"
        print("Auto-confirmed with --yes flag.")
    else:
        answer = input("Apply these changes to the golden files? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted. No changes made.")
        return

    # Write updated golden files
    updated_files = result.get("golden_files", {})
    for name in ("Custom Apps", "Trusted Domains", "Low Data"):
        updated = updated_files.get(name)
        if not updated:
            print(f"Warning: no updated content for {name}, skipping.", file=sys.stderr)
            continue

        updated = split_mixed_target_rules(updated)

        path = GOLDEN_FILES[name]
        with open(path, "w") as f:
            f.write(format_lsrules_json(updated))

        old_count = len(golden_data[name].get("rules", []))
        new_count = len(updated.get("rules", []))
        print(f"Updated {name}.lsrules: {old_count} -> {new_count} rules")

    archive_incoming(incoming_path)
    print("\nDone. Review the changes with `git diff` before committing.")


if __name__ == "__main__":
    main()
