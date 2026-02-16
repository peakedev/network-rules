# network-rules

Curated [Little Snitch](https://obdev.at/products/littlesnitch/) firewall rules managed as code. The rule files in this repository are published via GitHub and consumed by Little Snitch as **remote rule groups**, making it easy to keep rules consistent, version-controlled, and shareable across machines.

## Rule Groups

| File | Purpose |
|---|---|
| `Custom Apps.lsrules` | Per-app allow/deny rules (Adobe, ChatGPT, Cursor, Figma, Slack, etc.) |
| `Trusted Domains.lsrules` | Globally trusted domains and IP ranges (Apple, Microsoft, GitHub, Spotify, etc.) |
| `Low Data.lsrules` | Deny rules for data-heavy background processes to reduce bandwidth usage |

These three files are the **golden source of truth**. In Little Snitch they are subscribed to as remote rule groups pointing at the raw GitHub URLs on the `main` branch.

## Directory Structure

```
.
├── Custom Apps.lsrules        # Remote rule group — app-specific rules
├── Trusted Domains.lsrules    # Remote rule group — globally trusted domains
├── Low Data.lsrules           # Remote rule group — bandwidth reduction
├── export/
│   └── export_new_rules.py    # Script to extract new manual rules from Little Snitch
├── incoming/                  # Staging area for newly exported rules
└── processed/                 # Archive of previously reviewed exports
```

## Workflow

Over time, Little Snitch prompts you to allow or deny new connections as your needs change. These decisions accumulate as local rules on the machine. Periodically you want to capture those new rules, review them, and merge the keepers into the golden rule files.

1. **Export** — Run the export script to pull all manually-created rules out of Little Snitch and write them to `incoming/`.
2. **Review** — Inspect the exported file and decide which rules belong in which golden rule group.
3. **Merge** — Add the approved rules to the appropriate `.lsrules` file at the root and commit.
4. **Archive** — Move the reviewed export to `processed/` for record-keeping.
5. **Sync** — Little Snitch automatically picks up changes from the remote rule groups on its next update cycle.

## Export Script

The export script extracts rules you created via connection alert prompts (`origin=alert`) or the network monitor (`origin=monitor`), filtering out everything that belongs to remote rule groups, factory groups, or built-in groups.

```bash
python3 export/export_new_rules.py
```

The script requires `sudo` because the Little Snitch CLI needs root access to read the data model. Output is written to `incoming/YYYYMMDD.lsrules`.

Use `--force` to overwrite if you run it more than once on the same day.

### Requirements

- macOS with [Little Snitch](https://obdev.at/products/littlesnitch/) installed
- Python 3 (no external dependencies)
