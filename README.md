# agent-audit

A read-only check of your local AI-agent setup (Claude Code, Claude Desktop, Cursor, Codex).

AI coding agents quietly accumulate risk in their config files: an API key that
got saved inside a permission rule when you clicked "always allow", a secret sitting
in plaintext, a config file that ended up tracked in git, a wall of `allow` rules
with nothing in the `deny` list, MCP servers that auto-run whatever version ships
next, and skills carrying invisible/bidi characters or a `curl | sh`.

`agent-audit` finds these in one command.

## Run it

```bash
python3 agent_audit.py            # scans the current project + your global agent configs
python3 agent_audit.py ~/code/app # scan a specific project
python3 agent_audit.py --json     # machine-readable, for CI
```

No dependencies. Python 3.11+ (uses the standard library only; `tomllib` for Codex).

## It will not leak anything

- **Nothing leaves your machine.** No network calls, no telemetry. Read the file, it's ~300 lines.
- **Secret values are never printed.** A finding says *"a google secret is baked into an allow rule"* and the file it's in - never the key itself.
- **Read-only.** It never edits or deletes your files.

## What it checks

| Area | Example finding |
|------|-----------------|
| Secrets in permission rules | a key baked into an `allow` rule by "always allow" |
| Secrets in plaintext config | token-shaped strings in `.claude.json`, `.mcp.json`, `settings.*.json` |
| Config tracked in git | `settings.local.json` committed - secrets now in repo history |
| Over-broad permissions | many `allow` rules, no `deny`; blanket `Bash(*)` / exec / network rules |
| MCP servers | unpinned `npx`/`uvx` servers; secrets in env/headers/args; plain-http remotes |
| Skills | invisible/bidi characters, base64 blobs, `curl \| sh` |

Exit code is `1` if any HIGH finding is present, `0` otherwise - so you can drop it into a pre-commit hook or CI later.

## If it finds a leaked secret

**Rotate it.** Removing the key from the file does not remove it from git history or
from anywhere the repo was pushed. Revoke the old key with the provider and issue a new one,
then stop tracking the file (`git rm --cached`, add it to `.gitignore`).

## License

MIT. Contributions of new token patterns and new agent tools welcome.
