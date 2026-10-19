#!/usr/bin/env python3
"""
agent-audit - a read-only check of your local AI-agent setup.

It looks for the mistakes that AI coding agents (Claude Code, Claude Desktop,
Cursor, Codex) quietly accumulate: API keys saved inside permission rules,
secrets in plaintext config, config files tracked in git, blanket "always
allow" rules with no deny list, unpinned MCP servers, and suspicious skills
(invisible/bidi characters, piping a download straight into a shell).

It NEVER sends anything over the network and NEVER prints the value of a
secret - only its type, length, and where it lives. Everything runs locally.

Usage:
    python3 agent_audit.py [DIR]      # DIR defaults to the current directory
    python3 agent_audit.py --json     # machine-readable output
"""
import json, os, re, sys, glob, subprocess, unicodedata
from collections import Counter

HOME = os.path.expanduser("~")
MAX_DEPTH = 4            # how deep to walk the project dir
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "Pods",
             ".venv", "venv", "__pycache__", ".cache"}

findings = []   # (severity, area, where, what)


def add(sev, area, where, what):
    findings.append((sev, area, where.replace(HOME, "~"), what))


def load_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_toml(p):
    try:
        import tomllib
        with open(p, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


# token shapes for the big providers; add your own as needed
SECRET_RX = re.compile(
    r"(sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{10,})")
SECRET_KEY_RX = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PAT|AUTH)", re.I)


def secret_kind(s):
    """A coarse label for a token, so we can report WITHOUT showing the value."""
    for pat, label in [(r"sk-ant-", "anthropic"), (r"ghp_|github_pat_", "github"),
                       (r"AKIA", "aws"), (r"xox", "slack"), (r"AIza", "google"),
                       (r"eyJ", "jwt"), (r"sk-", "openai-like")]:
        if re.match(pat, s):
            return label
    return "token"


# ---------------- MCP servers (shared across Claude / Cursor) ----------------
def audit_mcp(servers, where):
    for name, s in (servers or {}).items():
        if not isinstance(s, dict):
            continue
        url = s.get("url", "")
        if url.startswith("http://") and not re.search(r"localhost|127\.0\.0\.1|\[::1\]", url):
            add("HIGH", "mcp", where, f"{name}: remote server over plain http (traffic unencrypted)")
        args = [str(a) for a in s.get("args", [])]
        cmd = " ".join([s.get("command", "")] + args)
        runner = re.search(r"\b(npx|uvx|bunx|pnpm dlx)\b", cmd)
        if runner:
            pkgs = [a for a in args if not a.startswith("-")
                    and re.match(r"^(@[\w.-]+/)?[\w.-]+(@[\w.^~-]+)?$", a)]
            pkg = pkgs[0] if pkgs else "?"
            if not re.search(r".@\d", pkg):
                add("MED", "mcp", where,
                    f"{name}: '{runner.group(1)} {pkg}' is not version-pinned; "
                    "any future (possibly compromised) release runs automatically")
        for k, v in (s.get("env") or {}).items():
            if SECRET_KEY_RX.search(k) and isinstance(v, str) and v and not v.startswith("${"):
                add("HIGH", "mcp", where, f"{name}: env {k} is a literal value ({len(v)} chars), not a ${{VAR}} reference")
        for k, v in (s.get("headers") or {}).items():
            if isinstance(v, str) and len(v) > 15 and "${" not in v:
                add("HIGH", "mcp", where, f"{name}: header {k} is a literal value ({len(v)} chars)")
        for a in args:
            if SECRET_RX.search(a):
                add("HIGH", "mcp", where, f"{name}: a {secret_kind(SECRET_RX.search(a).group(0))} secret is passed as a command-line argument (visible in `ps`)")


# ---------------- Claude Code / Desktop permissions ----------------
BROAD = [r"^Bash$", r"^Bash\(\*\)$", r"^Bash\(.*:\*\)$", r"^WebFetch$",
         r"^Write$", r"^Edit$", r"^mcp__[\w-]+$"]
DANGER_CMD = re.compile(r"Bash\((rm|curl|wget|sh|bash|python3?|node|ssh|scp|git push|npx|sudo|osascript|security)\b")


def audit_permissions(p):
    s = load_json(p)
    if not s:
        return
    perm = s.get("permissions") or {}
    if perm.get("defaultMode") == "bypassPermissions":
        add("HIGH", "perms", p, "defaultMode=bypassPermissions: every tool call runs without asking")
    if s.get("skipDangerousModePermissionPrompt"):
        add("MED", "perms", p, "dangerous-mode confirmation is suppressed")
    allow = perm.get("allow") or []
    # a key leaked into an allow rule: the exact bug that caused the real incident
    for a in allow:
        m = SECRET_RX.search(a)
        if m:
            add("HIGH", "perms", p, f"a {secret_kind(m.group(0))} secret is baked into an allow rule (saved by 'always allow' on a command that contained it)")
    broad = [a for a in allow if any(re.match(b, a) for b in BROAD)]
    danger = [a for a in allow if DANGER_CMD.match(a)]
    if broad:
        add("MED", "perms", p, f"{len(broad)} blanket allow rule(s), e.g. {broad[:3]}")
    if danger:
        add("MED", "perms", p, f"{len(danger)} allow rule(s) for network/exec commands, e.g. {danger[:3]}")
    if allow and not (perm.get("deny") or []):
        add("LOW", "perms", p, f"{len(allow)} allow rule(s) and no deny rules (nothing is ever blocked)")
    for ev, lst in (s.get("hooks") or {}).items():
        for h in lst:
            for hh in h.get("hooks", []):
                c = hh.get("command", "")
                if re.search(r"curl|wget|https?://", c):
                    add("MED", "hooks", p, f"{ev} hook makes a network call: {c[:60]}")


# ---------------- plaintext secrets in any agent config ----------------
def audit_plaintext(p):
    try:
        with open(p, encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return
    kinds = Counter(secret_kind(m.group(0)) for m in SECRET_RX.finditer(text))
    if kinds:
        add("HIGH", "secrets", p, f"{sum(kinds.values())} token-shaped string(s) in plaintext: {dict(kinds)}")


# ---------------- config files that are tracked in git ----------------
def git_tracked(path):
    d = os.path.dirname(path)
    try:
        r = subprocess.run(["git", "-C", d, "ls-files", "--error-unmatch", os.path.basename(path)],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


# ---------------- skills ----------------
HIDDEN = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
B64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
FETCH_EXEC = re.compile(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh")


def audit_skill(p):
    d = os.path.dirname(p)
    try:
        t = open(p, encoding="utf-8").read()
    except Exception:
        return
    hid = HIDDEN.findall(t)
    if hid:
        names = Counter(unicodedata.name(c, hex(ord(c))) for c in hid)
        add("HIGH", "skills", p, f"{len(hid)} invisible/bidi char(s): {dict(names.most_common(3))}")
    if B64.search(t):
        add("MED", "skills", p, "a long base64-like blob (could hide a payload)")
    if FETCH_EXEC.search(t):
        add("HIGH", "skills", p, "instructs piping a downloaded script straight into a shell")
    for f in glob.glob(d + "/**/*", recursive=True):
        if not f.endswith((".sh", ".py", ".js", ".mjs", ".ts")):
            continue
        try:
            body = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if HIDDEN.search(body):
            add("HIGH", "skills", f, "invisible/bidi characters inside a bundled script")
        if FETCH_EXEC.search(body):
            add("HIGH", "skills", f, "bundled script pipes a download into a shell")


# ---------------- walk the project dir (bounded) ----------------
def walk_project(root):
    hits = {"mcp": [], "perms": [], "plaintext": []}
    root = os.path.abspath(root)
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count("/") - base_depth >= MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if fn == ".mcp.json":
                hits["mcp"].append(full)
            elif fn.startswith("settings") and fn.endswith(".json") and ".claude" in dirpath:
                hits["perms"].append(full)
                hits["plaintext"].append(full)
            elif fn == "mcp.json" and ".cursor" in dirpath:
                hits["mcp"].append(full)
    return hits


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    root = args[0] if args else os.getcwd()

    # ---- global agent configs (all tools) ----
    global_json_cfgs = [
        os.path.join(HOME, ".claude.json"),
        os.path.join(HOME, ".claude/settings.json"),
        os.path.join(HOME, ".claude/settings.local.json"),
        os.path.join(HOME, "Library/Application Support/Claude/claude_desktop_config.json"),
        os.path.join(HOME, ".cursor/mcp.json"),
        os.path.join(HOME, ".config/cursor/mcp.json"),
    ]
    scanned = []
    for p in global_json_cfgs:
        if not os.path.exists(p):
            continue
        scanned.append(p)
        cfg = load_json(p) or {}
        audit_mcp(cfg.get("mcpServers"), p)
        for proj, pc in (cfg.get("projects") or {}).items():
            if isinstance(pc, dict):
                audit_mcp(pc.get("mcpServers"), f"{p} :: project {os.path.basename(proj)}")
        audit_plaintext(p)
        if "settings" in os.path.basename(p):
            audit_permissions(p)

    # ---- Codex (TOML) ----
    codex = os.path.join(HOME, ".codex/config.toml")
    if os.path.exists(codex):
        scanned.append(codex)
        cfg = load_toml(codex) or {}
        audit_mcp(cfg.get("mcp_servers") or cfg.get("mcpServers"), codex)
        audit_plaintext(codex)

    # ---- project tree ----
    hits = walk_project(root)
    for p in hits["mcp"]:
        scanned.append(p)
        audit_mcp((load_json(p) or {}).get("mcpServers"), p)
    for p in set(hits["perms"]):
        scanned.append(p)
        audit_permissions(p)
        audit_plaintext(p)

    # ---- git-tracked config (the real-incident check) ----
    for p in set(scanned):
        name = os.path.basename(p)
        if name in ("settings.local.json", ".mcp.json", "claude_desktop_config.json") and git_tracked(p):
            add("HIGH", "git", p, f"{name} is tracked in git - secrets/permissions in it are in the repo history")

    # ---- skills ----
    skill_files = (glob.glob(os.path.join(HOME, ".claude/skills/**/SKILL.md"), recursive=True)
                   + glob.glob(os.path.join(HOME, ".claude/plugins/**/SKILL.md"), recursive=True)
                   + glob.glob(os.path.join(root, ".claude/skills/**/SKILL.md"), recursive=True))
    for p in skill_files:
        audit_skill(p)

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    findings.sort(key=lambda f: (order[f[0]], f[1]))
    totals = Counter(f[0] for f in findings)

    if as_json:
        print(json.dumps({
            "scanned": [p.replace(HOME, "~") for p in sorted(set(scanned))],
            "skills_checked": len(skill_files),
            "findings": [{"severity": s, "area": a, "where": w, "what": wt} for s, a, w, wt in findings],
            "totals": dict(totals),
        }, ensure_ascii=False, indent=2))
    else:
        print("agent-audit - local, read-only. Secret VALUES are never shown or sent.\n")
        print(f"scanned {len(set(scanned))} config file(s) and {len(skill_files)} skill(s) under {root}\n")
        if not findings:
            print("No issues found. Your agent setup looks clean.")
        for sev, area, where, what in findings:
            print(f"[{sev}] {area:8} {where}\n           {what}")
        print(f"\ntotals: {dict(totals)}")
        if totals.get("HIGH"):
            print("\nFix HIGH findings first. If a secret leaked, ROTATE it - "
                  "removing it from the file does not remove it from git history.")

    return 1 if totals.get("HIGH") else 0


if __name__ == "__main__":
    sys.exit(main())
