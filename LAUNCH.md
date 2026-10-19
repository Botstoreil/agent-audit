# Launch draft - agent-audit

The point of publishing: people come to the tool and run it themselves. No cold DMs.
Post ONCE in each place, lead with the real story, be honest about the privacy guarantee.

---

## Show HN / Reddit r/programming title

> Show HN: agent-audit - find the API key your AI agent saved in a permission rule

## Body (English)

I let Claude Code "always allow" a command once. It turned out the command had my
Google AI key inline, so the whole command - key included - got saved into
`settings.local.json`. That file was tracked in git and had been pushed for 8 months.
I only found it by writing a script to audit my own agent config.

So I cleaned up the script and open-sourced it. `agent-audit` is a single Python file,
no dependencies, that checks your local AI-agent setup (Claude Code, Claude Desktop,
Cursor, Codex) for:

- secrets saved inside permission rules ("always allow" on a command with a key in it)
- secrets in plaintext config
- config files tracked in git (so they're in your repo history)
- walls of `allow` rules with an empty `deny` list
- MCP servers pinned to "latest" that auto-run whatever ships next
- skills with invisible/bidi characters or `curl | sh`

It runs locally, makes zero network calls, and never prints the value of a secret -
only its type and where it lives. ~300 lines, read it before you run it.

    python3 agent_audit.py

Would love patterns for agent tools I haven't covered (Windsurf, Cline, etc).

GitHub: <LINK>

---

## Hebrew dev community (Telegram / Facebook groups)

כתבתי כלי קטן בקוד פתוח שבודק אם סוכן ה-AI שלכם (Claude Code, Cursor, Codex) שמר בטעות
מפתח API בתוך קובץ הרשאות, או דחף קובץ הגדרות עם סודות ל-git. זה קרה לי: מפתח Google
נשמר בכלל "always allow" והיה דחוף ל-git שמונה חודשים.

קובץ פייתון אחד, בלי תלויות, רץ מקומית, לא שולח שום דבר לרשת, ולא מדפיס את הערך של
אף סוד - רק את הסוג ואיפה הוא נמצא.

    python3 agent_audit.py

<LINK>

---

## After launch - what to measure (the real gate)

- installs / clones in the first month
- how many people open an issue or report a real finding
- only if there's pull: build the paid layer (CI action + team dashboard)

Do NOT build the paid tier before there are users. First prove people want the free one.
