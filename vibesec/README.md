# 🛡️ VibeSec

**Paste your code → get a plain-English security report with fixes.**

Built for people who ship fast ("vibe coders") and want a quick safety check
before they push. Drop in files or paste a snippet, and VibeSec flags common
security mistakes — hardcoded secrets, SQL/command injection, `eval`, XSS, weak
crypto, insecure defaults — and explains, in beginner-friendly language, *why*
each one is risky and *how* to fix it.

## Two modes

| Mode | What it does | Needs |
|------|--------------|-------|
| **Built-in scan** | ~30 pattern-based checks that run **entirely in your browser**. Instant, free, and your code never leaves your machine. | Nothing |
| **🤖 Deep scan with Claude AI** | Sends your code to Claude for a smarter, deeper review with tailored fixes. | The server (local or deployed) + an Anthropic API key |

The built-in scan always works. The AI deep scan is an optional toggle and uses
**bring-your-own-key**: the visitor supplies their own Anthropic API key, which
is stored only in their browser and never saved or logged on the server.

---

## Quick start

You only need **Python 3** (already installed on most machines).

```bash
cd vibesec
python server.py
```

Then open **http://localhost:8000** and start scanning.

> You can also just open `index.html` directly in a browser — the built-in scan
> works fine that way. Running `server.py` is only needed for the AI deep scan.

---

## Turning on the AI deep scan

1. Install the Anthropic SDK (already in `requirements.txt`):
   ```bash
   pip install anthropic
   ```
2. Restart `python server.py` and reload the page. Tick **🤖 Deep scan with
   Claude AI**, paste your own Anthropic API key (get one at
   https://console.anthropic.com) into the field that appears, then scan.

Your key is kept in your browser (optionally remembered via `localStorage`) and
sent to the server only to relay the request to Anthropic — it is never stored
or logged. Your code is only sent to Anthropic when the toggle is on and you run
a scan.

> **Local shortcut:** if you set `ANTHROPIC_API_KEY` in the server's own
> environment, the key field disappears and scans use that key — handy for
> solo/local use. **Don't do this on a public deployment** or you'll pay for
> everyone's scans.

### Optional config

| Env var | Default | Purpose |
|---------|---------|---------|
| `HOST` | `127.0.0.1` | Interface to bind (`0.0.0.0` for hosting) |
| `PORT` | `8000` | Port to serve on (hosts usually set this for you) |
| `ANTHROPIC_API_KEY` | — | Local-only fallback key (omit for bring-your-own-key) |
| `VIBESEC_MODEL` | `claude-opus-4-8` | Which Claude model to use |

---

The built-in checks are **heuristics**. They catch common mistakes but can miss
real issues and occasionally flag harmless code (false positives). VibeSec is a
helpful first pass — not a replacement for a professional security review.
