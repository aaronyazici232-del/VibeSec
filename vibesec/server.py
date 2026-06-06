#!/usr/bin/env python3
"""
VibeSec server.

Serves the static site AND acts as a stateless proxy for the optional
"Deep scan with Claude AI" feature.

Run it locally:
    python server.py
then open http://localhost:8000

Deploy it: see README.md (Dockerfile / render.yaml included). Set HOST=0.0.0.0
and let the platform set $PORT.

The built-in (browser) scanner works with or without this server and never
sends code anywhere.

AI deep scan uses BRING-YOUR-OWN-KEY:
  * The browser sends the visitor's own Anthropic API key with the request.
  * This server uses it for that single request and NEVER stores or logs it.
  * For local dev convenience, if a visitor doesn't send a key the server will
    fall back to an ANTHROPIC_API_KEY in its own environment (don't set one on a
    public deployment, or you'd be paying for everyone's scans).
The `anthropic` package must be installed for the AI proxy to work
(pip install anthropic). The built-in checks need nothing.
"""

import json
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
MODEL = os.environ.get("VIBESEC_MODEL", "claude-opus-4-8")
MAX_CODE_CHARS = 60000

SYSTEM_PROMPT = """You are VibeSec, a friendly application-security reviewer for \
people who build software quickly without a security background ("vibe coders").

You will be given one or more source files. Find real, concrete security \
vulnerabilities and risky patterns. For each issue:
- Explain the risk in plain, non-jargon language a beginner can understand.
- Be specific about WHY it is dangerous and what an attacker could do.
- Give a concrete, actionable fix (ideally with a short corrected snippet).

Focus on things that actually matter: hardcoded secrets/credentials, injection \
(SQL, command, code/eval), insecure deserialization, XSS, broken authentication \
or authorization, SSRF, path traversal, weak crypto, insecure transport, unsafe \
defaults (debug mode, permissive CORS), and sensitive data exposure.

Prefer precision over volume: only report issues you are reasonably confident \
about. Do not invent problems. If the code is largely fine, say so and report \
only what you find. Assign each finding a severity of critical, high, medium, \
low, or info."""

# JSON schema for structured output so the front-end can render findings reliably.
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "A short, friendly overall assessment (2-4 sentences).",
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "line": {
                        "type": "integer",
                        "description": "Approx line number, or 0 if unknown.",
                    },
                    "snippet": {
                        "type": "string",
                        "description": "The relevant line(s) of code, if applicable.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Plain-language explanation of the risk.",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "Concrete fix, with a corrected snippet if helpful.",
                    },
                },
                "required": [
                    "title", "severity", "line", "snippet",
                    "description", "recommendation",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "findings"],
    "additionalProperties": False,
}


def sdk_installed():
    """Whether the `anthropic` package is importable on this server."""
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def has_server_key():
    """Whether this server has its own key (local-dev fallback only)."""
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def run_deep_scan(code: str, api_key: str = None) -> dict:
    """Call Claude with structured output and return the parsed findings dict.

    `api_key` is the caller's own key (bring-your-own-key). When it's None we let
    the SDK resolve a key from the server environment (local-dev convenience).
    The key is used for this one request and is never stored or logged.
    """
    import anthropic

    code = (code or "")[:MAX_CODE_CHARS]
    if not code.strip():
        return {"summary": "No code was provided.", "findings": []}

    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    user_msg = (
        "Review the following code for security issues and respond using the "
        "required JSON format.\n\n```\n" + code + "\n```"
    )

    # Stream so long reviews don't hit request timeouts; structured output
    # guarantees the first text block is schema-valid JSON.
    with client.messages.stream(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": FINDINGS_SCHEMA},
        },
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    ) as stream:
        message = stream.get_final_message()

    text = next((b.text for b in message.content if b.type == "text"), "")
    return json.loads(text)


class Handler(SimpleHTTPRequestHandler):
    # quieter logging
    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/api/config":
            installed = sdk_installed()
            return self._send_json(200, {
                "aiAvailable": installed,
                "mode": "byok",
                "hasServerKey": has_server_key(),
                "reason": "ready" if installed else "server is missing the 'anthropic' package",
                "model": MODEL if installed else None,
            })
        return super().do_GET()

    def do_POST(self):
        if self.path.rstrip("/") != "/api/deep-scan":
            return self._send_json(404, {"error": "not found"})

        if not sdk_installed():
            return self._send_json(503, {
                "error": "AI deep scan isn't available on this server (the 'anthropic' package isn't installed)."
            })

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2_000_000:
                return self._send_json(413, {"error": "request too large"})
            body = self.rfile.read(length) if length else b"{}"
            data = json.loads(body or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._send_json(400, {"error": "invalid request body"})

        # Bring-your-own-key: prefer the caller's key; fall back to a server env
        # key only for local dev. The key is used once and never stored or logged.
        body_key = (data.get("apiKey") or "").strip()
        if body_key:
            api_key = body_key
        elif has_server_key():
            api_key = None  # let the SDK resolve it from the environment
        else:
            return self._send_json(400, {
                "error": "Enter your Anthropic API key to use the AI deep scan."
            })

        try:
            result = run_deep_scan(data.get("code", ""), api_key)
            return self._send_json(200, result)
        except Exception as exc:  # surface a readable, key-free message to the UI
            name = type(exc).__name__
            status = 401 if "Authentication" in name else 500
            friendly = {
                "AuthenticationError": "That API key was rejected by Anthropic. Double-check it and try again.",
                "PermissionDeniedError": "That API key doesn't have permission for this model.",
                "RateLimitError": "Anthropic rate-limited this key. Wait a moment and retry.",
            }.get(name, f"{name}: {str(exc) or 'unexpected error'}")
            return self._send_json(status, {"error": friendly})


def main():
    handler = partial(Handler, directory=HERE)
    httpd = ThreadingHTTPServer((HOST, PORT), handler)
    if not sdk_installed():
        ai_line = "off - server is missing the 'anthropic' package (pip install anthropic)"
    elif has_server_key():
        ai_line = f"ON with this server's key ({MODEL}) - fine for local, NOT for public deploys"
    else:
        ai_line = f"bring-your-own-key ({MODEL}) - visitors supply their own API key"
    shown_host = "localhost" if HOST in ("127.0.0.1", "0.0.0.0") else HOST
    print("\n  VibeSec is running")
    print(f"  ->  http://{shown_host}:{PORT}")
    print(f"  AI deep scan: {ai_line}")
    print("  (Ctrl+C to stop)\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped. Stay safe out there.\n")
        httpd.server_close()


if __name__ == "__main__":
    main()
