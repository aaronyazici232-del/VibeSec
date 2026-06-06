/*
 * VibeSec — built-in security rules
 *
 * Each rule is a heuristic, regex-based check that runs entirely in the browser.
 * Findings are hints, not proof: regex can't understand your whole program, so
 * expect the occasional false positive. The goal is to catch the *common*
 * mistakes that bite people shipping fast.
 *
 * Rule shape:
 *   id        unique slug
 *   title     short human name
 *   severity  'critical' | 'high' | 'medium' | 'low' | 'info'
 *   pattern   RegExp tested against each line of code
 *   why       plain-language explanation of the risk
 *   fix       plain-language "how to fix it"
 *   ignore    (optional) RegExp — if it matches the line, skip (cuts false positives)
 *   cwe       (optional) reference id
 */

const VIBESEC_RULES = [
  // ---------------------------------------------------------------- SECRETS
  {
    id: 'aws-access-key',
    title: 'Hardcoded AWS access key',
    severity: 'critical',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    why: 'This looks like an AWS access key ID committed straight into your code. Anyone who sees this file (GitHub, a leaked bundle, a screen share) can spin up servers and run up a huge bill on your account.',
    fix: 'Remove the key from the code and rotate it immediately in the AWS console. Load credentials from environment variables or a secrets manager instead, e.g. read `process.env.AWS_ACCESS_KEY_ID` (Node) or `os.environ["AWS_ACCESS_KEY_ID"]` (Python).',
    cwe: 'CWE-798',
  },
  {
    id: 'private-key-block',
    title: 'Private key embedded in source',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    why: 'A private key is pasted directly into the file. Private keys are the master keys to servers, signing, or encryption — leaking one is game over.',
    fix: 'Never store private keys in code. Keep them in a secrets manager or an environment variable, load them at runtime, and rotate this key now that it has been exposed.',
    cwe: 'CWE-798',
  },
  {
    id: 'anthropic-key',
    title: 'Hardcoded Anthropic API key',
    severity: 'critical',
    pattern: /\bsk-ant-[A-Za-z0-9_\-]{20,}/,
    why: 'An Anthropic API key is hardcoded. If it leaks, someone can make API calls billed to you.',
    fix: 'Delete the key, regenerate it in the Anthropic console, and read it from `ANTHROPIC_API_KEY` in the environment instead of hardcoding it.',
    cwe: 'CWE-798',
  },
  {
    id: 'openai-key',
    title: 'Hardcoded OpenAI / generic "sk-" key',
    severity: 'critical',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}/,
    ignore: /sk-ant-|sk_live_|sk_test_/,
    why: 'This looks like an OpenAI-style secret key in your source. Leaked AI keys get scraped and abused within minutes.',
    fix: 'Remove it, rotate the key with your provider, and load it from an environment variable.',
    cwe: 'CWE-798',
  },
  {
    id: 'stripe-key',
    title: 'Hardcoded Stripe secret key',
    severity: 'critical',
    pattern: /\bsk_live_[0-9a-zA-Z]{16,}/,
    why: 'A live Stripe secret key is in your code. This can move real money and read customer/payment data.',
    fix: 'Roll the key in the Stripe dashboard right away and load it from a server-side environment variable. Never expose secret keys in front-end code.',
    cwe: 'CWE-798',
  },
  {
    id: 'github-token',
    title: 'Hardcoded GitHub token',
    severity: 'critical',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}/,
    why: 'A GitHub personal access / app token is committed. It can read or push to your repos depending on scope.',
    fix: 'Revoke the token in GitHub settings and use an environment variable or GitHub Actions secret instead.',
    cwe: 'CWE-798',
  },
  {
    id: 'google-api-key',
    title: 'Hardcoded Google API key',
    severity: 'high',
    pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/,
    why: 'A Google API key is hardcoded. Depending on restrictions, it can be abused to rack up charges on Maps, Cloud, etc.',
    fix: 'Restrict the key (by referrer/IP/API) and store it in environment config rather than source.',
    cwe: 'CWE-798',
  },
  {
    id: 'slack-token',
    title: 'Hardcoded Slack token',
    severity: 'high',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
    why: 'A Slack token is exposed. It can read/post messages in your workspace.',
    fix: 'Revoke the token in Slack and load it from environment config.',
    cwe: 'CWE-798',
  },
  {
    id: 'jwt-literal',
    title: 'Hardcoded JWT / bearer token',
    severity: 'high',
    pattern: /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/,
    why: 'A JSON Web Token is baked into the code. If it is a real session/access token, anyone with it can impersonate that user or service until it expires.',
    fix: 'Do not hardcode tokens. Obtain them at runtime and store them securely (httpOnly cookie or secrets store). Treat this one as compromised.',
    cwe: 'CWE-798',
  },
  {
    id: 'generic-secret-assign',
    title: 'Possible hardcoded secret / password',
    severity: 'high',
    pattern: /(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*['"][^'"]{6,}['"]/i,
    ignore: /process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv|\$\{|<[^>]+>|your[_-]?|example|placeholder|changeme|xxxx|todo|dummy|sample|\*\*\*|redacted|None|null|""|''/i,
    why: 'A secret or password appears to be assigned a literal value in the code. Hardcoded credentials get committed, shared, and leaked.',
    fix: 'Move the value into an environment variable or secrets manager and read it at runtime. If it was ever committed, rotate it.',
    cwe: 'CWE-798',
  },
  {
    id: 'creds-in-url',
    title: 'Credentials embedded in a URL',
    severity: 'high',
    pattern: /[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/[^/\s:@'"]+:[^/\s@'"]+@/,
    ignore: /process\.env|os\.environ|\$\{|<[^>]+>|user:pass(word)?@|example\.com|username:password/i,
    why: 'A connection string includes a username and password directly in the URL (e.g. db://user:pass@host). These end up in logs, error messages, and version history.',
    fix: 'Pull the username/password out of the URL and supply them through environment variables or a secrets manager.',
    cwe: 'CWE-798',
  },

  // ------------------------------------------------------------- INJECTION
  {
    id: 'sql-string-concat',
    title: 'Possible SQL injection (string building)',
    severity: 'critical',
    pattern: /(?:select|insert\s+into|update|delete\s+from|drop\s+table|where)\b[^;'"]*?(?:["'`]\s*\+|\+\s*["'`]|%\s*\(|\.format\s*\(|f["'`])/i,
    why: 'A SQL query is being built by gluing strings together with user-controlled data. Attackers can inject their own SQL to read, modify, or delete your whole database.',
    fix: 'Use parameterized queries / prepared statements. Pass values as parameters (e.g. `cursor.execute("... WHERE id = %s", [id])`) instead of concatenating or formatting them into the query string.',
    cwe: 'CWE-89',
  },
  {
    id: 'sql-execute-fstring',
    title: 'SQL executed from an f-string / format()',
    severity: 'critical',
    pattern: /\b(?:execute|executemany|query|raw)\s*\(\s*f["'`]/i,
    why: 'A database query is run from an f-string. Any variable interpolated into it can carry a SQL injection payload.',
    fix: 'Switch to parameterized queries — keep the SQL static and pass values as a separate argument list, never interpolated into the string.',
    cwe: 'CWE-89',
  },
  {
    id: 'os-command-injection',
    title: 'Shell command built from variables',
    severity: 'critical',
    pattern: /\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\([^)]*(?:\+|%|\.format\(|f["'`]|`)/i,
    why: 'A shell command is being assembled from variables. If any part comes from user input, an attacker can chain extra commands (e.g. `; rm -rf /`).',
    fix: 'Avoid the shell. Pass arguments as a list (e.g. `subprocess.run(["ls", path])`) instead of one string, and never set `shell=True` with untrusted input.',
    cwe: 'CWE-78',
  },
  {
    id: 'subprocess-shell-true',
    title: 'subprocess with shell=True',
    severity: 'high',
    pattern: /subprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True/i,
    why: 'Running a subprocess with `shell=True` invokes a full shell, which makes command injection possible if any input is attacker-controlled.',
    fix: 'Set `shell=False` (the default) and pass the command as a list of arguments. Only use `shell=True` with fully static, trusted strings.',
    cwe: 'CWE-78',
  },
  {
    id: 'child-process-exec',
    title: 'Node child_process.exec with dynamic input',
    severity: 'high',
    pattern: /(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[^,)]*\+)/,
    why: '`child_process.exec` runs a string through the shell. Interpolating variables into it allows command injection.',
    fix: 'Use `execFile` / `spawn` with an arguments array instead of `exec`, so user input can never break out into shell syntax.',
    cwe: 'CWE-78',
  },

  // --------------------------------------------------- DANGEROUS EXECUTION
  {
    id: 'eval-call',
    title: 'Use of eval()',
    severity: 'high',
    pattern: /(?<![.\w])eval\s*\(/,
    why: '`eval()` runs whatever string you give it as live code. If any of that string comes from user input, it becomes arbitrary code execution — one of the most dangerous bugs there is.',
    fix: 'Almost nothing needs eval. Parse data with `JSON.parse` (JS) or `ast.literal_eval` (Python), look values up in an object/dict, or restructure the logic to avoid executing strings.',
    cwe: 'CWE-95',
  },
  {
    id: 'py-exec-call',
    title: 'Use of exec()',
    severity: 'high',
    pattern: /(?<![.\w])exec\s*\(/,
    why: 'Python `exec()` runs arbitrary code from a string. Feeding it any untrusted data is a classic remote-code-execution hole.',
    fix: 'Avoid executing strings. Restructure the logic, or use a narrow, safe alternative like `ast.literal_eval` for simple literals.',
    cwe: 'CWE-95',
  },
  {
    id: 'js-function-ctor',
    title: 'Code built with new Function()',
    severity: 'high',
    pattern: /new\s+Function\s*\(/,
    why: 'The `Function` constructor compiles a string into runnable code, just like eval. User-controlled input here means remote code execution.',
    fix: 'Avoid generating code from strings. Use normal functions, lookup tables, or a safe expression library if you truly need dynamic evaluation.',
    cwe: 'CWE-95',
  },
  {
    id: 'py-pickle-loads',
    title: 'Insecure deserialization with pickle',
    severity: 'high',
    pattern: /\bpickle\.loads?\s*\(/,
    why: 'Unpickling data can execute arbitrary code. If the data ever comes from a user, file upload, or network, this is a remote-code-execution risk.',
    fix: 'Do not unpickle untrusted data. Use a safe format like JSON for anything that crosses a trust boundary.',
    cwe: 'CWE-502',
  },
  {
    id: 'py-yaml-load',
    title: 'Unsafe yaml.load()',
    severity: 'high',
    pattern: /\byaml\.load\s*\(/,
    ignore: /SafeLoader|Loader\s*=\s*yaml\.SafeLoader|safe_load/,
    why: '`yaml.load()` without a safe loader can instantiate arbitrary Python objects, which attackers can abuse to run code.',
    fix: 'Use `yaml.safe_load(...)` instead (or pass `Loader=yaml.SafeLoader`).',
    cwe: 'CWE-502',
  },

  // --------------------------------------------------------------- XSS / DOM
  {
    id: 'js-innerhtml',
    title: 'Assigning to innerHTML',
    severity: 'medium',
    pattern: /\.(?:innerHTML|outerHTML)\s*=/,
    ignore: /innerHTML\s*=\s*['"`]\s*['"`]/,
    why: 'Writing to `innerHTML` with data that contains user input lets attackers inject HTML/JavaScript (cross-site scripting).',
    fix: 'Use `textContent` for plain text. If you must render HTML, sanitize it first with a library like DOMPurify.',
    cwe: 'CWE-79',
  },
  {
    id: 'js-document-write',
    title: 'Use of document.write()',
    severity: 'medium',
    pattern: /document\.write(?:ln)?\s*\(/,
    why: '`document.write` injects raw markup into the page; with user input it enables cross-site scripting and can break the page.',
    fix: 'Build elements with `document.createElement` / `textContent`, or sanitize any HTML before inserting it.',
    cwe: 'CWE-79',
  },
  {
    id: 'react-dangerous-html',
    title: 'dangerouslySetInnerHTML',
    severity: 'medium',
    pattern: /dangerouslySetInnerHTML/,
    why: 'React escapes output by default; this prop bypasses that protection. Untrusted HTML here results in cross-site scripting.',
    fix: 'Avoid it where possible. If you need to render HTML, run it through a sanitizer (e.g. DOMPurify) before passing it in.',
    cwe: 'CWE-79',
  },
  {
    id: 'vue-v-html',
    title: 'Vue v-html directive',
    severity: 'medium',
    pattern: /v-html\s*=/,
    why: '`v-html` renders raw HTML and skips Vue’s escaping. With user-supplied content it opens a cross-site scripting hole.',
    fix: 'Prefer `{{ }}` text interpolation. If raw HTML is required, sanitize it first.',
    cwe: 'CWE-79',
  },

  // ----------------------------------------------------- CRYPTO / TRANSPORT
  {
    id: 'weak-hash',
    title: 'Weak hash algorithm (MD5 / SHA-1)',
    severity: 'medium',
    pattern: /\b(?:md5|sha1)\b|hashlib\.(?:md5|sha1)|getInstance\s*\(\s*["'](?:MD5|SHA-1)["']/i,
    why: 'MD5 and SHA-1 are broken for security use — they are fast to brute-force and have collision attacks. Bad for passwords or integrity checks.',
    fix: 'For passwords use a slow password hash like bcrypt, scrypt, or Argon2. For integrity use SHA-256 or stronger.',
    cwe: 'CWE-327',
  },
  {
    id: 'tls-verify-off',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    pattern: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE|_create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i,
    why: 'Turning off certificate verification means anyone on the network can impersonate the server (man-in-the-middle) and read or change traffic.',
    fix: 'Leave certificate verification on. If you hit a cert error, fix the certificate or add the proper CA — do not disable verification.',
    cwe: 'CWE-295',
  },
  {
    id: 'insecure-http',
    title: 'Insecure http:// URL',
    severity: 'low',
    pattern: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.|schemas\.|www\.w3\.org|xmlns)/i,
    why: 'Traffic over plain http:// is unencrypted and can be read or modified in transit.',
    fix: 'Use https:// endpoints. For local development http://localhost is fine.',
    cwe: 'CWE-319',
  },
  {
    id: 'math-random-token',
    title: 'Math.random() used for something security-ish',
    severity: 'low',
    pattern: /Math\.random\s*\(\)/,
    why: '`Math.random()` is predictable and must never be used to generate tokens, passwords, session IDs, or anything security-sensitive.',
    fix: 'For anything security-related use `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` / `crypto.randomUUID()` (Node). Ignore this if it is just for visual/non-security randomness.',
    cwe: 'CWE-330',
  },

  // ------------------------------------------------ CONFIG / MISCONFIG / LEAKS
  {
    id: 'cors-wildcard',
    title: 'CORS allows any origin (*)',
    severity: 'medium',
    pattern: /Access-Control-Allow-Origin["'`]?\s*[:,]\s*["'`]\*|origin\s*:\s*["'`]\*["'`]|cors\(\s*\)/i,
    why: 'Allowing every origin (`*`) lets any website call your API from a victim’s browser. Combined with cookies/credentials this can leak user data.',
    fix: 'Whitelist the specific origins you trust instead of using `*`, and never combine `*` with credentialed requests.',
    cwe: 'CWE-942',
  },
  {
    id: 'debug-mode-on',
    title: 'Debug mode enabled',
    severity: 'medium',
    pattern: /\bdebug\s*=\s*True|DEBUG\s*=\s*True|app\.debug\s*=\s*true|flask\.debug|debug:\s*true/i,
    why: 'Debug mode can expose stack traces, configuration, and an interactive console to attackers if it ships to production.',
    fix: 'Turn debug off in production. Drive it from an environment variable so it is only on during local development.',
    cwe: 'CWE-489',
  },
  {
    id: 'bind-all-interfaces',
    title: 'Server bound to 0.0.0.0',
    severity: 'low',
    pattern: /0\.0\.0\.0/,
    ignore: /Access-Control|CERT_NONE/,
    why: 'Binding to 0.0.0.0 exposes the service on every network interface. On a dev laptop or misconfigured host this can make a debug server reachable from the internet.',
    fix: 'Bind to 127.0.0.1 for local-only services. Only use 0.0.0.0 intentionally behind a firewall/reverse proxy in production.',
    cwe: 'CWE-668',
  },
  {
    id: 'log-sensitive',
    title: 'Logging a secret / password',
    severity: 'low',
    pattern: /(?:console\.log|print|logger?\.(?:info|debug|warn|error|log))\s*\([^)]*(?:password|passwd|secret|api[_-]?key|token|credit[_-]?card)/i,
    why: 'Printing secrets to logs spreads them into log files, log aggregators, and consoles where many people (and tools) can read them.',
    fix: 'Remove the secret from the log line, or mask it (show only the last few characters).',
    cwe: 'CWE-532',
  },
  {
    id: 'localstorage-token',
    title: 'Storing a token in localStorage',
    severity: 'low',
    pattern: /localStorage\.setItem\s*\([^)]*(?:token|password|secret|api[_-]?key|jwt)/i,
    why: 'localStorage is readable by any JavaScript on the page, so a single cross-site-scripting bug can steal tokens kept there.',
    fix: 'Prefer httpOnly, Secure cookies for auth tokens so JavaScript cannot read them. If you must use localStorage, keep XSS risk minimal.',
    cwe: 'CWE-922',
  },
  {
    id: 'sec-check-disabled',
    title: 'Security check suppressed',
    severity: 'info',
    pattern: /#\s*nosec|eslint-disable.*no-eval|nosemgrep|@ts-ignore|noqa:\s*S\d|type:\s*ignore/i,
    why: 'A linter or security check is being silenced here. Sometimes that is fine — but it can also hide a real problem on this line.',
    fix: 'Double-check why the check was disabled and make sure the underlying code is actually safe.',
    cwe: 'CWE-1078',
  },
];

// Expose for both browser (global) and any module consumer.
if (typeof window !== 'undefined') {
  window.VIBESEC_RULES = VIBESEC_RULES;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VIBESEC_RULES };
}
