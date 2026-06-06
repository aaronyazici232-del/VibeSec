/* VibeSec — front-end scanning engine + UI */
(function () {
  'use strict';

  const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SEVERITY_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
  const SEVERITY_COLOR = {
    critical: '#ff4d6d', high: '#ff8a3d', medium: '#ffc53d', low: '#4da8ff', info: '#8a92b2',
  };

  const MAX_FILE_BYTES = 1024 * 1024;          // 1 MB per file
  const MAX_AI_CHARS = 60000;                   // cap what we send to the AI

  // ---- state ----------------------------------------------------------------
  /** @type {{name:string, content:string}[]} */
  let files = [];
  let activeFilter = 'all';
  let lastFindings = [];
  let aiAvailable = false;
  let hasServerKey = false;
  let aiModel = 'Claude';
  const LS_KEY = 'vibesec_api_key';

  // ---- element refs ---------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const dropZone = $('dropZone');
  const fileInput = $('fileInput');
  const codeInput = $('codeInput');
  const fileListEl = $('fileList');
  const resultsEl = $('results');
  const findingsListEl = $('findingsList');
  const aiToggle = $('aiToggle');
  const aiToggleWrap = $('aiToggleWrap');
  const aiStatus = $('aiStatus');
  const aiPanel = $('aiPanel');
  const aiKeyPanel = $('aiKeyPanel');
  const apiKeyInput = $('apiKeyInput');
  const rememberKey = $('rememberKey');

  // ---- helpers --------------------------------------------------------------
  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function extOf(name) {
    const m = /\.([a-z0-9]+)$/i.exec(name || '');
    return m ? m[1].toLowerCase() : '';
  }

  function looksBinary(name) {
    const bin = ['png','jpg','jpeg','gif','webp','ico','pdf','zip','gz','tar','exe','dll',
                 'so','dylib','mp3','mp4','mov','woff','woff2','ttf','otf','wasm','class','o'];
    return bin.includes(extOf(name));
  }

  // ---- the scanner ----------------------------------------------------------
  function scanSource(name, content) {
    const findings = [];
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.length > 2000) continue; // skip blanks / minified megastrings

      for (const rule of window.VIBESEC_RULES) {
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(line)) continue;
        if (rule.ignore && rule.ignore.test(line)) continue;

        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          file: name,
          line: i + 1,
          snippet: line.trim().slice(0, 240),
          why: rule.why,
          fix: rule.fix,
          cwe: rule.cwe || null,
          source: 'local',
        });
      }
    }
    return findings;
  }

  function gatherSources() {
    const sources = files.slice();
    const pasted = codeInput.value.trim();
    if (pasted) sources.push({ name: 'pasted code', content: codeInput.value });
    return sources;
  }

  // ---- scoring --------------------------------------------------------------
  function computeScore(findings) {
    let penalty = 0;
    for (const f of findings) penalty += SEVERITY_WEIGHT[f.severity] || 1;
    return Math.max(0, 100 - penalty);
  }

  function gradeFor(score, findings) {
    const hasCritical = findings.some((f) => f.severity === 'critical');
    if (hasCritical) return { grade: 'At risk', ring: SEVERITY_COLOR.critical };
    if (score >= 90) return { grade: 'Looking good', ring: '#2ecf80' };
    if (score >= 70) return { grade: 'Some cleanup', ring: SEVERITY_COLOR.medium };
    if (score >= 40) return { grade: 'Needs work', ring: SEVERITY_COLOR.high };
    return { grade: 'At risk', ring: SEVERITY_COLOR.critical };
  }

  // ---- rendering ------------------------------------------------------------
  function severityRank(sev) { return SEVERITY_ORDER.indexOf(sev); }

  function renderResults(findings) {
    lastFindings = findings;
    resultsEl.hidden = false;

    // sort: severity desc, then file, then line
    findings.sort((a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line);

    const localFindings = findings.filter((f) => f.source === 'local');
    const score = computeScore(localFindings);
    const { grade, ring } = gradeFor(score, localFindings);

    // gauge
    const gauge = $('gauge');
    gauge.style.setProperty('--pct', score);
    gauge.style.setProperty('--ring', ring);
    $('scoreNum').textContent = score;
    $('scoreGrade').textContent = grade;

    // headline + summary
    const counts = countBySeverity(localFindings);
    $('scoreHeadline').textContent = localFindings.length === 0
      ? 'No obvious issues found'
      : `${localFindings.length} potential issue${localFindings.length === 1 ? '' : 's'} found`;
    $('scoreSummary').textContent = summarize(counts);

    // severity count chips
    const sevCounts = $('sevCounts');
    sevCounts.innerHTML = '';
    for (const sev of SEVERITY_ORDER) {
      if (!counts[sev]) continue;
      const el = document.createElement('span');
      el.className = 'sev-count';
      el.innerHTML = `<span class="sev-dot" style="background:${SEVERITY_COLOR[sev]}"></span>${counts[sev]} ${sev}`;
      sevCounts.appendChild(el);
    }

    renderFilters(findings);
    renderFindings(findings);

    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function countBySeverity(findings) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }

  function summarize(counts) {
    if (counts.critical) return 'Critical issues found — fix these before you ship.';
    if (counts.high) return 'Some high-severity issues to address soon.';
    if (counts.medium || counts.low) return 'A few things worth tightening up.';
    return 'Nice — the built-in checks didn’t spot common mistakes. Still worth a human review.';
  }

  function renderFilters(findings) {
    const chips = $('filterChips');
    chips.innerHTML = '';
    const counts = countBySeverity(findings);
    const total = findings.length;

    const make = (key, label) => {
      const chip = document.createElement('button');
      chip.className = 'chip' + (activeFilter === key ? ' active' : '');
      chip.textContent = label;
      chip.onclick = () => { activeFilter = key; renderFilters(findings); renderFindings(findings); };
      chips.appendChild(chip);
    };

    make('all', `All (${total})`);
    for (const sev of SEVERITY_ORDER) {
      if (counts[sev]) make(sev, `${sev[0].toUpperCase() + sev.slice(1)} (${counts[sev]})`);
    }
  }

  function renderFindings(findings) {
    const visible = activeFilter === 'all'
      ? findings
      : findings.filter((f) => f.severity === activeFilter);

    $('findingsCount').textContent =
      `Showing ${visible.length} of ${findings.length} finding${findings.length === 1 ? '' : 's'}`;

    $('emptyState').hidden = findings.length !== 0;
    $('copyReportBtn').hidden = findings.length === 0;
    findingsListEl.innerHTML = '';

    for (const f of visible) {
      findingsListEl.appendChild(buildFindingCard(f));
    }
  }

  function buildFindingCard(f) {
    const card = document.createElement('div');
    card.className = 'finding';
    card.dataset.sev = f.severity;
    card.dataset.src = f.source;

    const loc = f.line ? `${escapeHtml(f.file)}:${f.line}` : escapeHtml(f.file);
    const srcLabel = f.source === 'ai'
      ? '<span class="finding-src ai">AI</span>'
      : '<span class="finding-src">rule</span>';

    const head = document.createElement('div');
    head.className = 'finding-head';
    head.innerHTML = `
      <span class="sev-badge" data-sev="${f.severity}">${f.severity}</span>
      <span class="finding-title">${escapeHtml(f.title)}</span>
      ${srcLabel}
      <span class="finding-loc">${loc}</span>
      <span class="chevron">▶</span>`;
    head.onclick = () => card.classList.toggle('open');

    const body = document.createElement('div');
    body.className = 'finding-body';
    body.innerHTML = `
      ${f.snippet ? `<pre class="snippet">${escapeHtml(f.snippet)}</pre>` : ''}
      <div class="body-block">
        <div class="body-label">⚠️ Why it’s a risk</div>
        <p class="body-text">${escapeHtml(f.why)}</p>
      </div>
      <div class="body-block">
        <div class="body-label">🛠️ How to fix it</div>
        <p class="body-text fix">${escapeHtml(f.fix)}</p>
      </div>
      ${f.cwe ? `<a class="cwe-link" href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-','')}.html" target="_blank" rel="noopener">Reference: ${escapeHtml(f.cwe)} ↗</a>` : ''}`;

    card.appendChild(head);
    card.appendChild(body);
    return card;
  }

  // ---- copyable AI fix report ----------------------------------------------
  function buildAiReport() {
    const findings = lastFindings.slice().sort((a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line);
    if (!findings.length) return '';

    const localFindings = findings.filter((f) => f.source === 'local');
    const score = computeScore(localFindings);
    const counts = countBySeverity(findings);
    const parts = SEVERITY_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);

    const out = [];
    out.push('# Security issues to fix (report from VibeSec)');
    out.push('');
    out.push('Please fix the security issues listed below in my code. For each one, apply the suggested fix (or a safer equivalent) without breaking existing functionality. Where a secret is hardcoded, also remind me to rotate it. Issues are ordered most-severe first.');
    out.push('');
    out.push(`**Summary:** ${findings.length} issue${findings.length === 1 ? '' : 's'} — ${parts.join(', ')}. Built-in security score: ${score}/100.`);

    // include the AI deep-scan notes if that ran successfully
    const aiDone = !aiPanel.hidden && document.getElementById('aiPanelStatus').textContent === 'done';
    const aiNote = aiDone ? document.getElementById('aiSummary').textContent.trim() : '';
    if (aiNote) {
      out.push('');
      out.push(`**Notes from Claude AI review:** ${aiNote}`);
    }

    findings.forEach((f, i) => {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      out.push('');
      out.push('---');
      out.push('');
      out.push(`## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
      out.push(`**Where:** ${loc}${f.cwe ? `  ·  ${f.cwe}` : ''}`);
      if (f.snippet) {
        out.push('');
        out.push('```');
        out.push(f.snippet.replace(/```/g, "'''"));
        out.push('```');
      }
      out.push('');
      out.push(`**Risk:** ${f.why}`);
      out.push(`**Fix:** ${f.fix}`);
    });

    out.push('');
    return out.join('\n');
  }

  async function copyReport() {
    const text = buildAiReport();
    if (!text) return;

    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) {
      // fallback for older/insecure contexts
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      document.body.removeChild(ta);
    }

    const btn = $('copyReportBtn');
    btn.textContent = ok ? '✓ Copied to clipboard!' : '⚠ Copy failed — select & copy manually';
    btn.classList.toggle('copied', ok);
    setTimeout(() => {
      btn.textContent = '📋 Copy fix report for AI';
      btn.classList.remove('copied');
    }, 2000);
  }

  // ---- main scan flow -------------------------------------------------------
  async function runScan() {
    const sources = gatherSources();
    if (sources.length === 0) {
      flashDropZone();
      return;
    }

    const scanBtn = $('scanBtn');
    scanBtn.disabled = true;
    scanBtn.textContent = '🔍 Scanning…';

    // local scan (synchronous, but yield so the button updates)
    await new Promise((r) => setTimeout(r, 30));
    let findings = [];
    for (const s of sources) findings = findings.concat(scanSource(s.name, s.content));

    renderResults(findings);

    scanBtn.disabled = false;
    scanBtn.textContent = '🔍 Scan for security risks';

    // optional AI deep scan
    if (aiToggle.checked && aiAvailable) {
      await runAiScan(sources);
    } else {
      aiPanel.hidden = true;
    }
  }

  function flashDropZone() {
    dropZone.classList.add('dragover');
    dropZone.querySelector('.drop-title').textContent = 'Add some code first 👇';
    setTimeout(() => {
      dropZone.classList.remove('dragover');
      dropZone.querySelector('.drop-title').textContent = 'Drag & drop your code files here';
    }, 1400);
  }

  // ---- AI deep scan (bring-your-own-key) ------------------------------------
  function getApiKey() { return (apiKeyInput.value || '').trim(); }

  function loadSavedKey() {
    try {
      const k = localStorage.getItem(LS_KEY);
      if (k) apiKeyInput.value = k;
    } catch (e) { /* localStorage may be blocked */ }
  }

  function persistKey() {
    try {
      if (rememberKey.checked && getApiKey()) localStorage.setItem(LS_KEY, getApiKey());
      else localStorage.removeItem(LS_KEY);
    } catch (e) { /* ignore */ }
  }

  function updateAiStatus() {
    if (!aiAvailable) return;
    if (hasServerKey) {
      aiStatus.textContent = `ready · ${aiModel}`;
      aiStatus.style.color = 'var(--accent-2)';
    } else if (getApiKey()) {
      aiStatus.textContent = `ready · ${aiModel} · your key`;
      aiStatus.style.color = 'var(--accent-2)';
    } else {
      aiStatus.textContent = 'bring your own key';
      aiStatus.style.color = '';
    }
  }

  function syncKeyPanel() {
    // Show the key field only when AI is on, available, and the server has no key.
    aiKeyPanel.hidden = !(aiToggle.checked && aiAvailable && !hasServerKey);
    if (!aiKeyPanel.hidden && !getApiKey()) apiKeyInput.focus();
    updateAiStatus();
  }

  async function checkAiAvailability() {
    try {
      const res = await fetch('api/config');
      if (!res.ok) throw new Error('no config');
      const cfg = await res.json();
      aiAvailable = !!cfg.aiAvailable;
      hasServerKey = !!cfg.hasServerKey;
      aiModel = cfg.model || 'Claude';

      if (!aiAvailable) {
        aiToggle.disabled = true;
        aiToggleWrap.classList.add('disabled');
        aiStatus.textContent = cfg.reason || 'unavailable';
        return;
      }
      aiToggle.disabled = false;
      aiToggleWrap.classList.remove('disabled');
      updateAiStatus();
    } catch (e) {
      aiAvailable = false;
      aiToggle.disabled = true;
      aiToggleWrap.classList.add('disabled');
      aiStatus.textContent = 'AI scan not available here';
    }
  }

  function combineForAi(sources) {
    let blob = '';
    for (const s of sources) {
      blob += `\n===== FILE: ${s.name} =====\n${s.content}\n`;
      if (blob.length > MAX_AI_CHARS) break;
    }
    return blob.slice(0, MAX_AI_CHARS);
  }

  async function runAiScan(sources) {
    const userKey = getApiKey();
    if (!hasServerKey && !userKey) {
      aiKeyPanel.hidden = false;
      apiKeyInput.focus();
      aiPanel.hidden = false;
      $('aiPanelStatus').textContent = 'needs key';
      $('aiSummary').textContent = 'Enter your Anthropic API key above, then scan again to run the AI deep scan.';
      return;
    }

    aiPanel.hidden = false;
    $('aiPanelStatus').textContent = 'analyzing with Claude…';
    $('aiSummary').textContent = 'Claude is reading your code. This can take a few seconds…';

    try {
      const res = await fetch('api/deep-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: combineForAi(sources), apiKey: userKey }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `server returned ${res.status}`);

      $('aiPanelStatus').textContent = 'done';
      $('aiSummary').textContent = data.summary || 'Analysis complete.';

      const aiFindings = (data.findings || []).map((f) => ({
        ruleId: 'ai',
        title: f.title || 'AI finding',
        severity: SEVERITY_ORDER.includes(f.severity) ? f.severity : 'info',
        file: 'AI review',
        line: f.line || 0,
        snippet: f.snippet || '',
        why: f.description || '',
        fix: f.recommendation || '',
        cwe: null,
        source: 'ai',
      }));

      // merge AI findings with the local ones already on screen
      renderResults(lastFindings.filter((f) => f.source === 'local').concat(aiFindings));
    } catch (e) {
      $('aiPanelStatus').textContent = 'error';
      $('aiSummary').textContent = `Couldn’t complete the AI scan: ${e.message}. The built-in results above are still valid.`;
    }
  }

  // ---- file handling --------------------------------------------------------
  function addFiles(fileObjs) {
    const arr = Array.from(fileObjs);
    let pending = arr.length;
    if (!pending) return;

    arr.forEach((file) => {
      if (looksBinary(file.name) || file.size > MAX_FILE_BYTES) {
        pending--;
        if (pending === 0) renderFileList();
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        // avoid dupes by name
        files = files.filter((f) => f.name !== file.name);
        files.push({ name: file.name, content: String(reader.result || '') });
        pending--;
        if (pending === 0) renderFileList();
      };
      reader.onerror = () => { pending--; if (pending === 0) renderFileList(); };
      reader.readAsText(file);
    });
  }

  function renderFileList() {
    fileListEl.hidden = files.length === 0;
    fileListEl.innerHTML = '';
    files.forEach((f, idx) => {
      const chip = document.createElement('span');
      chip.className = 'file-chip';
      chip.innerHTML = `<code>${escapeHtml(f.name)}</code>
        <button class="rm" title="Remove" aria-label="Remove ${escapeHtml(f.name)}">×</button>`;
      chip.querySelector('.rm').onclick = () => { files.splice(idx, 1); renderFileList(); };
      fileListEl.appendChild(chip);
    });
  }

  // ---- sample ---------------------------------------------------------------
  const SAMPLE_CODE = `# demo_app.py  — intentionally insecure example
import os, subprocess, pickle, hashlib
from flask import Flask, request

app = Flask(__name__)

API_KEY = "sk-ant-api03-EXAMPLEexampleexampleexample1234567890"
DB_PASSWORD = "hunter2_supersecret"

@app.route("/run")
def run():
    name = request.args.get("name")
    # building a shell command from user input
    os.system("echo Hello " + name)
    return "ok"

@app.route("/user")
def user():
    uid = request.args.get("id")
    # SQL built by string formatting
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return "ok"

def check(pw):
    return hashlib.md5(pw.encode()).hexdigest()   # weak hash

def load(data):
    return pickle.loads(data)                      # insecure deserialization

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)            # debug + bind-all
`;

  // ---- wire up events -------------------------------------------------------
  $('browseBtn').onclick = (e) => { e.stopPropagation(); fileInput.click(); };
  dropZone.onclick = () => fileInput.click();
  dropZone.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
  fileInput.onchange = () => { addFiles(fileInput.files); fileInput.value = ''; };

  ['dragenter', 'dragover'].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });

  $('scanBtn').onclick = runScan;
  $('clearBtn').onclick = () => {
    files = []; codeInput.value = ''; renderFileList();
    resultsEl.hidden = true; aiPanel.hidden = true; lastFindings = [];
  };
  $('sampleBtn').onclick = () => {
    codeInput.value = SAMPLE_CODE;
    codeInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };
  $('copyReportBtn').onclick = copyReport;

  // Ctrl/Cmd+Enter to scan
  codeInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runScan();
  });

  // AI key panel
  aiToggle.addEventListener('change', syncKeyPanel);
  apiKeyInput.addEventListener('input', () => { persistKey(); updateAiStatus(); });
  rememberKey.addEventListener('change', persistKey);
  $('forgetKeyBtn').onclick = () => {
    apiKeyInput.value = '';
    try { localStorage.removeItem(LS_KEY); } catch (e) { /* ignore */ }
    updateAiStatus();
    apiKeyInput.focus();
  };
  $('toggleKeyVis').onclick = () => {
    apiKeyInput.type = apiKeyInput.type === 'password' ? 'text' : 'password';
  };

  // init
  loadSavedKey();
  checkAiAvailability();
})();
