
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const https = require('https');
const express = require('express');
const util = require('util');
const { execFile } = require('child_process');
const execFileP = util.promisify(execFile);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (_req, res) => res.json({ ok: true }));


function httpJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const lib = u.protocol === 'http:' ? http : https;
      const opts = {
        method,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + (u.search || ''),
        headers: { 'Content-Type': 'application/json', ...headers },
      };
      const req = lib.request(opts, (res) => {
        let data = '';
        res.on('data', (d) => (data += d));
        res.on('end', () => {
          if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          try { resolve(JSON.parse(data || '{}')); } catch { resolve({ raw: data }); }
        });
      });
      req.on('error', reject);
      if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
      req.end();
    } catch (e) { reject(e); }
  });
}

function scoreFinding(f) {
  const t = (f.title || '').toLowerCase();
  const m = (f.message || '').toLowerCase();
  const s = (f.ruleId || '').toLowerCase();

  // Critical  5
  if (t.includes('sql') || m.includes('sqli') || s.includes('sqli')) return 5;
  if (t.includes('eval') || m.includes('eval(') || m.includes('exec(')) return 5;
  if (t.includes('command injection') || m.includes('command injection')) return 5;
  if (t.includes('deserial') || m.includes('pickle') || m.includes('objectinputstream')) return 5;

  // High 4
  if (t.includes('secret') || m.includes('hardcoded') || m.includes('password') || m.includes('apikey') || m.includes('aws_secret')) return 4;
  if (t.includes('ssrf') || t.includes('path traversal') || t.includes('rce')) return 4;

  // Med  3
  if (t.includes('xss') || m.includes('innerhtml') || m.includes('document.write') || m.includes('dom')) return 3;
  if (m.includes('weak crypto') || m.includes('md5') || m.includes('sha1')) return 3;

  // Default low 2
  return 2;
}

// CVSS helpers 
function cvssLabel(score) {
  if (score == null) return 'N/A';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >  0.0) return 'Low';
  return 'None';
}

function approxCvssForFinding(f) {
  const t = (f.title||'').toLowerCase();
  const m = (f.message||'').toLowerCase();
  const r = (f.ruleId||'').toLowerCase();
  const txt = `${t} ${m} ${r}`;

  // Critical classes
  if (/\bsql\b|sqli/.test(txt)) return 9.1;                 // SQL Injection
  if (/command injection|rce\b/.test(txt)) return 9.8;      // Command/RCE
  if (/deserial|pickle|objectinputstream/.test(txt)) return 9.0; // Insecure deserialization

  // High
  if (/ssrf|path traversal|directory traversal/.test(txt)) return 8.2;
  if (/hardcoded|secret|password|apikey|aws_secret/.test(txt)) return 7.5;

  // Medium
  if (/xss|innerhtml|document\.write|dom/i.test(txt)) return 6.1;
  if (/weak crypto|md5|sha1/.test(txt)) return 5.3;

  // Low / informational
  return 3.1;
}

function bucket(points) {
  if (points >= 5) return 'high';
  if (points >= 3) return 'med';
  return 'low';
}
function summarizeFindings(findings) {
  let H = 0, M = 0, L = 0;

  const enriched = (findings || []).map((f) => {
    const pts = typeof f.score === 'number' ? f.score : scoreFinding(f);
    const sev = f.severity || bucket(pts);

    // count H/M/L
    if (sev === 'high') H++; else if (sev === 'med') M++; else L++;

    //  CVSS guess
    const cvss = typeof f.cvss === 'number' ? f.cvss : approxCvssForFinding(f);

    return { ...f, score: pts, severity: sev, cvss, cvss_label: cvssLabel(cvss) };
  })

  // overall 0–100
  const overall = Math.round(
    100 * (1.75 * H + 0.5 * M + 0.2 * L) / Math.max(1, H + M + L)
  );

  // Overall CVSS (0–10): weighted by H/M/L
  const overallCvss = parseFloat((
    (H * 8.8 + M * 6.0 + L * 3.0) / Math.max(1, H + M + L)
  ).toFixed(1));

  return { enriched, counts: { high: H, med: M, low: L }, overall, overallCvss };
}

function dedupeFindings(arr) {
  const seen = new Set(); const out = [];
  for (const f of arr || []) {
    const key = `${f.ruleId || f.title || ''}::${f.line || ''}::${(f.snippet || '').slice(0, 80)}`;
    if (!seen.has(key)) { seen.add(key); out.push(f); }
  }
  return out;
}

/* ---- Semgrep runner (CLI) ----
   Requires semgrep installed on system/venv.
   If not on PATH, set process.env.SEMGREP_PATH to the binary. */
async function runSemgrepOnCode(code, ext = '.js') {
  const fname = path.join(os.tmpdir(), 'vigilant_' + Date.now() + ext);
  fs.writeFileSync(fname, code, 'utf8');
  try {
    const semgrepBin = process.env.SEMGREP_PATH || 'semgrep';
    const confPath = path.resolve(process.cwd(), '.semgrep.yml');
    const confArg = fs.existsSync(confPath) ? ['--config', confPath] : ['--config', 'auto'];
    const { stdout } = await execFileP(semgrepBin, ['--json', ...confArg, fname], { timeout: 30000 });
    const parsed = JSON.parse(stdout || '{}');
    const results = (parsed.results || []).map((r) => {
      const ruleId = r.check_id || r.rule_id || (r.rule && r.rule.id) || 'semgrep';
      const message = (r.extra && r.extra.message) || (r.extra && r.extra.metadata && r.extra.metadata.message) || r.msg || '';
      let line = null;
      if (r.start && typeof r.start.line === 'number') line = r.start.line;
      else if (r.extra && r.extra.lines && typeof r.extra.lines.start === 'number') line = r.extra.lines.start;
      const snippet = (r.extra && r.extra.lines && r.extra.lines.text) || (r.extra && r.extra.metadata && r.extra.metadata.snippet) || '';
      return { ruleId, title: ruleId, message: message || '', line, snippet: String(snippet).slice(0, 1000), source: 'semgrep' };
    });
    return { findings: results, raw: parsed };
  } catch (err) {
    return { error: err && err.message ? err.message : String(err) };
  } finally { try { fs.unlinkSync(fname); } catch {} }
}

/* ---- simple heuristics */
function runHeuristics(code) {
  const out = []; const lines = (code || '').split('\n');
  lines.forEach((ln, idx) => {
    if (/["'`].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*["'`]\s*\+\s*.+/i.test(ln)) {
      out.push({ title: 'SQL concatenation', message: 'Possible SQL injection via string concatenation', line: idx + 1, snippet: ln.trim(), source: 'heuristic' });
    }
    if (/\beval\(|\bexec\(|document\.write\(|innerHTML\s*=|pickle\.loads\(/i.test(ln)) {
      out.push({ title: 'Unsafe code pattern', message: ln.trim().slice(0, 400), line: idx + 1, snippet: ln.trim(), source: 'heuristic' });
    }
    if (/api[_-]?key|apikey|secret|aws[_-]?secret|awsAccessKey|password\s*[:=]/i.test(ln)) {
      out.push({ title: 'Possible secret/API key', message: 'Hardcoded secret or API key pattern', line: idx + 1, snippet: ln.trim(), source: 'heuristic' });
    }
    if (/\b(exec|spawn|system)\(/i.test(ln) && /child_process|exec/.test(code)) {
      out.push({ title: 'Command exec', message: 'Possible command execution', line: idx + 1, snippet: ln.trim(), source: 'heuristic' });
    }
  });
  return out;
}

/* -------------- Endpoints --------------------------- */

/** Code: Semgrep only */
app.post('/api/semgrep-scan', async (req, res) => {
  try {
    const { code = '', ext = '.js' } = req.body || {};
    if (!code) return res.status(400).json({ error: 'no code provided' });

    const result = await runSemgrepOnCode(code, ext);
    if (result.error) return res.status(500).json({ error: result.error });

    const { enriched, counts, overall } = summarizeFindings(result.findings || []);
    return res.json({ findings: enriched, counts, overall, raw: result.raw });
  } catch (err) {
    console.error('semgrep-scan error', err);
    res.status(500).json({ error: err.message || 'semgrep scan failed' });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const { code = '', lang = '' } = req.body || {};
    if (!code) return res.status(400).json({ error: 'no code provided' });

    let findings = runHeuristics(code);

    const extMap = { js: '.js', javascript: '.js', py: '.py', python: '.py', java: '.java', yml: '.yml', yaml: '.yml', json: '.json', html: '.js' };
    const ext = extMap[(lang || '').toLowerCase()] || '.js';
    let sem = null;
    try { sem = await runSemgrepOnCode(code, ext); } catch (e) { sem = { error: e.message || String(e) }; }
    if (sem && !sem.error && sem.findings && sem.findings.length) findings.push(...sem.findings);
    else if (sem && sem.error) console.warn('Semgrep not used:', sem.error);

    //  summarize
    const merged = dedupeFindings(findings);
    const { enriched, counts, overall } = summarizeFindings(merged);
    res.json({ findings: enriched, counts, overall });
  } catch (err) {
    console.error('scan error', err);
    res.status(500).json({ error: err.message || 'scan failed' });
  }
});

/** Context: try Python embeddings microservice first, else fallback heuristics */
app.post('/api/context-scan', async (req, res) => {
  try {
    const { text = '', config = {} } = req.body || {};
    if (!text) return res.json({ findings: [], overall: 0 });

    // Try Python svc (http://127.0.0.1:5055/scan)
    let svc;
    try { svc = await httpJson('http://127.0.0.1:5055/scan', { method: 'POST', body: { text, config } }); }
    catch (_) { svc = null; }

    if (svc && svc.findings) {
      const H = (svc.findings || []).filter((f) => f.sev === 'high').length;
      const M = (svc.findings || []).filter((f) => f.sev === 'med').length;
      const L = (svc.findings || []).filter((f) => f.sev === 'low').length;
      const overall = typeof svc.overall === 'number'
        ? svc.overall
        : Math.round(100 * (6 * H + 0.25 * M + 0.05 * L) / Math.max(1, H + M + L));
      return res.json({ findings: svc.findings, overall });
    }

    // ----- Fallback: Node heuristics -----
    const cfg = {
      projects: config.projects || ['Atlas', 'Phoenix', 'Nebula', 'atlas-deploy', 'atlas-prod', 'atlas-db'],
      high_risk_terms: config.high_risk_terms || [
        'password','secret','token','keys','access key','service account key','master key',
        'prod db','production db','db password','db creds','credentials','creds','rotate'
      ],
      confidential: config.confidential || ['customer list','customer data','client list','PII','balances','financials','salary','SSN'],
    };

    const lines = (text || '').split(/\r?\n/);
    const findings = [];
    lines.forEach((ln, i) => {
      const L = ln.toLowerCase();
      let score = 0; const tags = [];
      const hasProj = cfg.projects.some((p) => L.includes(p.toLowerCase()));
      const hasRisk = cfg.high_risk_terms.some((t) => L.includes(t.toLowerCase()));
      const hasConf = cfg.confidential.some((t) => L.includes(t.toLowerCase()));
      if (hasProj) { score += 3; tags.push('project'); }
      if (hasRisk) { score += 3; tags.push('highrisk'); }
      if (hasConf) { score += 2; tags.push('confidential'); }
      if (/\b[A-Za-z0-9+/]{16,}={0,2}\b/.test(ln) || /\b[0-9a-f]{32,}\b/i.test(ln)) { score += 2; tags.push('blob'); }
      if (hasProj && hasRisk && score < 7) score = 7;
      if (score > 0) {
        const sev = score >= 7 ? 'high' : score >= 4 ? 'med' : 'low';
        findings.push({ line: i + 1, sev, score, text: ln, tags });
      }
    });

    const H = findings.filter((f) => f.sev === 'high').length;
    const M = findings.filter((f) => f.sev === 'med').length;
    const Lw = findings.filter((f) => f.sev === 'low').length;
    const overall = Math.round(100 * (1.4 * H + 0.75 * M + 0.5 * Lw) / Math.max(1, H + M + Lw));
    res.json({ findings, overall });
  } catch (err) {
    console.error('context-scan error', err);
    res.status(500).json({ error: err.message || 'context scan failed' });
  }
});

/** CVE: proxy to cve.circl.lu */
app.get('/api/cve/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return res.status(400).json({ error: 'Invalid CVE id' });

    const j = await httpJson(`https://cve.circl.lu/api/cve/${encodeURIComponent(id)}`);
    const summary = j.summary || (j.cve && j.cve.description && j.cve.description.description_data && j.cve.description.description_data[0] && j.cve.description.description_data[0].value) || '';
    let cvss = null;
    if (typeof j.cvss === 'number') cvss = j.cvss;
    else if (j.impact && j.impact.baseMetricV3 && j.impact.baseMetricV3.cvssV3 && j.impact.baseMetricV3.cvssV3.baseScore) cvss = j.impact.baseMetricV3.cvssV3.baseScore;
      res.json({
      cveId: id,
      cvss,
      cvss_label: cvssLabel(typeof cvss === 'number' ? cvss : null),
      summary
    });

  } catch (err) {
    console.error('cve error', err);
    res.status(500).json({ error: 'CVE lookup failed' });
  }
});

/* ============ Start ============ */
app.listen(PORT, () => {
  console.log(`Vigilant server running on http://localhost:${PORT}`);
  console.log(`Static site: ${path.join(__dirname, 'public')}`);
  console.log(`If Semgrep isn't detected, set SEMGREP_PATH or ensure it's on PATH.`);
});
