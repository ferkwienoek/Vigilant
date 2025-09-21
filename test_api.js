// test_api.js

async function runTest() {
  const badCode = `
// CVE mention
// CVE-2021-44228

const name = req.body.name;
const query = "SELECT * FROM users WHERE name = '" + name + "'";
db.query(query);

eval(req.query.payload);

document.write("<img src=x onerror=alert('pwn')>");
const API_KEY = "12345-SECRET";
`;

  console.log('Posting code to /api/scan ...');
  const r = await fetch('http://localhost:3000/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: badCode })
  });
  const j = await r.json();
  console.log('Response:', JSON.stringify(j, null, 2));

  const types = j.findings.map(f => f.ruleId);
  const expected = ['sql_concat', 'exec_input', 'xss_dom', 'hardcoded_secret', 'cve-mention'];
  const missing = expected.filter(e => !types.includes(e));
  if (missing.length === 0) {
    console.log(' All expected findings present:', expected);
  } else {
    console.warn(' Missing expected findings:', missing);
  }
}

runTest().catch(err => { console.error('Test failed:', err); process.exit(1); });
