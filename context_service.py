# context_service.py — spaCy + RapidFuzz + Embeddings (Sentence-Transformers)
# Runs on 127.0.0.1:5055
from flask import Flask, request, jsonify
import spacy
from rapidfuzz import fuzz
from sentence_transformers import SentenceTransformer, util

app = Flask(__name__)

# -------- Models --------
nlp = spacy.load("en_core_web_sm")
model = SentenceTransformer("all-MiniLM-L6-v2")  

cfg = {
  projects: [
    "Atlas",
    "Project Atlas",
    "Jupiter",
    "Phoenix",
    "Nebula",
    "atlas-prod",
    "atlas-db"
  ],
  high_risk_terms: [
    "password",
    "passw0rd",
    "secret",
    "secrets",
    "token",
    "keys",
    "access key",
    "service account key",
    "master key",
    "vault key",
    "db password",
    "db creds",
    "credentials",
    "creds",
    "rotate"
  ],
  confidential: [
    "customer list",
    "client list",
    "PII",
    "financials",
    "payroll",
    "salary",
    "database",
    "db",
    "readme"
  ]
};

def any_fuzzy(text, candidates, t=85):
    """Return True if text fuzzy-matches any candidate above threshold t."""
    tl = text.lower()
    for c in candidates:
        if fuzz.partial_ratio(tl, c.lower()) >= t:
            return True
    return False

def sem_sim_any(text, candidates, thresh=0.62):
  
    if not text.strip() or not candidates:
        return False
    s_emb = model.encode([text], convert_to_tensor=True, normalize_embeddings=True)
    c_emb = model.encode(candidates, convert_to_tensor=True, normalize_embeddings=True)
    cos = util.cos_sim(s_emb, c_emb)[0]  # row vector
    max_sim = float(cos.max().cpu().item())
    return max_sim >= thresh

def score_line(line, cfg):
    s = line.strip()
    if not s:
        return None

    doc = nlp(s)
    ents = [e.text for e in doc.ents]  

    hitP = any(any_fuzzy(e, cfg["projects"]) for e in ents) \
        or any_fuzzy(s, cfg["projects"]) \
        or sem_sim_any(s, cfg["projects"], 0.60)

    hitH = any_fuzzy(s, cfg["high_risk_terms"]) or sem_sim_any(s, cfg["high_risk_terms"], 0.62)

    hitC = any_fuzzy(s, cfg["confidential"]) or sem_sim_any(s, cfg["confidential"], 0.62)

    score = (3 if hitP else 0) + (5 if hitH else 0) + (2 if hitC else 0)
    if score == 0:
        return None

    sev = "high" if score >= 7 else "med" if score >= 4 else "low"
    tags = []
    if hitP: tags.append("project")
    if hitH: tags.append("high-risk")
    if hitC: tags.append("confidential")

    return {"score": score, "sev": sev, "tags": tags}


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    text = data.get("text", "")
    cfg = data.get("config", DEFAULT_CFG)

    findings = []
    H = M = L = 0
    for i, line in enumerate(text.splitlines()):
        res = score_line(line, cfg)
        if res:
            res["line"] = i + 1
            res["text"] = line.strip()
            findings.append(res)
            if res["sev"] == "high": H += 1
            elif res["sev"] == "med": M += 1
            else: L += 1

    findings.sort(key=lambda x: (-x["score"], x["line"]))
    overall = round(100 * (1 * H + 1.5 * M + 0.5 * L) / max(1, H + M + L))
    return jsonify({"findings": findings, "totals": {"H": H, "M": M, "L": L}, "overall": overall})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055)
