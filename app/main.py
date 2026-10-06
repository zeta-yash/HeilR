from dotenv import load_dotenv
load_dotenv()
from functools import lru_cache
from pathlib import Path
import csv, datetime as dt, threading
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import engine, llm
from .samples import S

app = FastAPI(title="Scam Autopsy", docs_url="/api/docs", openapi_url="/api/openapi.json")

class In(BaseModel):
    text: str = Field(min_length=1, max_length=6000)
    use_llm: bool = True
class Bulk(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=50)

@lru_cache(maxsize=256)
def run(text: str, use_llm: bool) -> engine.Result:
    r = engine.analyze(text)
    used = False
    if use_llm and llm.enabled():
        forced = frozenset(b for b, ex in r.ambiguous.items() if llm.classify_brand(b, ex) == "identity_claim")
        if forced: r = engine.analyze(text, forced); used = True
        s = llm.explain(r.level, r.scam_type, r.flags)
        if s: r.summary, used = s, True
    if not r.summary:   # deterministic fallback
        r.summary = (f"{len(r.flags)} warning sign(s) found, mainly: {r.flags[0].title.lower()}." if r.flags else "No strong warning signs were found. This is not a guarantee, so verify on the official site if money or logins are involved.")
    r.llm_used = used; r.ambiguous = {}
    return r

@app.post("/api/analyze", response_model=engine.Result)
def analyze(i: In): return run(i.text, i.use_llm)

@app.post("/api/bulk")
def bulk(b: Bulk):
    return [{"text": t[:160], "level": (r := run(t, False)).level, "score": r.score, "flags": [f.title for f in r.flags[:3]]} for t in b.texts]

@app.get("/api/samples")
def samples(): return [{"scam": bool(s), "text": t} for s, t in S]

@app.get("/api/eval")
def evaluate():
    rows = [(s, engine.analyze(t)) for s, t in S]
    miss = [{"text": t[:120], "level": r.level} for (s, t), (_, r) in zip(S, rows) if s and r.level == "low"]
    fa = [{"text": t[:120], "level": r.level} for (s, t), (_, r) in zip(S, rows) if not s and r.level != "low"]
    n = len(S); return {"total": n, "correct": n - len(miss) - len(fa), "missed_scams": miss, "false_alarms": fa, "note": "Engine only (LLM off). Samples were written by the developers."}

# ---- anonymous campus reports (CSV). Stores only: date, scam type, count. Never message text, names or devices. ----
REPORTS = Path(__file__).resolve().parent.parent / "data" / "reports.csv"
ALLOWED = {"Fake internship / fee", "Scholarship / KYC link", "Fake refund", "Prize or lottery", "Fake job offer",
           "OTP or credential theft", "Malicious app", "Suspicious link"}
_lock = threading.Lock()

class Report(BaseModel):
    scam_type: str = Field(max_length=40)

def _stats():
    tot, last = {}, ""
    with _lock:
        if REPORTS.exists():
            with REPORTS.open(newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    try: tot[row["scam_type"]] = tot.get(row["scam_type"], 0) + int(row["count"])
                    except (KeyError, ValueError): continue
                    last = max(last, row.get("date", ""))
    items = sorted(({"scam_type": k, "count": v} for k, v in tot.items()), key=lambda x: -x["count"])
    return {"total": sum(tot.values()), "types": items, "updated": last, "source": "data/reports.csv"}

@app.get("/api/stats")
def stats(): return _stats()

@app.post("/api/report")
def report(r: Report):
    if r.scam_type not in ALLOWED: raise HTTPException(400, "Unknown scam type")
    with _lock:
        REPORTS.parent.mkdir(exist_ok=True)
        new = not REPORTS.exists()
        with REPORTS.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new: w.writerow(["date", "scam_type", "count"])
            w.writerow([dt.date.today().isoformat(), r.scam_type, 1])
    return _stats()

@app.get("/api/reports.csv")
def reports_csv():
    if not REPORTS.exists(): raise HTTPException(404, "No reports yet")
    return FileResponse(REPORTS, media_type="text/csv", filename="reports.csv")

@app.get("/api/health")
def health(): return {"ok": True, "llm": llm.enabled()}

app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
