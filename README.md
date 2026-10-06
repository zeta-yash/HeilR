---
title: Scam Autopsy
sdk: docker
app_port: 7860
---
# Scam Autopsy
Paste a suspicious message, email or link: get a risk rating, the exact red flags (highlighted), and next steps. Defence-only.

**Design:** a deterministic Python engine (`app/engine.py`) decides the rating and flags. The LLM (`app/llm.py`, LangChain + Mistral)
never sets the rating: it only classifies whether a brand is an *identity claim* or a *tool mention* (e.g. "Google Form"), and
rewrites findings in plain words. Inputs are redacted, output is Pydantic-validated, and any failure falls back to the engine.

## Run locally (VS Code)
```
uv sync
cp .env.example .env        # put MISTRAL_API_KEY in .env (optional: works without it)
uv run uvicorn app.main:app --reload
uv run pytest               # engine tests
```
Open http://127.0.0.1:8000 (API docs at /api/docs).

## Deploy on Hugging Face
Create a **Docker** Space, push this folder, add `MISTRAL_API_KEY` under Settings > Secrets. Port 7860 is preconfigured.

## Notes
- Front end is React loaded from a CDN (no Node build); it needs internet in the browser.
- Add each bug you find to `app/samples.py` as a regression case.
- The free tier may use your prompts for training unless you opt out in your Mistral account: that is why input is redacted.
