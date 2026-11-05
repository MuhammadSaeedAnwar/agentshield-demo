# AgentShield Web Demo

Live, browser-based demo of [AgentShield](https://github.com/MuhammadSaeedAnwar/AgentShield): run prompt-injection attack cases against a simulated tool-using AI agent, with and without defenses, and see every tool call, policy violation and leaked secret.

- **Live demo:** LIVE_URL
- **Case study:** LIVE_URL/case-study
- **API docs:** LIVE_URL/api/docs

> The demo runs AgentShield's deterministic mock agent only. No real model is called, no API key is used, and email, files and databases are simulated in memory. Results describe the harness and the defenses, not any commercial LLM.

## Screenshots

| Attack vs defended | Full benchmark |
|---|---|
| ![Attack vs defended](docs/screenshots/03-rag-injection.png) | ![Benchmark](docs/screenshots/04-benchmark-all-defenses.png) |

| Case study | Mobile |
|---|---|
| ![Case study](docs/screenshots/05-case-study.png) | ![Mobile](docs/screenshots/06-mobile.png) |

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app:app --reload        # http://127.0.0.1:8000
pytest -q                       # 20 API tests
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Status, dataset hash, case count |
| GET | `/api/cases` | All 30 cases (id, title, category, severity, channel) |
| GET | `/api/cases/{id}` | One case: policy, payload, tools, expected safe behaviour |
| GET | `/api/defenses` | The five defenses and what they do |
| POST | `/api/run` | `{"case_id":"A-02","defenses":["authorization"],"tool_provisioning":"minimal"}`: runs the case with no defenses and with the chosen defenses, returns both traces |
| POST | `/api/benchmark` | `{"defenses":[...]}`: runs all 30 cases in both conditions, returns rates with 95% Wilson intervals, overall and per category |

## Security controls

- Strict request schemas: unknown fields rejected, defense names allowlisted, case ids must match `^[A-F]-\d{2}$`.
- 4 KB request body limit; consistent JSON errors (`422` validation, `404` unknown case, `413` too large).
- Security headers on every response: Content-Security-Policy (no inline scripts, no framing), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- Static files served from a fixed allowlist (no path traversal).
- The frontend renders all dataset text with `textContent`, never `innerHTML`, so attack payloads cannot execute in the browser (checked by a test).

## Layout

```
app.py              FastAPI app (API + pages)
agentshield/        AgentShield core package (standard library only)
data/attacks.json   30 attack cases
web/                index.html, case-study.html, app.js, style.css
tests/test_api.py   API, validation and security tests
```

Deployed on Vercel (Python runtime). MIT licensed. Author: Muhammad Saeed Anwar.
