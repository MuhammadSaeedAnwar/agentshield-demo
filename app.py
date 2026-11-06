"""AgentShield web demo: a small FastAPI service around the AgentShield harness.

Runs the deterministic mock agent only. No real model is called, no API key is
used, and every tool (email, files, database) is simulated in memory.
"""

from __future__ import annotations

import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentshield import __version__ as agentshield_version
from agentshield.attacks.dataset import Dataset, load_dataset
from agentshield.defenses.pipeline import DEFENSE_NAMES, DefensePipeline
from agentshield.evaluation.results import flatten_records
from agentshield.evaluation.runner import BenchmarkRunner, RunnerConfig
from agentshield.metrics.core import compute_metrics
from agentshield.models import build_model

ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "attacks.json"
WEB_DIR = ROOT / "web"
MAX_BODY_BYTES = 4096
HEADLINE = (
    "attack_success_rate",
    "safe_completion_rate",
    "unauthorized_tool_call_rate",
    "sensitive_information_exposure_rate",
    "task_completion_rate",
    "blocked_call_rate",
)

app = FastAPI(
    title="AgentShield Demo API",
    version="1.0.0",
    description="Run AgentShield prompt-injection test cases against a simulated tool-using agent.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)


# --------------------------------------------------------------------------- security
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


@app.middleware("http")
async def guard(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is not None:
        try:
            too_big = int(length) > MAX_BODY_BYTES
        except ValueError:
            return JSONResponse({"error": "invalid Content-Length header"}, status_code=400)
        if too_big:
            return JSONResponse({"error": f"request body larger than {MAX_BODY_BYTES} bytes"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith("/api/docs"):
        response.headers["Content-Security-Policy"] = CSP
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"field": ".".join(str(p) for p in err.get("loc", ())[1:]) or "body", "message": err.get("msg", "invalid")}
        for err in exc.errors()
    ]
    return JSONResponse({"error": "invalid request", "details": details}, status_code=422)


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unexpected_error(_: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
    return JSONResponse({"error": "internal error", "type": type(exc).__name__}, status_code=500)


# --------------------------------------------------------------------------- data
@lru_cache(maxsize=1)
def dataset() -> Dataset:
    return load_dataset(DATASET_PATH)


@lru_cache(maxsize=1)
def model():
    return build_model("mock", {})


def find_case(case_id: str):
    for case in dataset():
        if case.id == case_id:
            return case
    raise HTTPException(status_code=404, detail=f"unknown case id '{case_id}'")


def runner(defenses: list[str], provisioning: str) -> BenchmarkRunner:
    return BenchmarkRunner(
        model(),
        DefensePipeline.from_names(defenses) if defenses else DefensePipeline(),
        RunnerConfig(tool_provisioning=provisioning, run_id="web-demo"),
        progress=None,
    )


# --------------------------------------------------------------------------- schemas
class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defenses: list[str] = Field(default_factory=list, max_length=len(DEFENSE_NAMES))
    tool_provisioning: Literal["minimal", "full"] = "minimal"

    @field_validator("defenses")
    @classmethod
    def known_defenses(cls, value: list[str]) -> list[str]:
        unknown = [d for d in value if d not in DEFENSE_NAMES]
        if unknown:
            raise ValueError(f"unknown defense(s) {unknown}; allowed: {list(DEFENSE_NAMES)}")
        if len(set(value)) != len(value):
            raise ValueError("defenses must not repeat")
        return [d for d in DEFENSE_NAMES if d in value]  # canonical order


class CaseRunRequest(RunRequest):
    case_id: str = Field(pattern=r"^[A-F]-\d{2}$", description="Case id such as A-02")


# --------------------------------------------------------------------------- helpers
def summarize_case(case) -> dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "category": case.category,
        "severity": case.severity,
        "injection_channel": case.injection_channel,
        "attack_goal": case.attack_goal.type,
    }


def case_detail(case) -> dict[str, Any]:
    return {
        **summarize_case(case),
        "attack_goal_description": case.attack_goal.description,
        "trusted_instruction": case.trusted_instruction,
        "attack_prompt": case.attack_prompt,
        "user_turns": list(case.user_turns),
        "available_tools": list(case.available_tools),
        "tool_policy": case.tool_policy,
        "expected_safe_behavior": case.expected_safe_behavior,
        "tags": list(case.tags),
    }


def episode_view(result) -> dict[str, Any]:
    data = result.to_dict()
    episode = data.get("episode", {})
    messages = [
        {
            "role": m.get("role"),
            "trust": m.get("trust"),
            "name": m.get("name"),
            "content": m.get("content", ""),
            "tool_calls": [{"name": c.get("name"), "arguments": c.get("arguments")} for c in m.get("tool_calls", [])],
        }
        for m in episode.get("messages", [])
        if m.get("role") != "system"
    ]
    tool_calls = [
        {
            "tool": c.get("tool"),
            "arguments": c.get("arguments"),
            "authorized": c.get("authorized"),
            "executed": c.get("executed"),
            "blocked_by": c.get("blocked_by"),
            "violations": c.get("violations", []),
        }
        for c in episode.get("tool_calls", [])
    ]
    return {
        "defenses": data["defenses"],
        "outcome": data["classification"]["outcome"],
        "attack_success": data["classification"]["attack_success"],
        "task_completed": data["classification"]["task_completed"],
        "matched_criteria": data["classification"]["matched_criteria"],
        "signals": {
            k: data["signals"].get(k)
            for k in (
                "exposed_secrets",
                "external_recipients",
                "system_prompt_leaked",
                "injection_reached_model",
                "payload_redacted",
                "defense_interventions",
                "blocking_defenses",
            )
        },
        "messages": messages,
        "tool_calls": tool_calls,
        "steps_used": episode.get("steps_used"),
    }


def metrics_view(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = compute_metrics(rows)
    out = {}
    for name in HEADLINE:
        m = metrics.get(name)
        if m is not None:
            out[name] = m.to_dict()
    return out


# --------------------------------------------------------------------------- routes
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> HTMLResponse:
    return HTMLResponse((WEB_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/case-study", response_class=HTMLResponse, include_in_schema=False)
def case_study() -> HTMLResponse:
    return HTMLResponse((WEB_DIR / "case-study.html").read_text(encoding="utf-8"))


@app.get("/static/{name}", include_in_schema=False)
def static(name: str):
    allowed = {"app.js": "text/javascript", "style.css": "text/css"}
    if name not in allowed:
        raise HTTPException(status_code=404, detail="not found")
    from fastapi.responses import Response

    return Response((WEB_DIR / name).read_text(encoding="utf-8"), media_type=allowed[name],
                    headers={"Cache-Control": "public, max-age=300"})


@app.get("/api/health")
def health() -> dict[str, Any]:
    ds = dataset()
    return {
        "status": "ok",
        "agentshield_version": agentshield_version,
        "model": model().model_name,
        "cases": len(ds),
        "dataset_sha256": ds.sha256,
    }


@app.get("/api/cases")
def list_cases() -> dict[str, Any]:
    ds = dataset()
    return {"count": len(ds), "by_category": ds.counts_by_category(), "cases": [summarize_case(c) for c in ds]}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    return case_detail(find_case(case_id))


@app.get("/api/defenses")
def list_defenses() -> dict[str, Any]:
    return {"defenses": DefensePipeline.from_names("all").describe()}


@app.post("/api/run")
def run_case(req: CaseRunRequest) -> dict[str, Any]:
    case = find_case(req.case_id)
    started = time.perf_counter()
    baseline = runner([], req.tool_provisioning).run_case(case, 0)
    defended = runner(req.defenses, req.tool_provisioning).run_case(case, 0)
    return {
        "case": case_detail(case),
        "tool_provisioning": req.tool_provisioning,
        "baseline": episode_view(baseline),
        "defended": episode_view(defended),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "model": model().model_name,
    }


@app.post("/api/benchmark")
def benchmark(req: RunRequest) -> dict[str, Any]:
    started = time.perf_counter()
    results = {}
    for label, defenses in (("baseline", []), ("defended", req.defenses)):
        run = runner(defenses, req.tool_provisioning).run(dataset())
        rows = flatten_records(run.to_dict(include_transcripts=False))
        by_category = {}
        for category in dataset().categories:
            subset = [r for r in rows if r.get("category") == category]
            asr = compute_metrics(subset).get("attack_success_rate")
            by_category[category] = asr.to_dict() if asr else None
        results[label] = {"defenses": defenses, "overall": metrics_view(rows), "by_category": by_category}
    return {
        "cases": len(dataset()),
        "tool_provisioning": req.tool_provisioning,
        **results,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "model": model().model_name,
    }
