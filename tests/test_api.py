"""API tests for the AgentShield web demo."""
import pytest
from fastapi.testclient import TestClient

import app as demo

client = TestClient(demo.app)


def test_health():
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["cases"] == 30
    assert body["model"].startswith("mock")


def test_cases_and_detail():
    body = client.get("/api/cases").json()
    assert body["count"] == 30 and len(body["by_category"]) == 6
    detail = client.get("/api/cases/A-02").json()
    assert detail["id"] == "A-02" and "attack_prompt" in detail


def test_unknown_case_404():
    r = client.get("/api/cases/Z-99")
    assert r.status_code == 404 and "error" in r.json()


def test_defenses_listed():
    names = [d["name"] for d in client.get("/api/defenses").json()["defenses"]]
    assert names == ["sanitization", "separation", "authorization", "confirmation", "output_validation"]


def test_run_baseline_vs_defended():
    r = client.post("/api/run", json={"case_id": "A-02", "defenses": ["authorization"]})
    assert r.status_code == 200
    body = r.json()
    assert body["baseline"]["attack_success"] is True
    assert body["defended"]["attack_success"] is False
    assert any(c["blocked_by"] for c in body["defended"]["tool_calls"])


def test_defense_order_is_canonical():
    r = client.post("/api/run", json={"case_id": "A-02", "defenses": ["authorization", "sanitization"]})
    assert r.json()["defended"]["defenses"] == ["sanitization", "authorization"]


@pytest.mark.parametrize(
    "payload",
    [
        {"case_id": "a-02"},
        {"case_id": "A-02; DROP"},
        {"case_id": "A-02", "defenses": ["evil"]},
        {"case_id": "A-02", "defenses": ["authorization", "authorization"]},
        {"case_id": "A-02", "tool_provisioning": "root"},
        {"case_id": "A-02", "extra": 1},
        {},
    ],
)
def test_invalid_run_requests_422(payload):
    r = client.post("/api/run", json=payload)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid request"


def test_valid_pattern_but_unknown_case_404():
    assert client.post("/api/run", json={"case_id": "F-99"}).status_code == 404


def test_malformed_json_422():
    r = client.post("/api/run", content=b"{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422


def test_body_size_limit():
    r = client.post("/api/run", content=b"x" * 5000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_benchmark_all_defenses():
    body = client.post("/api/benchmark", json={"defenses": list(demo.DEFENSE_NAMES)}).json()
    assert body["baseline"]["overall"]["attack_success_rate"]["numerator"] == 9
    assert body["defended"]["overall"]["attack_success_rate"]["numerator"] == 0
    assert body["defended"]["overall"]["task_completion_rate"]["numerator"] == 30


def test_security_headers_and_pages():
    for path in ("/", "/case-study", "/static/app.js", "/static/style.css"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_static_path_traversal_blocked():
    assert client.get("/static/..%2fapp.py").status_code == 404
    assert client.get("/static/app.py").status_code == 404


def test_frontend_never_uses_innerhtml():
    js = (demo.WEB_DIR / "app.js").read_text()
    assert "innerHTML" not in js.replace("never innerHTML", "")
