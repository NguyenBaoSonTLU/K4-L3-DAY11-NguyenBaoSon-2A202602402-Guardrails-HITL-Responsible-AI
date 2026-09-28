"""Local browser dashboard for the VinBank guardrail lab.

Run from the repository root with ``uvicorn app:app --reload``.
The browser only receives model replies and policy decisions; provider keys stay
in the server process. Lab checks never call a model or perform a banking action.
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agents.agent import create_blue_agent  # noqa: E402
from agents.security_boundary import ActionRequest, authorize_action, contains_secret  # noqa: E402
from assignment.pipeline import (  # noqa: E402
    build_observability,
    build_production_plugins,
    is_egress_allowed,
)
from core.config import get_blue_model, get_openrouter_api_key  # noqa: E402
from core.utils import chat_with_agent  # noqa: E402
from guardrails.input_guardrails import detect_injection, topic_filter  # noqa: E402
from guardrails.output_guardrails import content_filter  # noqa: E402

app = FastAPI(title="VinBank Guardrail Studio", version="1.0.0", docs_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "web"), name="static")


class ChatRequest(BaseModel):
    session_id: str = Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    message: str = Field(min_length=1, max_length=4000)


class TextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=6000)


class ActionRequestBody(BaseModel):
    action: str = Field(min_length=1, max_length=80)
    destination: str = Field(min_length=1, max_length=500)
    payload: str = Field(default="", max_length=4000)
    approval_id: str | None = Field(default=None, max_length=80)
    reviewer_id: str | None = Field(default=None, max_length=80)


@dataclass
class SessionState:
    agent: Any
    runner: Any
    plugins: list[Any]
    audit: Any
    monitor: Any
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    sequence: int = 0


_sessions: dict[str, SessionState] = {}


def _session(session_id: str) -> SessionState:
    state = _sessions.get(session_id)
    if state is None:
        # Keep a bounded number of local sessions. No chat history is stored by
        # the model runner, and this cache only holds counters and audit events.
        if len(_sessions) >= 100:
            _sessions.pop(next(iter(_sessions)))
        plugins = build_production_plugins(use_llm_judge=False)
        agent, runner = create_blue_agent(plugins)
        audit, monitor = build_observability()
        state = SessionState(agent, runner, plugins, audit, monitor)
        _sessions[session_id] = state
    return state


def _step(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {
        "model": get_blue_model(),
        "provider": "OpenRouter",
        "key_configured": bool(get_openrouter_api_key()),
        "mode": "Live Blue agent",
    }


@app.get("/api/session/{session_id}")
def session_summary(session_id: str) -> dict:
    state = _sessions.get(session_id)
    return state.monitor.snapshot() if state else {
        "total_requests": 0,
        "blocked_requests": 0,
        "block_rate": 0.0,
        "rate_limit_hits": 0,
        "judge_checks": 0,
        "judge_fails": 0,
        "judge_fail_rate": 0.0,
        "alerts": [],
    }


@app.post("/api/chat")
async def chat(request: ChatRequest) -> dict:
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Enter a banking question.")

    state = _session(request.session_id)
    async with state.lock:
        state.sequence += 1
        request_id = f"ui-{state.sequence}"
        state.audit.record_input(user_id=request.session_id, text=message,
                                 request_id=request_id)
        state.monitor.total_requests += 1

        rate, input_guard, output_guard = state.plugins
        rate_before = rate.blocked_count
        input_before = input_guard.blocked_count
        output_before = output_guard.blocked_count
        redact_before = output_guard.redacted_count
        output_total_before = output_guard.total_count

        try:
            # The runner invokes rate, input, model, and output callbacks in order.
            # OpenAIRunner uses a synchronous SDK client; keep the UI responsive.
            reply, _ = await asyncio.to_thread(
                lambda: asyncio.run(chat_with_agent(state.agent, state.runner, message))
            )
        except Exception as exc:
            state.audit.record_output(
                user_id=request.session_id,
                text="Model request failed",
                blocked=False,
                layer="service_error",
                request_id=request_id,
            )
            # Do not expose provider diagnostics or credentials to the browser.
            raise HTTPException(
                status_code=503,
                detail=f"Model unavailable ({type(exc).__name__}). Check the server connection and provider key.",
            ) from exc

        rate_block = rate.blocked_count > rate_before
        input_block = input_guard.blocked_count > input_before
        output_block = output_guard.blocked_count > output_before
        redacted = output_guard.redacted_count > redact_before
        model_ran = output_guard.total_count > output_total_before
        egress_block = contains_secret(reply)
        if egress_block:
            reply = "I can't share internal system details. Please ask a banking question."

        blocked = rate_block or input_block or output_block or egress_block
        layer = (
            "rate_limiter" if rate_block else
            "input_guardrail" if input_block else
            "output_guardrail" if output_block or redacted else
            "reply_egress" if egress_block else None
        )
        if egress_block:
            layer = "reply_egress"
        if blocked:
            state.monitor.blocked_requests += 1
        if rate_block:
            state.monitor.rate_limit_hits += 1

        state.audit.record_output(
            user_id=request.session_id, text=reply, blocked=blocked,
            layer=layer, request_id=request_id,
        )
        state.monitor.check_metrics()

        trace = [
            _step("Rate limiter", "blocked" if rate_block else "passed",
                  "Request quota exceeded" if rate_block else "Within session quota"),
            _step("Input guardrails", "skipped" if rate_block else
                  "blocked" if input_block else "passed",
                  "Injection or topic rule" if input_block else
                  "Not reached" if rate_block else "Banking input accepted"),
            _step("Blue model", "completed" if model_ran else "skipped",
                  "OpenRouter response received" if model_ran else "No model call"),
            _step("Output guardrails", "blocked" if output_block else
                  "redacted" if redacted else "passed" if model_ran else "skipped",
                  "Sensitive output removed" if output_block or redacted else
                  "No sensitive output found" if model_ran else "Not reached"),
            _step("Reply / egress", "blocked" if egress_block else
                  "passed" if model_ran else "skipped",
                  "Protected value withheld" if egress_block else
                  "Reply cleared for display" if model_ran else "Not reached"),
        ]
        return {
            "reply": reply,
            "blocked": blocked,
            "redacted": redacted,
            "layer": layer,
            "trace": trace,
            "metrics": state.monitor.snapshot(),
        }


@app.post("/api/lab/input")
def inspect_input(request: TextRequest) -> dict:
    injection = detect_injection(request.text)
    topic = topic_filter(request.text)
    return {
        "decision": "BLOCK" if "BLOCK" in (injection, topic) else "ALLOW",
        "injection": injection,
        "topic": topic,
        "reason": "Prompt injection detected" if injection == "BLOCK" else
                  "Outside supported banking topics" if topic == "BLOCK" else
                  "Banking question accepted",
    }


@app.post("/api/lab/output")
def inspect_output(request: TextRequest) -> dict:
    filtered = content_filter(request.text)
    result = filtered["redacted"]
    protected_value = contains_secret(result)
    if protected_value:
        result = "[BLOCKED: protected internal value]"
    return {
        "safe": filtered["safe"] and not protected_value,
        "redacted": result,
        "issues": filtered["issues"] + (["protected value"] if protected_value else []),
    }


@app.post("/api/lab/action")
def inspect_action(request: ActionRequestBody) -> dict:
    egress_allowed = is_egress_allowed(request.destination, request.payload)
    decision = authorize_action(ActionRequest(
        action=request.action,
        destination=request.destination,
        payload=request.payload,
        approval_id=request.approval_id or None,
        reviewer_id=request.reviewer_id or None,
    ))
    allowed = egress_allowed and decision.allowed
    return {
        "allowed": allowed,
        "requires_human": decision.requires_human,
        "reason": decision.reason if egress_allowed else
                  "Destination or payload rejected by egress policy",
        "egress_allowed": egress_allowed,
    }


def _load_evidence(name: str) -> dict | None:
    path = ROOT / "outputs" / name
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _rows(data: dict | None, key: str) -> list[dict]:
    values = data.get(key) if data else None
    return [row for row in values if isinstance(row, dict)] if isinstance(values, list) else []


@app.get("/api/evidence")
def evidence() -> dict:
    defense = _load_evidence("results.json")
    attack = _load_evidence("attack_results.json")
    defense_valid = None
    if defense is not None:
        try:
            schema = json.loads((ROOT / "schemas" / "results.schema.json").read_text(encoding="utf-8"))
            defense_valid = jsonschema.Draft202012Validator(schema).is_valid(defense)
        except (OSError, ValueError, jsonschema.SchemaError):
            defense_valid = False
    safe = _rows(defense, "safe_queries")
    probes = _rows(defense, "attack_queries")
    rate = defense.get("rate_limit", {}) if defense else {}
    if not isinstance(rate, dict):
        rate = {}
    unsafe = _rows(attack, "unsafe_attacks")
    guards = _rows(attack, "guards_attacks")
    return {
        "defense_available": defense is not None,
        "defense_valid": defense_valid,
        "attack_available": attack is not None,
        "safe_passed": sum(not row.get("blocked", False) for row in safe),
        "safe_total": len(safe),
        "attacks_blocked": sum(bool(row.get("blocked")) for row in probes),
        "attacks_total": len(probes),
        "rate_passed": rate.get("passed", 0),
        "rate_blocked": rate.get("blocked", 0),
        "red_leaks": sum(bool(row.get("leaked")) for row in unsafe),
        "red_total": len(unsafe),
        "advance_blocks": sum(bool(row.get("blocked")) for row in guards),
        "advance_total": len(guards),
    }
