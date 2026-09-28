"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, deque[dict]] = defaultdict(deque)

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Keep the request's input and start time until its output arrives."""
        self._open[request_id or user_id].append({
            "input": text,
            "started_at": utc_now_iso(),
            "start_monotonic": time.monotonic(),
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish one request and retain its decision and elapsed time."""
        key = request_id or user_id
        pending = self._open.get(key)
        started = pending.popleft() if pending else None
        if pending is not None and not pending:
            del self._open[key]
        record = {
            "user_id": user_id,
            "request_id": request_id,
            "input": started["input"] if started else None,
            "output": text,
            "started_at": started["started_at"] if started else None,
            "finished_at": utc_now_iso(),
            "latency_ms": round(
                max(0.0, (time.monotonic() - started["start_monotonic"]) * 1000), 3
            ) if started else None,
            "blocked": blocked,
            "layer": layer,
        }
        self.logs.append(record)
        return record

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
