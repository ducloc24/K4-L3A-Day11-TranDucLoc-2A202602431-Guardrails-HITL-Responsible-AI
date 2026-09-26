"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time
import json
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
        self._open: dict[str, float] = {}

    @staticmethod
    def _request_key(user_id: str, request_id: str | None) -> str:
        return request_id or user_id
    
    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = self._request_key(user_id, request_id)
        self._open[key] = {
            "started_at": time.perf_counter(),
            "timestamp": utc_now_iso(),
            "input": text,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = self._request_key(user_id, request_id)
        opened = self._open.pop(key, {})
        started_at = opened.get("started_at")

        latency_ms = (
            round((time.perf_counter() - started_at) * 1000, 2)
            if started_at is not None
            else None
        )

        self.logs.append(
            {
                "timestamp": opened.get("timestamp", utc_now_iso()),
                "request_id": request_id,
                "user_id": user_id,
                "input": opened.get("input", ""),
                "response": text,
                "blocked": blocked,
                "layer": layer,
                "latency_ms": latency_ms,
            }
        )
    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
