"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
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
        self._open_inputs: dict[str, str] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Lưu input và thời điểm bắt đầu theo request_id (hoặc user_id)."""
        # Dùng request_id (hoặc fallback sang user_id) làm khóa ghép cặp input <-> output
        key = request_id or user_id
        # Lưu mốc thời gian độ chính xác cao để tính latency khi có output
        self._open[key] = time.perf_counter()
        self._open_inputs[key] = text

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Lưu kết quả xử lý, lớp chặn (nếu có), độ trễ (ms) vào self.logs."""
        key = request_id or user_id
        # Lấy lại thời điểm bắt đầu và tính thời gian xử lý (mili-giây)
        start = self._open.pop(key, None)
        latency_ms = round((time.perf_counter() - start) * 1000, 2) if start is not None else 0.0
        input_text = self._open_inputs.pop(key, "")

        # Ghi 1 bản ghi audit (cắt preview tối đa 120 ký tự để log gọn)
        self.logs.append(
            {
                "timestamp": utc_now_iso(),
                "request_id": key,
                "user_id": user_id,
                "input_preview": input_text[:120],
                "output_preview": (text or "")[:120],
                "blocked": blocked,
                "layer": layer,
                "latency_ms": latency_ms,
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        # Tự tạo thư mục cha (outputs/) nếu chưa tồn tại rồi mới ghi JSON
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
