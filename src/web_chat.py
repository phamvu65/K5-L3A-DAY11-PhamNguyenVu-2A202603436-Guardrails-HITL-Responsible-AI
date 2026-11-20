"""Local Blue chatbot UI. Run: python -X utf8 src/web_chat.py"""
from __future__ import annotations

import argparse
import asyncio
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agents.agent import create_blue_agent
from assignment.pipeline import build_production_plugins
from core.utils import chat_with_agent


PAGE = Path(__file__).parent / "web" / "index.html"
MAX_MESSAGE_LENGTH = 4000


class ChatService:
    """Reuse Blue's guardrails and rate limiter across local UI requests."""

    def __init__(self):
        self.plugins = build_production_plugins()
        self.agent, self.runner = create_blue_agent(self.plugins)
        self.runner.client_kwargs.update(timeout=30, max_retries=1)

    async def reply(self, message: str) -> dict:
        rate, input_guard, output_guard = self.plugins
        before = (rate.blocked_count, input_guard.blocked_count,
                  output_guard.blocked_count, output_guard.redacted_count)
        text, _ = await chat_with_agent(self.agent, self.runner, message)
        after = (rate.blocked_count, input_guard.blocked_count,
                 output_guard.blocked_count, output_guard.redacted_count)
        status = "answered"
        for index, label in enumerate(("rate_limit", "input_blocked", "output_blocked", "redacted")):
            if after[index] > before[index]:
                status = label
                break
        return {"reply": text or "Chưa nhận được câu trả lời. Vui lòng thử lại.", "status": status}


def make_handler(service: ChatService):
    class Handler(BaseHTTPRequestHandler):
        def send_data(self, status, data, content_type="application/json; charset=utf-8"):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8") if isinstance(data, dict) else data
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                self.send_data(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/health":
                self.send_data(200, {"ok": True})
            else:
                self.send_data(404, {"error": "Không tìm thấy trang."})

        def do_POST(self):
            if self.path != "/api/chat":
                self.send_data(404, {"error": "Không tìm thấy API."})
                return
            # Only same-origin browser requests may spend the local API quota.
            origin = self.headers.get("Origin")
            allowed_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if self.headers.get("Host") not in allowed_hosts:
                self.send_data(403, {"error": "Máy chủ yêu cầu không hợp lệ."})
                return
            expected = f"http://{self.headers.get('Host')}"
            if origin and origin != expected:
                self.send_data(403, {"error": "Nguồn yêu cầu không hợp lệ."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 24000:
                    raise ValueError
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                message = data.get("message") if isinstance(data, dict) else None
                if not isinstance(message, str) or not message.strip() or len(message) > MAX_MESSAGE_LENGTH:
                    raise ValueError
            except (ValueError, UnicodeError):
                self.send_data(400, {"error": "Nhập câu hỏi từ 1 đến 4.000 ký tự."})
                return
            try:
                result = asyncio.run(service.reply(message.strip()))
            except Exception as exc:
                # Never expose provider errors, credentials or internal prompts.
                status = getattr(exc, "status_code", None)
                self.send_data(503, {"error": (
                    "Dịch vụ AI đang giới hạn lượt gọi. Vui lòng thử lại sau."
                    if status == 429 else
                    "Chưa thể kết nối dịch vụ AI. Kiểm tra cấu hình API trên máy chủ rồi thử lại."
                )})
                return
            self.send_data(200, result)

        def log_message(self, format, *args):
            # Do not log chat messages or headers.
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description="VinBank Blue local chatbot")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    service = ChatService()
    server = HTTPServer(("127.0.0.1", args.port), make_handler(service))
    server.timeout = 60
    print(f"VinBank chat: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
