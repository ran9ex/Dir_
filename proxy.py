"""
Dir' (درع) as a drop-in proxy for the OpenAI chat-completions API.

  python proxy.py --upstream https://api.openai.com/v1 --port 8787

Point any app at http://localhost:8787/v1 instead of the provider. Requests are masked and scanned,
replies are guarded and restored. Pass X-Dir-Session to keep separate users' tokens apart
(default: one session per Authorization header).

Prototype limits: no streaming (stream=true is refused), single-threaded, plain HTTP.
Put it behind TLS and authentication before any real use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from gateway import Gateway, GatewayConfig
from llm import OpenAICompatibleLLM


class _Handler(BaseHTTPRequestHandler):
    gateway: Gateway = None

    def _send(self, code: int, payload: dict, extra: dict | None = None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path.split("?")[0].rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            return self._send(404, {"error": {"message": "not found"}})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            messages = body["messages"]
            assert isinstance(messages, list) and all("role" in m and isinstance(m.get("content"), str) for m in messages)
        except Exception:
            return self._send(400, {"error": {"message": "invalid request: expected messages with string content"}})
        if body.get("stream"):
            return self._send(400, {"error": {"message": "streaming is not supported by this prototype"}})

        session = self.headers.get("X-Dir-Session") or hashlib.sha256(
            (self.headers.get("Authorization") or "anonymous").encode()).hexdigest()[:16]
        llm = self.gateway.llm
        if body.get("model") and hasattr(llm, "model"):
            llm.model = body["model"]
        res = self.gateway.run(messages, session=session)
        headers = {"X-Dir-Action": res.action, "X-Dir-Risk-Residual": res.risk.get("residual", 0)}
        if res.action == "error":
            return self._send(502, {"error": {"message": res.message_ar}}, headers)
        content = res.message_ar if res.action == "blocked" else res.final_reply
        finish = "content_filter" if res.action == "blocked" else "stop"
        self._send(200, {
            "id": "dir-" + res.event.get("id", "x"), "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "dir-proxy"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": finish}],
        }, headers)

    def log_message(self, *args):
        pass


def make_server(gateway: Gateway, host: str = "127.0.0.1", port: int = 8787) -> HTTPServer:
    handler = type("DirHandler", (_Handler,), {"gateway": gateway})
    return HTTPServer((host, port), handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=os.environ.get("DIR_LLM_BASE_URL", "https://api.openai.com/v1"))
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--trusted", nargs="*", default=[], help="domains allowed in model replies")
    a = ap.parse_args()
    gw = Gateway(OpenAICompatibleLLM(base_url=a.upstream), GatewayConfig(trusted_domains=tuple(a.trusted)))
    print(f"Dir' proxy on http://127.0.0.1:{a.port}/v1  ->  {a.upstream}")
    make_server(gw, port=a.port).serve_forever()
