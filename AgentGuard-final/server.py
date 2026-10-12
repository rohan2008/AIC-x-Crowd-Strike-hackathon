"""Dependency-free local server. Run: python3 server.py"""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import urlsplit
from agentguard.attacks import CASES
from agentguard.data import TICKET
from agentguard.evaluation import compare, evaluate
from agentguard.redteam import generate
from agentguard.supervisor import CONFIGURATIONS

WEB = Path(__file__).resolve().parent / "web"
RUN_LOCK = BoundedSemaphore(1)
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload, content_type="application/json"):
        data = json.dumps(payload).encode() if content_type == "application/json" else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get("Host") in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

    def do_GET(self):
        if not self.valid_host():
            return self.respond(403, {"error": "Local host required."})
        path = urlsplit(self.path).path
        if path == "/api/config":
            return self.respond(200, {"cases": CASES, "ticket": TICKET, "configurations": CONFIGURATIONS,
                                      "live_available": bool(os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL")),
                                      "model": os.getenv("OPENAI_MODEL", "Not configured")})
        if path in ASSETS:
            filename, mime = ASSETS[path]
            return self.respond(200, (WEB / filename).read_bytes(), mime)
        self.respond(404, {"error": "Not found."})

    def do_POST(self):
        origin = self.headers.get("Origin")
        if not self.valid_host() or (origin and origin not in (f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}")):
            return self.respond(403, {"error": "Same-origin local requests required."})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.respond(415, {"error": "Use application/json."})
        if self.path not in ("/api/compare", "/api/evaluate", "/api/generate"):
            return self.respond(404, {"error": "Not found."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4_500_000:
                raise ValueError("Request must be between 1 byte and 4.5 MB.")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Request must be a JSON object.")
            mode = payload.get("mode", "simulation")
            if mode not in ("simulation", "live"):
                raise ValueError("Unsupported mode.")
            body = payload.get("body", "")
            reviewer_fault = payload.get("reviewer_fault", False)
            if not isinstance(reviewer_fault, bool) or (reviewer_fault and (mode != "simulation" or self.path != "/api/compare")):
                raise ValueError("Reviewer fault injection is only available for simulation comparisons.")
            if self.path in ("/api/compare", "/api/generate") and (not isinstance(body, str) or not body.strip() or len(body) > 12000):
                raise ValueError("Ticket body must contain 1–12000 characters.")
            if mode == "live" and self.path in ("/api/compare", "/api/evaluate"):
                if self.path == "/api/compare":
                    has_images = isinstance(payload.get("images"), list) and bool(payload["images"])
                else:
                    custom_cases = payload.get("custom_cases", [])
                    has_images = isinstance(custom_cases, list) and any(isinstance(case, dict) and isinstance(case.get("images"), list) and case["images"] for case in custom_cases)
                if has_images and payload.get("image_consent") is not True:
                    raise ValueError("Confirm image sharing in the app before sending images to the live model.")
        except (ValueError, UnicodeError) as exc:
            return self.respond(400, {"error": str(exc)})
        if not RUN_LOCK.acquire(blocking=False):
            return self.respond(409, {"error": "A run is already in progress. Please wait for it to finish."})
        try:
            if self.path == "/api/compare":
                result = compare(body, mode, reviewer_fault, payload.get("images"))
            elif self.path == "/api/generate":
                result = generate(body, mode)
            else:
                result = evaluate(mode, payload.get("custom_cases"))
            self.respond(200, result)
        except (ValueError, RuntimeError) as exc:
            self.respond(400, {"error": str(exc)})
        except Exception:
            self.respond(500, {"error": "Unexpected server error. Check the local terminal."})
            raise
        finally:
            RUN_LOCK.release()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"AgentGuard running at http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
