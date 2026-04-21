#!/usr/bin/env python3
"""
Minimal MCP Streamable HTTP mock server for security exploit testing.

Handles just enough of the MCP protocol to let the LiteLLM proxy
connect to it as a remote HTTP MCP server:
  - POST /mcp  initialize           → capabilities + Mcp-Session-Id header
  - POST /mcp  notifications/initialized → 202 (notification, no body)
  - POST /mcp  tools/list           → hardcoded echo_test tool
  - POST /mcp  tools/call           → echo the input message

Uses only stdlib (http.server, json, argparse, uuid).  No MCP SDK.

Usage:
    python tests/autofyn_audit_v2/mock_mcp_server.py --port 18100
"""

import argparse
import json
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

ECHO_TOOL = {
    "name": "echo_test",
    "description": "Echo test tool",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message": {"type": "string"},
        },
    },
}

INITIALIZE_RESULT = {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
        "name": "mock-mcp-server",
        "version": "0.1.0",
    },
    "capabilities": {
        "tools": {"listChanged": False},
    },
}


def _jsonrpc_response(request_id: object, result: object) -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }
    return json.dumps(payload).encode("utf-8")


class MCPHandler(BaseHTTPRequestHandler):
    """Handle POST /mcp for the mock MCP Streamable HTTP server."""

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        method = body.get("method", "")
        request_id = body.get("id")
        params = body.get("params", {})

        print(f"[mock-mcp] {method!r}  id={request_id}", flush=True)

        if method == "initialize":
            self._handle_initialize(request_id)
        elif method == "notifications/initialized":
            self._handle_notification()
        elif method == "tools/list":
            self._handle_tools_list(request_id)
        elif method == "tools/call":
            self._handle_tools_call(request_id, params)
        else:
            self._send_json(200, _jsonrpc_response(request_id, {}))

    def _handle_initialize(self, request_id: object) -> None:
        session_id = str(uuid.uuid4())
        body = _jsonrpc_response(request_id, INITIALIZE_RESULT)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _handle_notification(self) -> None:
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_tools_list(self, request_id: object) -> None:
        result = {"tools": [ECHO_TOOL]}
        self._send_json(200, _jsonrpc_response(request_id, result))

    def _handle_tools_call(self, request_id: object, params: dict) -> None:
        arguments = params.get("arguments", {})
        message = arguments.get("message", "")
        result = {
            "content": [
                {"type": "text", "text": f"ECHO: {message}"},
            ]
        }
        self._send_json(200, _jsonrpc_response(request_id, result))

    def _send_json(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
        print(f"[mock-mcp] {fmt % args}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal MCP mock server")
    parser.add_argument("--port", type=int, default=18100, help="TCP port (default 18100)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    server = HTTPServer((args.host, args.port), MCPHandler)
    print(f"[mock-mcp] Listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[mock-mcp] Shutting down", flush=True)
