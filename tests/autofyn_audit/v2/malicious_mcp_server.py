#!/usr/bin/env python3
"""
Malicious MCP Streamable HTTP server for RCE security exploit testing.

Demonstrates that a command-execution MCP server registered with `allow_all_keys: true`
enables full RCE on the proxy host when the MCP auth bypass (Finding A-1/A-2) is used.

Exposes three dangerous-but-realistic tools:
  - run_command    — executes arbitrary shell commands via subprocess
  - read_file      — reads arbitrary files from the filesystem
  - list_directory — lists directory contents via os.listdir

Many legitimate MCP servers (filesystem MCP, terminal MCP, code-interpreter MCP) have
exactly these capabilities. This server just doesn't restrict paths or commands.

Uses only stdlib (http.server, json, argparse, uuid, subprocess, os).  No MCP SDK.

Usage:
    python tests/autofyn_audit_v2/malicious_mcp_server.py --port 18101
"""

import argparse
import json
import os
import subprocess
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {
        "name": "run_command",
        "description": "Execute a shell command on the host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the file"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_directory",
        "description": "List the contents of a directory",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the directory"},
            },
            "required": ["path"],
        },
    },
]

INITIALIZE_RESULT = {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
        "name": "malicious-mcp-server",
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


def _tool_text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _run_command(command: str) -> str:
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=30,
            text=True,
        )
        output = proc.stdout
        if proc.stderr:
            output += f"\n[stderr]\n{proc.stderr}"
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after 30 seconds: {command!r}"
    except Exception as exc:
        return f"ERROR: {exc}"


def _read_file(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return f"ERROR: {exc}"


def _list_directory(path: str) -> str:
    try:
        entries = os.listdir(path)
        return "\n".join(entries) if entries else "(empty directory)"
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return f"ERROR: {exc}"


class MaliciousMCPHandler(BaseHTTPRequestHandler):
    """Handle POST /mcp for the malicious MCP Streamable HTTP server."""

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

        print(f"[malicious-mcp] {method!r}  id={request_id}", flush=True)

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
        result = {"tools": TOOLS}
        self._send_json(200, _jsonrpc_response(request_id, result))

    def _handle_tools_call(self, request_id: object, params: dict) -> None:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        print(f"[malicious-mcp] tool_call name={tool_name!r} args={arguments}", flush=True)

        if tool_name == "run_command":
            command = arguments.get("command", "")
            output = _run_command(command)
            result = _tool_text_result(output)
        elif tool_name == "read_file":
            path = arguments.get("path", "")
            contents = _read_file(path)
            result = _tool_text_result(contents)
        elif tool_name == "list_directory":
            path = arguments.get("path", "")
            listing = _list_directory(path)
            result = _tool_text_result(listing)
        else:
            result = _tool_text_result(f"ERROR: unknown tool {tool_name!r}")

        self._send_json(200, _jsonrpc_response(request_id, result))

    def _send_json(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
        print(f"[malicious-mcp] {fmt % args}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Malicious MCP server for RCE exploit testing")
    parser.add_argument("--port", type=int, default=18101, help="TCP port (default 18101)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    server = HTTPServer((args.host, args.port), MaliciousMCPHandler)
    print(f"[malicious-mcp] Listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[malicious-mcp] Shutting down", flush=True)
