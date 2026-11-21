# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""A small MCP server over stdio, written for EdgeFollow (no third-party package).

Transport: JSON-RPC 2.0, one message per line on stdin/stdout (MCP stdio transport, protocol versions 2025-11-25 and
2025-06-18; neither has batches). Methods: initialize, notifications/initialized, ping, tools/list, tools/call.
Nothing but protocol messages reaches stdout: anything a tool prints is captured and dropped.

Robustness: a line is read with a cap (MAX_LINE) before it is parsed; bytes that are not UTF-8 are replaced, not
fatal; any failure while parsing or handling one message is answered as a JSON-RPC error for that message, and the
server goes on. Replies are strict JSON (no NaN or Infinity).

Tool arguments are checked against the tool's input schema BEFORE the tool runs. The schema language understood
here is a closed subset of JSON Schema (object with properties / required / additionalProperties false; string with
enum, pattern, maxLength; integer with minimum, maximum; boolean). A tool whose schema uses anything else is refused
when it is registered, so a schema can never look stricter than the check that enforces it.

Errors, as MCP separates them: an unknown method or tool, or a malformed request, is a JSON-RPC error; an argument
that fails its schema, or a tool that fails, is a tool result with isError true. A ToolError carries its own (fixed,
non-data) message; any other failure is reported by its exception type only, never with its text or a traceback.
"""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import re
import signal
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18")                                 # newest first; no batches in either
MAX_LINE = 1 << 20                                                                # one request, at most 1 MiB
_SCHEMA_KEYS = {"object": {"type", "properties", "required", "additionalProperties", "description"},
                "string": {"type", "enum", "pattern", "maxLength", "description"},
                "integer": {"type", "minimum", "maximum", "description"},
                "boolean": {"type", "description"}}


class ToolError(Exception):
    """A failure the tool reports to the caller as an isError result. Its message must be fixed text plus closed
    values (edge names, status codes): never text read from a CSE or a MEC service."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):                  # a 3xx is an answer, never a new destination
        return None


def harden_http() -> None:
    """Every urllib request in this process: no proxy from the environment, no redirects followed."""
    for k in [k for k in os.environ if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")]:
        del os.environ[k]
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()))


class _Deadline(Exception):
    pass


def http_get_json(url: str, name: str, deadline_s: float = 10.0, max_body: int = 1 << 20):
    """One GET with a TOTAL deadline (a timer, so slow headers or a dripping body cannot stretch it), a size cap, no
    proxy and no redirect. Errors are ToolErrors naming `name` and a status code or an exception type, never text
    from the answer. The timer needs the main thread (the MCP servers are single-threaded)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def on_alarm(signum, frame):
        raise _Deadline()
    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, deadline_s)
    try:
        with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=deadline_s) as r:
            if r.status != 200:
                raise ToolError(f"{name} answered {int(r.status)}")
            buf = b""
            while True:
                chunk = r.read1(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > max_body:
                    raise ToolError(f"{name} answer too large")
        return json.loads(buf or b"null")
    except _Deadline:
        raise ToolError(f"{name} too slow") from None
    except ToolError:
        raise
    except urllib.error.HTTPError as e:
        raise ToolError(f"{name} answered {int(e.code)}") from None
    except (OSError, ValueError, RecursionError, http.client.HTTPException) as e:
        raise ToolError(f"{name} unreachable or not JSON ({type(e).__name__})") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    fn: Callable[..., dict]
    annotations: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.name):
            raise ValueError(f"tool name {self.name!r}")
        check_schema(self.schema, top=True)


def check_schema(schema: dict, top: bool = False) -> None:
    """Refuse any schema outside the subset validate() enforces."""
    if not isinstance(schema, dict) or schema.get("type") not in _SCHEMA_KEYS:
        raise ValueError(f"schema type {schema!r}")
    extra = set(schema) - _SCHEMA_KEYS[schema["type"]]
    if extra:
        raise ValueError(f"schema keywords not enforced here: {sorted(extra)}")
    if top and (schema["type"] != "object" or schema.get("additionalProperties") is not False):
        raise ValueError("a tool's input schema is an object with additionalProperties false")
    if schema["type"] == "object":
        props = schema.get("properties", {})
        if not set(schema.get("required", [])) <= set(props):
            raise ValueError("required names a property that is not defined")
        for sub in props.values():
            if sub.get("type") == "object":
                raise ValueError("nested objects are not supported")
            check_schema(sub)
    if schema["type"] == "string" and "pattern" in schema:
        re.compile(schema["pattern"])


def validate(schema: dict, value, where: str = "arguments") -> str | None:
    """None when value satisfies schema, else why not."""
    t = schema["type"]
    if t == "object":
        if not isinstance(value, dict):
            return f"{where}: expected an object"
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in value:
                return f"{where}: missing {k!r}"
        for k, v in value.items():
            if k not in props:
                return f"{where}: unexpected {str(k)[:40]!r}"
            why = validate(props[k], v, f"{where}.{k}")
            if why:
                return why
        return None
    if t == "string":
        if not isinstance(value, str):
            return f"{where}: expected a string"
        if "enum" in schema and value not in schema["enum"]:
            return f"{where}: must be one of {schema['enum']}"
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return f"{where}: longer than {schema['maxLength']}"
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            return f"{where}: does not match {schema['pattern']}"
        return None
    if t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"{where}: expected an integer"
        if "minimum" in schema and value < schema["minimum"]:
            return f"{where}: below {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"{where}: above {schema['maximum']}"
        return None
    if t == "boolean":
        return None if isinstance(value, bool) else f"{where}: expected true or false"
    return f"{where}: unsupported type"


def _err(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _ok(rid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _result(data: dict, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(data, sort_keys=True, allow_nan=False)}],
            "structuredContent": data, "isError": is_error}


class Server:
    def __init__(self, name: str, version: str, tools: list[Tool], instructions: str = "") -> None:
        self.name, self.version, self.instructions = name, version, instructions
        self.tools = {t.name: t for t in tools}
        if len(self.tools) != len(tools):
            raise ValueError("two tools share a name")
        self.initialized = False

    def handle_line(self, line) -> dict | None:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        if len(line) > MAX_LINE:
            return _err(None, -32700, "message too large")
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError):
            return _err(None, -32700, "parse error")
        try:
            return self.handle(msg)
        except Exception as e:                                       # noqa: BLE001 -- one bad message never stops us
            rid = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
            return _err(rid, -32603, f"internal error ({type(e).__name__})")

    def handle(self, msg) -> dict | None:
        if not isinstance(msg, dict):
            return _err(None, -32600, "invalid request (batches are not supported)")
        if "method" not in msg:                                     # a response from the client: nothing to answer
            return None
        rid, method = msg.get("id"), msg.get("method")
        if "id" not in msg:                                          # a notification: never answered
            return None
        if not isinstance(rid, (str, int)) or isinstance(rid, bool):
            return _err(None, -32600, "invalid id (a string or an integer)")
        if msg.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _err(rid, -32600, "invalid request")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return _err(rid, -32602, "params must be an object")
        if method == "initialize":
            asked = params.get("protocolVersion")
            self.initialized = True
            result = {"protocolVersion": asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0],
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": self.name, "version": self.version}}
            if self.instructions:
                result["instructions"] = self.instructions
            return _ok(rid, result)
        if method == "ping":
            return _ok(rid, {})
        if not self.initialized:
            return _err(rid, -32600, "not initialized")
        if method == "tools/list":
            return _ok(rid, {"tools": [{"name": t.name, "description": t.description, "inputSchema": t.schema,
                                        **({"annotations": t.annotations} if t.annotations else {})}
                                       for t in self.tools.values()]})
        if method == "tools/call":
            name = params.get("name")
            tool = self.tools.get(name) if isinstance(name, str) else None
            if tool is None:
                return _err(rid, -32602, "unknown tool")
            args = params.get("arguments", {})
            why = validate(tool.schema, args)
            if why:
                return _ok(rid, _result({"error": why}, True))
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    out = tool.fn(**args)
            except ToolError as e:
                return _ok(rid, _result({"error": str(e)[:300]}, True))
            except Exception as e:                                   # noqa: BLE001 -- reported by type only
                return _ok(rid, _result({"error": f"internal error ({type(e).__name__})"}, True))
            return _ok(rid, _result(out, False))
        return _err(rid, -32601, "method not found")

    def serve(self, rin=None, rout=None) -> None:
        rin = rin or getattr(sys.stdin, "buffer", sys.stdin)
        rout = rout or sys.stdout
        while True:
            line = rin.readline(MAX_LINE + 1)
            if not line:
                return
            nl = b"\n" if isinstance(line, bytes) else "\n"
            if len(line) > MAX_LINE and not line.endswith(nl):
                while True:                                          # drop the rest of an over-long line
                    rest = rin.readline(MAX_LINE)
                    if not rest or rest.endswith(nl):
                        break
                reply = _err(None, -32700, "message too large")
            elif not line.strip():
                continue
            else:
                reply = self.handle_line(line)
            if reply is None:
                continue
            try:
                text = json.dumps(reply, separators=(",", ":"), allow_nan=False)
            except ValueError:
                text = json.dumps(_err(reply.get("id"), -32603, "internal error (reply not JSON)"))
            rout.write(text + "\n")
            rout.flush()
