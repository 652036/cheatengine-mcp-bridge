#!/usr/bin/env python3
"""Standalone diagnostic for the Cheat Engine MCP bridge pipe.

Talks to CE directly over the named pipe, without the MCP SDK or an AI client in
the loop, so you can tell a broken bridge apart from a broken MCP setup.

    python check_pipe.py --ping
    python check_pipe.py --summary
    python check_pipe.py --status
    python check_pipe.py --call read_integer --params "{\\"address\\": \\"game.exe+1000\\"}"
    python check_pipe.py --lua-file C:/scripts/helper.lua
    python check_pipe.py --pipe CE_MCP_Bridge_alt --ping
    python check_pipe.py --timeout-ms 30000 --summary

Only requires pywin32 (deliberately not the `mcp` package, which is often the
thing being debugged).
"""

import argparse
import json
import os
import struct
import sys
import time

try:
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32file
    import win32pipe
except ImportError:
    print("pywin32 is required: pip install pywin32", file=sys.stderr)
    sys.exit(2)

DEFAULT_PIPE_NAME = "CE_MCP_Bridge_v99"
DEFAULT_TIMEOUT_MS = 15000
MIN_TIMEOUT_MS = 1000
MAX_REQUEST_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_LOCAL_FILE_BYTES = 16 * 1024 * 1024

ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231
ERROR_OPERATION_ABORTED = 995


def _read_int_env(name, default):
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


MAX_RESPONSE_BYTES = max(
    1024 * 1024,
    _read_int_env("CE_MCP_MAX_RESPONSE_BYTES", 64 * 1024 * 1024),
)
MAX_LOCAL_FILE_BYTES = max(
    1024 * 1024,
    _read_int_env("CE_MCP_MAX_LOCAL_FILE_BYTES", DEFAULT_MAX_LOCAL_FILE_BYTES),
)


def normalize_pipe_name(name=None):
    """Resolve explicit pipe name, CE_MCP_PIPE_NAME fallback, or default pipe path."""
    resolved = name.strip() if isinstance(name, str) else name
    if not resolved:
        resolved = (os.getenv("CE_MCP_PIPE_NAME") or "").strip()
    if not resolved:
        resolved = DEFAULT_PIPE_NAME
    if resolved.startswith("\\\\.\\pipe\\"):
        return resolved
    return r"\\.\pipe\{}".format(resolved)


class PipeClient:
    """Overlapped Win32 named-pipe client for direct CE bridge diagnostics."""

    def __init__(self, pipe_name, connect_wait_ms=3000, timeout_ms=DEFAULT_TIMEOUT_MS, auth_token=None):
        self.pipe_name = pipe_name
        self.connect_wait_ms = max(1, int(connect_wait_ms))
        self.timeout_ms = max(1, int(timeout_ms))
        self.auth_token = auth_token if auth_token is not None else (os.getenv("CE_MCP_AUTH_TOKEN") or None)
        self.handle = None
        self.last_connect_error = None
        self._next_id = 0
        self._io_event = None

    def _get_io_event(self):
        if self._io_event is None:
            self._io_event = win32event.CreateEvent(None, True, False, None)
        else:
            win32event.ResetEvent(self._io_event)
        return self._io_event

    def _discard_io_event(self):
        ev = self._io_event
        if ev is not None:
            self._io_event = None
            try:
                win32api.CloseHandle(ev)
            except Exception:
                pass

    def connect(self, *, deadline=None):
        """Connect using CreateFile-first deadline loop with FILE_FLAG_OVERLAPPED."""
        self.last_connect_error = None
        if self.handle:
            self.close()

        started = time.monotonic()
        connect_deadline = started + self.connect_wait_ms / 1000.0
        if deadline is not None:
            connect_deadline = min(connect_deadline, deadline)
        missing_grace_ms = min(self.connect_wait_ms, 1000)
        missing_deadline = None

        while time.monotonic() < connect_deadline:
            try:
                self.handle = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    win32con.FILE_FLAG_OVERLAPPED,
                    None,
                )
                return True
            except pywintypes.error as exc:
                now = time.monotonic()
                remaining_ms = int((connect_deadline - now) * 1000)

                if exc.winerror == ERROR_PIPE_BUSY:
                    self.last_connect_error = (
                        "pipe is busy (held by another MCP client or tool); wait for idle "
                        "disconnect or close the other client ({})".format(exc)
                    )
                    if remaining_ms <= 0:
                        return False
                    try:
                        win32pipe.WaitNamedPipe(self.pipe_name, min(remaining_ms, 1000))
                    except pywintypes.error:
                        pass
                    continue

                if exc.winerror == ERROR_FILE_NOT_FOUND:
                    self.last_connect_error = (
                        "pipe does not exist - is ce_mcp_bridge.lua running in CE? ({})".format(exc)
                    )
                    if missing_deadline is None:
                        missing_deadline = min(connect_deadline, now + missing_grace_ms / 1000.0)
                    if now >= missing_deadline or remaining_ms <= 0:
                        return False
                    time.sleep(min(0.05, missing_deadline - now))
                    continue

                self.last_connect_error = "CreateFile failed: {}".format(exc)
                if remaining_ms <= 0:
                    return False
                time.sleep(min(0.05, max(0.0, connect_deadline - now)))

        if not self.last_connect_error:
            self.last_connect_error = "connection deadline elapsed"
        return False

    def close(self):
        if self.handle:
            try:
                win32file.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None
        self._discard_io_event()

    def _cancel_pending_io(self, overlapped):
        # Drain GetOverlappedResult(..., True) before freeing the event or buffer.
        try:
            win32file.CancelIo(self.handle)
        finally:
            try:
                win32file.GetOverlappedResult(self.handle, overlapped, True)
            except pywintypes.error as exc:
                if exc.winerror != ERROR_OPERATION_ABORTED:
                    raise

    def _wait_for_io(self, overlapped, deadline, timeout_message):
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
        try:
            result = win32event.WaitForSingleObject(overlapped.hEvent, remaining_ms)
        except pywintypes.error:
            self._cancel_pending_io(overlapped)
            raise
        if result == win32con.WAIT_TIMEOUT:
            self._cancel_pending_io(overlapped)
            self._discard_io_event()
            raise TimeoutError(timeout_message)
        if result != win32con.WAIT_OBJECT_0:
            self._cancel_pending_io(overlapped)
            self._discard_io_event()
            raise ConnectionError("Pipe wait failed with status {}".format(result))
        return win32file.GetOverlappedResult(self.handle, overlapped, False)

    def _write_exact(self, data, deadline=None, timeout_ms=None):
        """Overlapped write to pipe, looping until every byte is written."""
        if deadline is None:
            budget_ms = self.timeout_ms if timeout_ms is None else max(1, int(timeout_ms))
            deadline = time.monotonic() + budget_ms / 1000.0
        view = memoryview(data)
        total = len(view)
        sent = 0

        while sent < total:
            remaining_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                raise TimeoutError("Write to CE timed out")

            chunk_len = min(total - sent, 1 << 20)
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = self._get_io_event()
            try:
                if sent == 0 and total <= (1 << 20) and isinstance(data, (bytes, bytearray)):
                    chunk = data
                else:
                    chunk = bytes(view[sent : sent + chunk_len])
                if time.monotonic() >= deadline:
                    raise TimeoutError("Write to CE timed out")
                win32file.WriteFile(self.handle, chunk, overlapped)
                n = self._wait_for_io(overlapped, deadline, "Write to CE timed out")
            except TimeoutError:
                raise
            except Exception:
                self._discard_io_event()
                raise

            if not n:
                raise ConnectionError("CE closed the pipe during write")
            sent += n

    def _read_exact(self, size, deadline=None, timeout_ms=None):
        """Overlapped read from pipe, looping until `size` bytes arrive."""
        if size == 0:
            return b""
        if deadline is None:
            budget_ms = self.timeout_ms if timeout_ms is None else max(1, int(timeout_ms))
            deadline = time.monotonic() + budget_ms / 1000.0
        chunks = []
        received = 0

        while received < size:
            remaining_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                raise TimeoutError("Read from CE timed out (CE main thread may be busy)")

            buf = win32file.AllocateReadBuffer(min(size - received, 1 << 20))
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = self._get_io_event()
            try:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Read from CE timed out (CE main thread may be busy)")
                win32file.ReadFile(self.handle, buf, overlapped)
                n = self._wait_for_io(
                    overlapped,
                    deadline,
                    "Read from CE timed out (CE main thread may be busy)",
                )
            except TimeoutError:
                raise
            except Exception:
                self._discard_io_event()
                raise

            if not n:
                raise ConnectionError("CE closed the pipe mid-response")

            if n == size and not chunks:
                return bytes(buf[:n])
            chunks.append(bytes(buf[:n]))
            received += n

        return b"".join(chunks)

    def call(self, method, params=None, timeout_ms=None):
        budget_ms = self.timeout_ms if timeout_ms is None else max(1, int(timeout_ms))
        deadline = time.monotonic() + budget_ms / 1000.0

        self._next_id += 1
        expected_id = self._next_id
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": expected_id,
        }
        if self.auth_token:
            request["auth_token"] = self.auth_token
        payload = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(payload) >= MAX_REQUEST_BYTES:
            raise ValueError(
                "Request too large: {} bytes (limit {} bytes)".format(len(payload), MAX_REQUEST_BYTES)
            )

        try:
            self._write_exact(struct.pack("<I", len(payload)) + payload, deadline=deadline)

            length = struct.unpack("<I", self._read_exact(4, deadline=deadline))[0]
            if length == 0:
                raise ConnectionError("Empty response frame received from CE")
            if length > MAX_RESPONSE_BYTES:
                raise ConnectionError("Response too large: {} bytes".format(length))

            body = self._read_exact(length, deadline=deadline).decode("utf-8", errors="replace")
            try:
                response = json.loads(body)
            except json.JSONDecodeError as exc:
                raise ConnectionError("Invalid JSON received from CE: {}".format(exc)) from exc

            if not isinstance(response, dict):
                raise ConnectionError(
                    "Invalid JSON-RPC response from CE: expected object, got {}".format(
                        type(response).__name__
                    )
                )

            has_error = bool(response.get("error"))
            resp_id = response.get("id")
            if has_error:
                if resp_id not in (None, expected_id):
                    raise ConnectionError(
                        "Mismatched response id from CE (expected {}, got {})".format(
                            expected_id, resp_id
                        )
                    )
            elif resp_id != expected_id:
                raise ConnectionError(
                    "Mismatched response id from CE (expected {}, got {})".format(
                        expected_id, resp_id
                    )
                )
        except (pywintypes.error, TimeoutError, ConnectionError):
            self.close()
            raise

        if response.get("error"):
            raise RuntimeError("CE error: {}".format(response["error"]))
        return response.get("result", response)


def read_text_file(path, max_bytes=None):
    """Read and auto-decode a local text file within the configured size limit."""
    limit = MAX_LOCAL_FILE_BYTES if max_bytes is None else max(1, int(max_bytes))
    file_size = os.path.getsize(path)
    if file_size > limit:
        raise ValueError(
            "File {} is too large ({} bytes, limit {} bytes)".format(path, file_size, limit)
        )
    with open(path, "rb") as f:
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(
            "File {} exceeds limit of {} bytes".format(path, limit)
        )

    candidates = ["utf-8-sig", "utf-8", "gb18030", "cp936"]
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in raw:
        candidates = ["utf-16", "utf-16-le", "utf-16-be"] + candidates
    for enc in candidates:
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise ValueError("Could not decode {}".format(path))


def dump(label, value):
    print("\n=== {} ===".format(label))
    print(json.dumps(value, indent=2, ensure_ascii=False))


def print_summary(client):
    status = client.call("status")
    print("\n--- Bridge ---")
    print("  version               : {}".format(status.get("version")))
    print("  pipe                  : {}".format(status.get("pipe_name")))
    print("  auth required         : {}".format(status.get("auth_required")))
    print("  worker running        : {}".format(status.get("worker_running")))
    print("  worker hot reload     : {}".format(status.get("worker_hot_reload")))
    print("  idle kick ms          : {}".format(status.get("idle_kick_ms")))
    print("\n--- Target ---")
    print("  process id            : {}".format(status.get("process_id")))
    print("  attached              : {}".format(status.get("process_attached")))
    print("  architecture          : {}".format(status.get("architecture")))
    print("  debugger started      : {}".format(status.get("debugger_started")))
    print("\n--- Capabilities ---")
    print("  DBK driver loaded     : {}".format(status.get("dbk_loaded")))
    print("  DBVM active           : {}".format(status.get("dbvm_active")))
    print("\n--- Resources ---")
    print("  hw bp slots used      : {}/{}".format(
        status.get("hw_breakpoint_slots_used"), status.get("hw_breakpoint_slots_total")))
    print("  breakpoints           : {}".format(len(status.get("breakpoints") or [])))
    print("  completed breakpoints : {}".format(len(status.get("completed_breakpoints") or [])))
    print("  dbvm watches          : {}".format(len(status.get("dbvm_watches") or [])))
    print("  AA scripts stored     : {}".format(len(status.get("auto_assemble_scripts") or [])))
    print("  scan results held     : {}".format(status.get("scan_results_available")))

    if status.get("process_attached"):
        info = client.call("get_process_info")
        print("\n--- Process info ---")
        print("  name                  : {}".format(info.get("process_name")))
        print("  name resolved         : {}".format(info.get("process_name_resolved")))
        print("  modules               : {}".format(info.get("total_modules")))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Cheat Engine MCP bridge pipe diagnostic")
    parser.add_argument(
        "--pipe",
        default=None,
        help="pipe name or full \\\\.\\pipe\\... path (fallback: CE_MCP_PIPE_NAME)",
    )
    parser.add_argument("--connect-wait-ms", type=int, default=3000)
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=DEFAULT_TIMEOUT_MS,
        help="request I/O timeout in ms (default: 15000, min: 1000)",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="optional shared-secret token (fallback: CE_MCP_AUTH_TOKEN)",
    )
    parser.add_argument("--ping", action="store_true", help="round-trip a ping")
    parser.add_argument("--status", action="store_true", help="dump raw bridge status")
    parser.add_argument("--summary", action="store_true", help="human-readable health summary")
    parser.add_argument("--call", metavar="METHOD", help="invoke an arbitrary bridge method")
    parser.add_argument("--params", default="{}", help="JSON params for --call")
    parser.add_argument("--lua-file", metavar="PATH", help="run a local Lua file in CE")
    parser.add_argument("--repeat", type=int, default=1, help="repeat the action N times")
    args = parser.parse_args(argv)
    args.timeout_ms = max(MIN_TIMEOUT_MS, args.timeout_ms)
    return args


def main(argv=None):
    args = parse_args(argv)

    if not any([args.ping, args.status, args.summary, args.call, args.lua_file]):
        args.summary = True

    pipe_name = normalize_pipe_name(args.pipe)
    client = PipeClient(
        pipe_name,
        connect_wait_ms=args.connect_wait_ms,
        timeout_ms=args.timeout_ms,
        auth_token=args.auth_token,
    )

    print("Connecting to {} ...".format(pipe_name))
    try:
        connected = client.connect()
    except pywintypes.error as exc:
        connected = False
        client.last_connect_error = str(exc)

    if not connected:
        print(
            "\nFAILED to connect: {}".format(client.last_connect_error or "connection failed"),
            file=sys.stderr,
        )
        print("\nChecklist:", file=sys.stderr)
        print("  1. Is Cheat Engine running?", file=sys.stderr)
        print("  2. Was ce_mcp_bridge.lua executed (Table -> Show Cheat Table Lua Script -> Execute)?", file=sys.stderr)
        print("  3. Does the CE console show 'MCP Server Listening on: {}'?".format(pipe_name), file=sys.stderr)
        print("  4. If you changed the pipe name, pass --pipe or set CE_MCP_PIPE_NAME with the same value.", file=sys.stderr)
        return 1
    print("Connected.")

    try:
        for i in range(max(1, args.repeat)):
            if args.repeat > 1:
                print("\n########## iteration {}/{} ##########".format(i + 1, args.repeat))

            if args.ping:
                started = time.monotonic()
                result = client.call("ping")
                elapsed = (time.monotonic() - started) * 1000
                dump("ping ({:.1f} ms)".format(elapsed), result)

            if args.summary:
                print_summary(client)

            if args.status:
                dump("status", client.call("status"))

            if args.lua_file:
                code, encoding = read_text_file(args.lua_file)
                print("\nLoaded {} ({} chars, {})".format(args.lua_file, len(code), encoding))
                dump("evaluate_lua", client.call("evaluate_lua", {"code": code, "serialize_result": False}))

            if args.call:
                try:
                    params = json.loads(args.params)
                except json.JSONDecodeError as e:
                    print("--params is not valid JSON: {}".format(e), file=sys.stderr)
                    return 2
                dump(args.call, client.call(args.call, params))

        return 0
    except Exception as e:
        print("\nERROR: {}".format(e), file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
