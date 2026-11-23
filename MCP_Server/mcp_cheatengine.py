import io
import os
import sys

# ============================================================================
# CRITICAL: WINDOWS LINE ENDING FIX FOR MCP (MONKEY-PATCH)
# The MCP SDK's stdio_server uses TextIOWrapper without newline='\n', causing
# Windows to output CRLF (\r\n) instead of LF (\n). This causes the error:
# "invalid trailing data at the end of stream"
# We MUST patch the MCP SDK BEFORE importing FastMCP.
# ============================================================================

if sys.platform == "win32":
    import msvcrt
    from io import TextIOWrapper
    from contextlib import asynccontextmanager

    def _set_binary_mode(stream) -> bool:
        """Enable binary mode on a stdio stream when it exposes a real OS fd."""
        if stream is None:
            return False
        try:
            msvcrt.setmode(stream.fileno(), os.O_BINARY)
            return True
        except (AttributeError, io.UnsupportedOperation, OSError, ValueError):
            return False

    # Set binary mode on underlying file handles (safe under pytest capture / pythonw)
    _set_binary_mode(sys.stdin)
    _set_binary_mode(sys.stdout)
    
    # Monkey-patch the MCP SDK's stdio_server to use newline='\n'
    import mcp.server.stdio as mcp_stdio
    import anyio
    import anyio.lowlevel
    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
    import mcp.types as types
    from mcp.shared.message import SessionMessage
    
    @asynccontextmanager
    async def _patched_stdio_server(
        stdin: "anyio.AsyncFile[str] | None" = None,
        stdout: "anyio.AsyncFile[str] | None" = None,
    ):
        """Patched stdio_server with proper Windows newline handling."""
        if not stdin:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdin = anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline='\n'))
        if not stdout:
            # Use newline='\n' to prevent CRLF translation on Windows
            raw_stdout = TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline='\n', write_through=True)
            stdout = anyio.wrap_file(raw_stdout)
        else:
            raw_stdout = None

        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        async def stdin_reader():
            try:
                async with read_stream_writer:
                    async for line in stdin:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_stream_writer.send(exc)
                            continue
                        session_message = SessionMessage(message)
                        await read_stream_writer.send(session_message)
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        def _write_and_flush(text: str) -> None:
            raw_stdout.write(text)
            raw_stdout.flush()

        async def stdout_writer():
            try:
                async with write_stream_reader:
                    async for session_message in write_stream_reader:
                        payload_json = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                        if raw_stdout is not None:
                            await anyio.to_thread.run_sync(_write_and_flush, payload_json + "\n")
                        else:
                            await stdout.write(payload_json + "\n")
                            await stdout.flush()
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            yield read_stream, write_stream
    
    # Apply the monkey-patch
    mcp_stdio.stdio_server = _patched_stdio_server

# ============================================================================
# STDOUT PROTECTION FOR MCP
# MCP uses stdout for JSON-RPC. ANY stray output corrupts it.
# ============================================================================

# Save original stdout for MCP to use
_mcp_stdout = sys.stdout

# Redirect stdout to stderr so any accidental prints go to logs, not MCP stream
sys.stdout = sys.stderr

# Now safe to import libraries that might print during import
import json
import struct
import time
import threading
import traceback
import anyio
from collections.abc import Sequence
from contextlib import contextmanager
from functools import partial, wraps
from pathlib import Path

try:
    import win32file
    import win32pipe
    import win32con
    import win32event
    import win32api
    import pywintypes
    from pydantic import StrictInt
    from mcp.server.fastmcp import FastMCP
    
    # CRITICAL: Also patch the reference inside the fastmcp module
    # FastMCP already imported stdio_server before our patch, so we need to update its reference too
    if sys.platform == "win32":
        import mcp.server.fastmcp.server as fastmcp_server
        fastmcp_server.stdio_server = _patched_stdio_server
        
except ImportError as e:
    print(f"[MCP CE] Import Error: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout

# Debug helper - always goes to stderr, never corrupts MCP
def debug_log(msg):
    print(f"[MCP CE] {msg}", file=sys.stderr, flush=True)

# Helper to format results as proper JSON strings for MCP tools
def format_result(result):
    """Format CE Bridge result as a compact JSON string for AI consumption."""
    if isinstance(result, dict):
        return json.dumps(result, indent=None, separators=(",", ":"), ensure_ascii=False)
    elif isinstance(result, str):
        return result  # Already a string
    else:
        return json.dumps(result, separators=(",", ":"), ensure_ascii=False)

# ============================================================================
# CONFIGURATION
# ============================================================================

# V11 Bridge uses 'CE_MCP_Bridge_v99'
DEFAULT_PIPE_NAME = "CE_MCP_Bridge_v99"


def _read_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return int(raw_value)
    except ValueError:
        debug_log(f"Invalid integer for {name}: {raw_value!r}. Falling back to {default}.")
        return default


def _normalize_pipe_name(pipe_name: str | None) -> str:
    if not pipe_name:
        pipe_name = DEFAULT_PIPE_NAME
    if pipe_name.startswith("\\\\.\\pipe\\"):
        return pipe_name
    return rf"\\.\pipe\{pipe_name}"


def _read_cli_arg(name: str) -> str | None:
    try:
        idx = sys.argv.index(name)
    except ValueError:
        return None
    if idx + 1 >= len(sys.argv):
        return None
    return sys.argv[idx + 1]


PIPE_NAME = _normalize_pipe_name(_read_cli_arg("--pipe") or os.getenv("CE_MCP_PIPE_NAME"))
MCP_SERVER_NAME = os.getenv("CE_MCP_SERVER_NAME", "cheatengine")
CE_AUTH_TOKEN = os.getenv("CE_MCP_AUTH_TOKEN") or None

# ============================================================================
# PIPE CLIENT
# ============================================================================

# Default end-to-end pipe request budget in milliseconds.
CE_READ_TIMEOUT_MS = max(1000, _read_int_env("CE_MCP_TIMEOUT_MS", 120000))
CE_BREAKPOINT_TIMEOUT_MS = max(1000, _read_int_env("CE_MCP_BREAKPOINT_TIMEOUT_MS", 10000))
CE_LOCK_TIMEOUT_MS = max(1, _read_int_env("CE_MCP_LOCK_TIMEOUT_MS", 15000))
CE_CONNECT_WAIT_MS = max(100, _read_int_env("CE_MCP_CONNECT_WAIT_MS", 3000))
CE_CONNECT_RETRIES = max(1, _read_int_env("CE_MCP_CONNECT_RETRIES", 3))
CE_CONNECT_RETRY_DELAY_MS = max(0, _read_int_env("CE_MCP_CONNECT_RETRY_DELAY_MS", 250))
MAX_SCAN_BUDGET = min(max(1, _read_int_env("CE_MCP_MAX_SCAN_BUDGET", 200000)), 200000)
MAX_REQUEST_BYTES = 100 * 1024 * 1024
MAX_RESPONSE_BYTES = max(1024 * 1024, _read_int_env("CE_MCP_MAX_RESPONSE_BYTES", 64 * 1024 * 1024))
MAX_LOCAL_FILE_BYTES = max(1024 * 1024, _read_int_env("CE_MCP_MAX_LOCAL_FILE_BYTES", 16 * 1024 * 1024))
MAX_WRITE_MEMORY_BYTES = 65536
# CE's bridge serves exactly one pipe client at a time. A handle kept open while
# the AI is idle (it rarely remembers to call `disconnect`) locks every other MCP
# client - another AI session, Cursor, Codex - out of CE. Release the handle after
# this much inactivity; the next command reconnects transparently.
# 0 = close after every command, negative = keep the connection open forever.
CE_IDLE_DISCONNECT_MS = _read_int_env("CE_MCP_IDLE_DISCONNECT_MS", 3000)
# How long to wait for CE to (re)create its pipe instance when none exists. The
# bridge leaves a ~50 ms gap between clients; a missing CE should still fail fast.
CE_PIPE_MISSING_GRACE_MS = max(0, _read_int_env("CE_MCP_PIPE_MISSING_GRACE_MS", 1000))

ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231

# Methods eligible for replay when a reply is lost. Unlisted methods are never
# replayed once delivery is uncertain.
RETRY_SAFE_METHODS = frozenset({
    "ping",
    "status",
    "get_status",
    "get_process_info",
    "enum_modules",
    "get_thread_list",
    "get_symbol_address",
    "get_address_info",
    "get_rtti_classname",
    "read_memory",
    "read_bytes",
    "read_integer",
    "read_string",
    "read_pointer",
    "read_pointer_chain",
    "checksum_memory",
    "get_scan_results",
    "aob_scan",
    "pattern_scan",
    "search_string",
    "generate_signature",
    "get_memory_regions",
    "enum_memory_regions_full",
    "disassemble",
    "get_instruction_info",
    "find_function_boundaries",
    "analyze_function",
    "find_references",
    "find_call_references",
    "dissect_structure",
    "list_breakpoints",
    "get_physical_address",
})


def _clamp_int(value, low: int, high: int) -> int:
    """Convert value to int and clamp it into [low, high]."""
    return min(max(int(value), low), high)


def _clamp_scan_budget(value, default=MAX_SCAN_BUDGET):
    try:
        return _clamp_int(value, 1, MAX_SCAN_BUDGET)
    except (TypeError, ValueError):
        return default


def _resolve_local_file_path(file_path: str) -> Path:
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("file_path must be a non-empty string")

    path = Path(file_path.strip()).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")
    return path


def _validate_write_bytes(data) -> list[int]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes, bytearray)):
        raise ValueError("bytes must be a non-empty sequence of integers (0..255)")
    if len(data) == 0:
        raise ValueError("bytes must not be empty")
    if len(data) > MAX_WRITE_MEMORY_BYTES:
        raise ValueError(f"bytes length {len(data)} exceeds maximum of {MAX_WRITE_MEMORY_BYTES}")
    validated: list[int] = []
    for idx, value in enumerate(data):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 255:
            raise ValueError(f"bytes[{idx}] must be an integer between 0 and 255, got {value!r}")
        validated.append(value)
    return validated


def _read_text_file_robust(file_path: str, encoding: str = "auto") -> tuple[str, str, str]:
    path = _resolve_local_file_path(file_path)
    file_size = path.stat().st_size
    if file_size > MAX_LOCAL_FILE_BYTES:
        raise ValueError(
            f"File too large: {file_size} bytes (limit {MAX_LOCAL_FILE_BYTES} bytes) for {path}"
        )
    with path.open("rb") as f:
        file_bytes = f.read(MAX_LOCAL_FILE_BYTES + 1)
    if len(file_bytes) > MAX_LOCAL_FILE_BYTES:
        raise ValueError(
            f"File too large: exceeded limit of {MAX_LOCAL_FILE_BYTES} bytes while reading {path}"
        )

    if encoding and encoding.lower() != "auto":
        try:
            return file_bytes.decode(encoding), encoding, str(path)
        except UnicodeDecodeError as exc:
            raise UnicodeDecodeError(
                exc.encoding,
                exc.object,
                exc.start,
                exc.end,
                f"{exc.reason}. Use encoding='auto' or provide the correct encoding."
            ) from exc

    likely_utf16 = (
        file_bytes.startswith((b"\xff\xfe", b"\xfe\xff"))
        or b"\x00" in file_bytes
    )

    candidates = ["utf-8-sig", "utf-8", "gb18030", "cp936"]
    if likely_utf16:
        candidates = ["utf-16", "utf-16-le", "utf-16-be"] + candidates
    for candidate in candidates:
        try:
            return file_bytes.decode(candidate), candidate, str(path)
        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError(
        "unknown",
        file_bytes,
        0,
        min(len(file_bytes), 1),
        "Unable to decode file. Try passing encoding explicitly, e.g. 'utf-8' or 'gb18030'.",
    )


def _attach_source_metadata(result, source_path: str, source_encoding: str, source_size: int):
    if isinstance(result, dict):
        payload = dict(result)
    else:
        payload = {"success": True, "result": result}

    payload["source_file"] = source_path
    payload["source_encoding"] = source_encoding
    payload["source_length"] = source_size
    return payload

class CEBridgeClient:
    def __init__(self):
        self.handle = None
        self.last_connect_error = None
        self._lock = threading.Lock()
        self._next_request_id = 0
        self._last_used = 0.0
        self._io_event = None
        self._idle_deadline = None
        self._idle_cond = threading.Condition()
        self._idle_thread = None

    def _allocate_request_id(self):
        self._next_request_id += 1
        return self._next_request_id

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
        """Attempts to connect to the CE Named Pipe (overlapped mode for timeout support).

        CreateFile first, WaitNamedPipe only when every instance is busy. Calling
        WaitNamedPipe up front fails instantly during the brief window in which CE
        is recreating its single instance for the next client.
        """
        self.last_connect_error = None
        started = time.monotonic()
        connect_deadline = started + (CE_CONNECT_WAIT_MS * CE_CONNECT_RETRIES) / 1000.0
        if deadline is not None:
            connect_deadline = min(connect_deadline, deadline)
        missing_deadline = min(connect_deadline, started + CE_PIPE_MISSING_GRACE_MS / 1000.0)

        while time.monotonic() < connect_deadline:
            try:
                self.handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    win32con.FILE_FLAG_OVERLAPPED,
                    None
                )
                return True
            except pywintypes.error as e:
                now = time.monotonic()
                remaining_ms = int((connect_deadline - now) * 1000)

                if e.winerror == ERROR_PIPE_BUSY:
                    self.last_connect_error = (
                        f"pipe is held by another MCP client (another AI session or tool); "
                        f"it is released once that client has been idle for its idle-disconnect "
                        f"time ({e})"
                    )
                    if remaining_ms <= 0:
                        return False
                    try:
                        win32pipe.WaitNamedPipe(PIPE_NAME, min(remaining_ms, 1000))
                    except pywintypes.error:
                        pass  # timed out or instance vanished; CreateFile decides
                    continue

                if e.winerror == ERROR_FILE_NOT_FOUND:
                    self.last_connect_error = (
                        f"pipe does not exist - is ce_mcp_bridge.lua running in CE? ({e})"
                    )
                    if now >= missing_deadline or remaining_ms <= 0:
                        return False
                    time.sleep(min(0.05, missing_deadline - now))
                    continue

                self.last_connect_error = f"CreateFile failed: {e}"
                if remaining_ms <= 0:
                    return False
                time.sleep(min(max(CE_CONNECT_RETRY_DELAY_MS, 50), remaining_ms) / 1000.0)

        return False

    def _ensure_idle_reaper_locked(self):
        if self._idle_thread is not None and self._idle_thread.is_alive():
            return
        thread = threading.Thread(target=self._idle_reaper_loop, name="ce-idle-reaper", daemon=True)
        self._idle_thread = thread
        thread.start()

    def _idle_reaper_loop(self):
        while True:
            with self._idle_cond:
                while self._idle_deadline is None:
                    self._idle_cond.wait()
                remaining = self._idle_deadline - time.monotonic()
                if remaining > 0:
                    self._idle_cond.wait(timeout=remaining)
                    continue
                self._idle_deadline = None
            self._release_if_idle()

    def _schedule_idle_release(self):
        """Arm the idle-release deadline. Caller holds the command lock."""
        if not self.handle or CE_IDLE_DISCONNECT_MS < 0:
            with self._idle_cond:
                self._idle_deadline = None
            return
        if CE_IDLE_DISCONNECT_MS == 0:
            self.close()
            return
        with self._idle_cond:
            self._ensure_idle_reaper_locked()
            self._idle_deadline = time.monotonic() + (CE_IDLE_DISCONNECT_MS / 1000.0)
            self._idle_cond.notify()

    def _release_if_idle(self):
        # A running command owns the lock and re-arms the deadline when it finishes.
        if not self._lock.acquire(blocking=False):
            return
        try:
            idle_s = time.monotonic() - self._last_used
            if self.handle and CE_IDLE_DISCONNECT_MS > 0 and idle_s >= CE_IDLE_DISCONNECT_MS / 1000.0 - 0.01:
                debug_log(f"Releasing CE pipe after {idle_s:.1f}s idle")
                self.close()
        finally:
            self._lock.release()

    def _cancel_pending_io(self, overlapped):
        # CancelIo only requests cancellation. Keep the OVERLAPPED, its event
        # and the caller's buffer alive until Windows completes the operation.
        try:
            win32file.CancelIo(self.handle)
        finally:
            try:
                win32file.GetOverlappedResult(self.handle, overlapped, True)
            except pywintypes.error as exc:
                if exc.winerror != 995:  # ERROR_OPERATION_ABORTED
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
            raise ConnectionError(f"Overlapped pipe I/O wait failed (status={result})")
        return win32file.GetOverlappedResult(self.handle, overlapped, False)

    def _write(self, data, timeout_ms=None, *, deadline=None):
        """Overlapped write to pipe, looping until every byte is accepted."""
        if deadline is None:
            budget_ms = CE_READ_TIMEOUT_MS if timeout_ms is None else timeout_ms
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

    def _read(self, size, timeout_ms=None, *, deadline=None):
        """Overlapped read from pipe, looping until `size` bytes arrive.

        A byte-mode named pipe returns whatever is currently buffered, not the
        full requested length. The previous single ReadFile treated a short read
        as a fatal "Incomplete response body", so any reply larger than CE's
        64 KB pipe buffer failed outright - enum_memory_regions_full, big
        disassembly listings, scan results and DBVM logs all hit this.
        """
        if deadline is None:
            budget_ms = CE_READ_TIMEOUT_MS if timeout_ms is None else timeout_ms
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
                n = self._wait_for_io(overlapped, deadline, "Read from CE timed out (CE main thread may be busy)")
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

    @contextmanager
    def command_lock(self, timeout_ms=None, *, deadline=None):
        # Concurrent MCP requests must not interleave pipe frames or wait forever
        # behind a CE operation which is stuck in the debugger/main thread.
        lock_ms = CE_LOCK_TIMEOUT_MS if timeout_ms is None else timeout_ms
        wait_s = max(1, lock_ms) / 1000.0
        if deadline is not None:
            wait_s = min(wait_s, deadline - time.monotonic())
        if wait_s <= 0 or not self._lock.acquire(timeout=wait_s):
            raise ConnectionError("CE pipe is busy with another command; this request was not sent")
        try:
            yield
        finally:
            try:
                self._last_used = time.monotonic()
                self._schedule_idle_release()
            finally:
                self._lock.release()

    def disconnect(self):
        with self.command_lock(timeout_ms=min(CE_LOCK_TIMEOUT_MS, 1000)):
            self.close()

    def send_command(self, method, params=None, timeout_ms=None, max_retries=2):
        """Send command to CE Bridge with auto-reconnection on failure.

        Queueing, connection and every attempt share one deadline. Once a write
        starts, even a failed write may have delivered the full request, so only
        explicitly replay-safe methods can be resent.
        """
        attempts = max(1, int(max_retries))
        budget_ms = CE_READ_TIMEOUT_MS if timeout_ms is None else timeout_ms
        deadline = time.monotonic() + budget_ms / 1000.0
        request_params = params or {}
        replay_safe = method in RETRY_SAFE_METHODS and not (
            method == "get_process_info" and request_params.get("refresh_symbols") is True
        )
        with self.command_lock(deadline=deadline):
            last_error = None

            for attempt in range(attempts):
                if time.monotonic() >= deadline:
                    break
                if not self.handle and not self.connect(deadline=deadline):
                    error_text = self.last_connect_error or "connection deadline elapsed"
                    raise ConnectionError(
                        f"Cheat Engine Bridge is not reachable on {PIPE_NAME}: {error_text}"
                    )

                request_id = self._allocate_request_id()
                request = {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": request_params,
                    "id": request_id
                }
                if CE_AUTH_TOKEN:
                    request["auth_token"] = CE_AUTH_TOKEN
                may_have_been_sent = False

                try:
                    # ensure_ascii=False keeps non-ASCII text as UTF-8 instead of
                    # \uXXXX escapes. Both sides handle escapes now, but sending raw
                    # UTF-8 is smaller and avoids surrogate-pair edge cases entirely.
                    req_json = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
                    if len(req_json) >= MAX_REQUEST_BYTES:
                        raise ValueError(
                            f"Request too large: {len(req_json)} bytes (limit < {MAX_REQUEST_BYTES} bytes)"
                        )
                    header = struct.pack('<I', len(req_json))

                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"CE request deadline elapsed ({budget_ms} ms)")
                    may_have_been_sent = True
                    self._write(header + req_json, deadline=deadline)

                    resp_header_buffer = self._read(4, deadline=deadline)
                    resp_len = struct.unpack('<I', resp_header_buffer)[0]

                    if resp_len == 0:
                        self.close()
                        raise ConnectionError("Empty response frame received from CE")

                    if resp_len > MAX_RESPONSE_BYTES:
                        self.close()
                        raise ConnectionError(
                            f"Response too large: {resp_len} bytes (limit {MAX_RESPONSE_BYTES}). "
                            f"Ask for less data, e.g. a smaller 'max'/'count'/'size'."
                        )

                    resp_body_buffer = self._read(resp_len, deadline=deadline)

                    try:
                        # errors='replace': memory contents can carry bytes that are
                        # not valid UTF-8. An uncaught UnicodeDecodeError here used to
                        # escape send_command entirely and surface as a tool crash.
                        response = json.loads(resp_body_buffer.decode('utf-8', errors='replace'))
                    except json.JSONDecodeError as e:
                        self.close()
                        raise ConnectionError(f"Invalid JSON received from CE: {e}")

                    if not isinstance(response, dict):
                        self.close()
                        raise ConnectionError(
                            f"Invalid JSON-RPC response from CE: expected object, got {type(response).__name__}"
                        )

                    has_error = bool(response.get("error"))
                    resp_id = response.get("id")
                    if has_error:
                        if resp_id not in (None, request_id):
                            self.close()
                            raise ConnectionError(
                                f"Mismatched response id from CE (expected {request_id}, got {resp_id})"
                            )
                        error = response["error"]
                        if isinstance(error, dict):
                            return {
                                "success": False,
                                "error": error.get("message", "Unknown CE error"),
                                "error_code": error.get("code"),
                                "error_data": error.get("data"),
                            }
                        return {"success": False, "error": str(error)}

                    if resp_id != request_id:
                        self.close()
                        raise ConnectionError(
                            f"Mismatched response id from CE (expected {request_id}, got {resp_id})"
                        )
                    if 'result' in response:
                        return response['result']

                    return response

                except (pywintypes.error, TimeoutError, ConnectionError) as e:
                    self.close()
                    last_error = e if isinstance(e, ConnectionError) else ConnectionError(
                        f"Pipe Communication failed: {e}"
                    )

                    if may_have_been_sent and not replay_safe:
                        raise ConnectionError(
                            f"{last_error} - '{method}' may have reached CE and is not "
                            f"safe to retry automatically. Verify the target state before repeating it."
                        ) from e

                    if attempt >= attempts - 1:
                        break

            if last_error:
                raise last_error
            raise ConnectionError(f"CE request deadline elapsed ({budget_ms} ms)")

    def close(self):
        with self._idle_cond:
            self._idle_deadline = None
        if self.handle:
            try:
                win32file.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None
        self._discard_io_event()

ce_client = CEBridgeClient()

# ============================================================================
# MCP SERVER - v11 IMPLEMENTATION
# ============================================================================

mcp = FastMCP(MCP_SERVER_NAME)


def threaded_tool():
    """Keep blocking Win32 pipe I/O off FastMCP's protocol event loop.

    Preserve the original signature for tool schema generation. CEBridgeClient
    serializes access to its single connection, including disconnect. Do not
    abandon an in-flight write on cancellation: its side effect is uncertain.
    """
    def register(fn):
        @wraps(fn)
        async def run(*args, **kwargs):
            return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))
        mcp.add_tool(run)
        return fn
    return register

# --- PROCESS & MODULES ---

@threaded_tool()
def get_process_info(refresh_symbols: bool = False) -> str:
    """Get current process ID, name, modules count and architecture.

    Set refresh_symbols=True only when you need CE to reinitialize its symbol
    handler; leaving it False avoids expensive PDB/module symbol reloads.
    """
    return format_result(ce_client.send_command("get_process_info", {"refresh_symbols": bool(refresh_symbols)}))

@threaded_tool()
def enum_modules() -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes."""
    return format_result(ce_client.send_command("enum_modules"))

@threaded_tool()
def get_thread_list() -> str:
    """Get list of threads in the attached process."""
    return format_result(ce_client.send_command("get_thread_list"))

@threaded_tool()
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name (e.g., 'Engine.GameEngine') to an address."""
    return format_result(ce_client.send_command("get_symbol_address", {"symbol": symbol}))

@threaded_tool()
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Get symbolic name and module info for an address (Reverse of get_symbol_address)."""
    return format_result(ce_client.send_command("get_address_info", {
        "address": address, 
        "include_modules": include_modules, 
        "include_symbols": include_symbols,
        "include_sections": include_sections
    }))

@threaded_tool()
def get_rtti_classname(address: str) -> str:
    """Try to identify the class name of an object at address using Run-Time Type Information."""
    return format_result(ce_client.send_command("get_rtti_classname", {"address": address}))

# --- MEMORY READING ---

@threaded_tool()
def read_memory(address: str, size: int = 256, include_bytes: bool = True) -> str:
    """Read raw bytes from memory. Set include_bytes=False for hex string only."""
    return format_result(ce_client.send_command("read_memory", {
        "address": address,
        "size": min(max(int(size), 1), 65536),
        "include_bytes": bool(include_bytes),
    }))

@threaded_tool()
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number from memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("read_integer", {"address": address, "type": type}))

@threaded_tool()
def read_string(address: str, max_length: int = 256, wide: bool = False) -> str:
    """Read a string from memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("read_string", {
        "address": address,
        "max_length": min(max(int(max_length), 1), 65536),
        "wide": wide,
    }))

@threaded_tool()
def read_pointer(address: str, offsets: list[int] | None = None) -> str:
    """Read one pointer at address, or follow a pointer chain if offsets are provided."""
    if offsets:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": offsets}))
    return format_result(ce_client.send_command("read_pointer", {"address": address}))

@threaded_tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(ce_client.send_command("read_pointer_chain", {"base": base, "offsets": offsets}))

@threaded_tool()
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(ce_client.send_command("checksum_memory", {
        "address": address,
        "size": min(max(int(size), 1), 16777216),
    }))

# --- SCANNING ---

@threaded_tool()
def scan_all(
    value: str | int | float,
    type: str = "dword",
    protection: str = "+W-C",
    start_address: str = "",
    size: int = 0,
    max_scan: int = MAX_SCAN_BUDGET,
) -> str:
    """Unified memory scanner capped to one 200,000-address window per call."""
    params = {
        "value": value,
        "type": type,
        "protection": protection,
        "max_scan": _clamp_scan_budget(max_scan),
    }
    if start_address:
        params["start_address"] = start_address
    if size:
        params["size"] = _clamp_scan_budget(size)
    return format_result(ce_client.send_command("scan_all", params))

@threaded_tool()
def get_scan_results(max: int = 100) -> str:
    """Get results from the last 'scan_all' operation. Use 'max' to limit output."""
    return format_result(ce_client.send_command("get_scan_results", {"max": _clamp_int(max, 1, 10000)}))
@threaded_tool()
def next_scan(value: str | int | float, scan_type: str = "exact") -> str:
    """Next scan to filter results. Types: exact, increased, decreased, changed, unchanged, bigger, smaller."""
    return format_result(ce_client.send_command("next_scan", {"value": value, "scan_type": scan_type}))

@threaded_tool()
def write_integer(address: str, value: int | float, type: str = "dword") -> str:
    """Write a number to memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("write_integer", {"address": address, "value": value, "type": type}))

@threaded_tool()
def write_memory(address: str, bytes: list[StrictInt]) -> str:
    """Write raw bytes to memory."""
    validated_bytes = _validate_write_bytes(bytes)
    return format_result(ce_client.send_command("write_memory", {"address": address, "bytes": validated_bytes}))

@threaded_tool()
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("write_string", {"address": address, "value": value, "wide": wide}))


@threaded_tool()
def aob_scan(
    pattern: str,
    protection: str = "+X",
    limit: int = 100,
    start_address: str = "",
    size: int = 0,
    time_budget_ms: int = 1500,
    max_windows: int = 1,
    allow_unsafe_global: bool = False,
    timeout_ms: int = 30000,
) -> str:
    """Scan for an Array of Bytes (AOB) pattern, e.g. "48 8B 05 ?? ?? ?? ??".

    Each window covers up to 200,000 addresses. Raise max_windows (up to 64) to walk
    several consecutive regions in one call instead of following next_start_address
    manually; the time budget still bounds the whole call. Low-entropy patterns are
    refused for unbounded scans unless allow_unsafe_global=True.
    """
    max_size = MAX_SCAN_BUDGET
    params = {
        "pattern": pattern,
        "protection": protection,
        "limit": min(max(int(limit), 1), 1000),
        "time_budget_ms": min(max(int(time_budget_ms), 100), 10000),
        "max_windows": min(max(int(max_windows), 1), 64),
        "allow_unsafe_global": bool(allow_unsafe_global),
    }
    if start_address:
        params["start_address"] = start_address
    if size:
        params["size"] = min(max(int(size), 1), max_size)
    return format_result(ce_client.send_command("aob_scan", params, timeout_ms=min(max(int(timeout_ms), 1000), 60000), max_retries=1))
@threaded_tool()
def search_string(
    string: str,
    wide: bool = False,
    limit: int = 100,
    start_address: str = "",
    size: int = 0,
    max_scan: int = MAX_SCAN_BUDGET,
    time_budget_ms: int = 1500,
    max_windows: int = 1,
    timeout_ms: int = 30000,
) -> str:
    """Search for a text string in memory.

    Raise max_windows (up to 64) to cover more than one 200,000-address window per call.
    """
    params = {
        "string": string,
        "wide": wide,
        "limit": min(max(int(limit), 1), 1000),
        "max_scan": _clamp_scan_budget(max_scan),
        "time_budget_ms": min(max(int(time_budget_ms), 100), 10000),
        "max_windows": min(max(int(max_windows), 1), 64),
    }
    if start_address:
        params["start_address"] = start_address
    if size:
        params["size"] = _clamp_scan_budget(size)
    return format_result(ce_client.send_command("search_string", params, timeout_ms=min(max(int(timeout_ms), 1000), 60000), max_retries=1))

@threaded_tool()
def generate_signature(address: str) -> str:
    """Generate a unique AOB signature that can find this specific address again."""
    return format_result(ce_client.send_command("generate_signature", {"address": address}))

@threaded_tool()
def get_memory_regions(max: int = 100, protection: str = "", refresh: bool = False) -> str:
    """List committed, readable memory regions. Optional filter like '+X', '+W-C'."""
    params: dict = {"max": _clamp_int(max, 1, 5000)}
    if protection:
        params["protection"] = protection
    if refresh:
        params["refresh"] = True
    return format_result(ce_client.send_command("get_memory_regions", params))

@threaded_tool()
def enum_memory_regions_full(max: int = 500, refresh: bool = False) -> str:
    """Enumerate ALL memory regions in the process (Native EnumMemoryRegions)."""
    params: dict = {"max": _clamp_int(max, 1, 5000)}
    if refresh:
        params["refresh"] = True
    return format_result(ce_client.send_command("enum_memory_regions_full", params))

# --- ANALYSIS & DISASSEMBLY ---

@threaded_tool()
def disassemble(address: str, count: int = 20) -> str:
    """Disassemble instructions starting at an address."""
    return format_result(ce_client.send_command("disassemble", {"address": address, "count": min(max(int(count), 1), 1000)}))

@threaded_tool()
def get_instruction_info(address: str) -> str:
    """Get detailed info about a single instruction (size, bytes, opcode)."""
    return format_result(ce_client.send_command("get_instruction_info", {"address": address}))

@threaded_tool()
def find_function_boundaries(address: str, max_search: int = 4096) -> str:
    """Attempt to find the start and end of a function containing the address."""
    return format_result(ce_client.send_command("find_function_boundaries", {
        "address": address,
        "max_search": _clamp_int(max_search, 0, 1048576),
    }))

@threaded_tool()
def analyze_function(address: str, max_instructions: int = 2000, max_bytes: int = 0x2000) -> str:
    """Analyze a function and list the CALL instructions it makes (direct and indirect)."""
    return format_result(ce_client.send_command("analyze_function", {
        "address": address,
        "max_instructions": min(max(int(max_instructions), 1), 20000),
        "max_bytes": min(max(int(max_bytes), 0x100), 0x10000),
    }))

@threaded_tool()
def find_references(
    address: str,
    limit: int = 50,
    start_address: str = "",
    size: int = 0,
    max_scan: int = MAX_SCAN_BUDGET,
    time_budget_ms: int = 1500,
    max_windows: int = 1,
    timeout_ms: int = 30000,
) -> str:
    """Find instructions whose bytes embed this address (executable regions only).

    Raise max_windows (up to 64) to cover more than one 200,000-address window per call.
    """
    params = {
        "address": address,
        "limit": min(max(int(limit), 1), 1000),
        "max_scan": _clamp_scan_budget(max_scan),
        "time_budget_ms": min(max(int(time_budget_ms), 100), 10000),
        "max_windows": min(max(int(max_windows), 1), 64),
        "protection": "+X",
    }
    if start_address:
        params["start_address"] = start_address
    if size:
        params["size"] = _clamp_scan_budget(size)
    return format_result(ce_client.send_command("find_references", params, timeout_ms=min(max(int(timeout_ms), 1000), 60000), max_retries=1))

@threaded_tool()
def find_call_references(
    function_address: str,
    start_address: str = "",
    size: int = 0,
    limit: int = 20,
    max_scan: int = MAX_SCAN_BUDGET,
    time_budget_ms: int = 1500,
    max_windows: int = 1,
    timeout_ms: int = 30000,
) -> str:
    """Find CALL references inside capped executable scan windows.

    Raise max_windows (up to 64) to cover more than one 200,000-address window per call.
    """
    params = {
        "address": function_address,
        "limit": min(max(int(limit), 1), 50),
        "max_scan": _clamp_scan_budget(max_scan),
        "time_budget_ms": min(max(int(time_budget_ms), 100), 10000),
        "max_windows": min(max(int(max_windows), 1), 64),
        "protection": "+X",
    }
    if start_address:
        params["start_address"] = start_address
    if size:
        params["size"] = _clamp_scan_budget(size)
    return format_result(ce_client.send_command("find_call_references", params, timeout_ms=min(max(int(timeout_ms), 1000), 60000), max_retries=1))

@threaded_tool()
def dissect_structure(address: str, size: int = 256) -> str:
    """Use CE's auto-guess feature to interpret memory at address as a structure."""
    return format_result(ce_client.send_command("dissect_structure", {"address": address, "size": min(max(int(size), 1), 65536)}))

# --- DEBUGGING & BREAKPOINTS ---

@threaded_tool()
def set_breakpoint(
    address: str,
    id: str | None = None,
    capture_registers: bool = True,
    capture_stack: bool = False,
    stack_depth: int = 16,
    one_shot: bool = True,
    max_hits: int | None = None,
    max_triggers: int = 256,
    conditions: list[dict] | None = None,
) -> str:
    """Set a bounded hardware execution breakpoint that immediately resumes the target.

    Requires status.debugger_started=True: start debugging directly in CE first.
    MCP does not auto-start the debugger; attachment can block CE's main thread.

    The safe default is one-shot. Conditions are ANDed and evaluated before expensive
    register/stack capture. Supported condition kinds are:
    - register: {"kind":"register","register":"R8","operator":"in","values":[42,123]}
    - memory: {"kind":"memory","base_register":"RDX","offset":0,"size":1,
               "operator":"eq","value":1}
    Operators: eq, ne, lt, le, gt, ge, in, mask_eq. max_triggers counts all debugger
    events, including condition misses, and automatically removes a never-matching
    breakpoint. This still causes a brief debugger stop per trigger; do not use an
    unbounded persistent breakpoint on a high-frequency function.
    """
    params = {
        "address": address,
        "id": id,
        "capture_registers": capture_registers,
        "capture_stack": capture_stack,
        "stack_depth": stack_depth,
        "one_shot": one_shot,
        "max_triggers": max_triggers,
        "conditions": conditions or [],
    }
    if max_hits is not None:
        params["max_hits"] = max_hits
    return format_result(ce_client.send_command("set_breakpoint", params, timeout_ms=CE_BREAKPOINT_TIMEOUT_MS, max_retries=1))

@threaded_tool()
def set_data_breakpoint(
    address: str,
    id: str | None = None,
    access_type: str = "w",
    size: int = 4,
    capture_registers: bool = True,
    capture_stack: bool = False,
    stack_depth: int = 16,
    one_shot: bool = True,
    max_hits: int | None = None,
    max_triggers: int = 256,
    conditions: list[dict] | None = None,
) -> str:
    """Set a bounded hardware data breakpoint. Types: 'r', 'w', or 'rw'.

    Requires status.debugger_started=True: start debugging directly in CE first.

    The same condition, one-shot, hit-limit and trigger-cap controls as set_breakpoint
    apply. x86 debug registers have no read-only condition, so 'r' also fires on writes.
    """
    params = {
        "address": address,
        "id": id,
        "access_type": access_type,
        "size": size,
        "capture_registers": capture_registers,
        "capture_stack": capture_stack,
        "stack_depth": stack_depth,
        "one_shot": one_shot,
        "max_triggers": max_triggers,
        "conditions": conditions or [],
    }
    if max_hits is not None:
        params["max_hits"] = max_hits
    return format_result(ce_client.send_command("set_data_breakpoint", params, timeout_ms=CE_BREAKPOINT_TIMEOUT_MS, max_retries=1))

@threaded_tool()
def remove_breakpoint(id: str) -> str:
    """Remove a breakpoint by its ID."""
    return format_result(ce_client.send_command("remove_breakpoint", {"id": id}))

@threaded_tool()
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return format_result(ce_client.send_command("list_breakpoints"))

@threaded_tool()
def clear_all_breakpoints() -> str:
    """Remove ALL breakpoints."""
    return format_result(ce_client.send_command("clear_all_breakpoints"))

@threaded_tool()
def get_breakpoint_hits(id: str | None = None, clear: bool = False) -> str:
    """Get hits and final auto-retirement state for one breakpoint (or all hits if None).

    Set clear=True to flush the hit buffer. One-shot and bounded breakpoints retain
    their completed metadata and hits after releasing the hardware slot.
    """
    return format_result(ce_client.send_command("get_breakpoint_hits", {"id": id, "clear": clear}))

# --- DBVM / HYPERVISOR TOOLS (Ring -1) ---

@threaded_tool()
def get_physical_address(address: str) -> str:
    """Translate Virtual Address to Physical Address (requires DBVM)."""
    return format_result(ce_client.send_command("get_physical_address", {"address": address}))

@threaded_tool()
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start invisible DBVM hypervisor watch. Modes: 'w' (writes), 'r' (reads), 'x' (execute)."""
    return format_result(ce_client.send_command("start_dbvm_watch", {
        "address": address,
        "mode": mode,
        "max_entries": _clamp_int(max_entries, 1, 100000),
    }))

@threaded_tool()
def stop_dbvm_watch(address: str) -> str:
    """Stop DBVM watch and return results."""
    return format_result(ce_client.send_command("stop_dbvm_watch", {"address": address}))

@threaded_tool()
def poll_dbvm_watch(address: str, max_results: int = 1000, clear: bool = True) -> str:
    """Poll DBVM watch logs WITHOUT stopping. Set clear=False to request sticky logs between polls."""
    return format_result(ce_client.send_command("poll_dbvm_watch", {
        "address": address,
        "max_results": _clamp_int(max_results, 1, 10000),
        "clear": clear,
    }))

# --- SCRIPTING & CONTROL ---

@threaded_tool()
def evaluate_lua(code: str, structured: bool = False) -> str:
    """Execute arbitrary Lua code in Cheat Engine. Set structured=True to preserve table results."""
    return format_result(ce_client.send_command("evaluate_lua", {"code": code, "serialize_result": structured}))

@threaded_tool()
def auto_assemble(script: str = "", id: str = "last", disable: bool = False) -> str:
    """Run an AutoAssembler script (injection, code caves, etc).

    The [ENABLE] run is stored under `id` so it can be reverted later: call again with
    disable=True and the same id to execute the script's [DISABLE] section, freeing
    allocations and restoring the original bytes.
    """
    params: dict = {"id": id, "disable": bool(disable)}
    if not disable:
        if not script:
            return format_result({"success": False, "error": "script is required unless disable=True"})
        params["script"] = script
    return format_result(ce_client.send_command("auto_assemble", params))

@threaded_tool()
def evaluate_lua_file(file_path: str, encoding: str = "auto", structured: bool = False) -> str:
    """Load Lua code from a local file and execute it in Cheat Engine."""
    code, used_encoding, resolved_path = _read_text_file_robust(file_path, encoding)
    result = ce_client.send_command("evaluate_lua", {"code": code, "serialize_result": structured})
    return format_result(_attach_source_metadata(result, resolved_path, used_encoding, len(code)))

@threaded_tool()
def auto_assemble_file(file_path: str, encoding: str = "auto", id: str = "last") -> str:
    """Load an AutoAssembler script from a local file and execute it."""
    script, used_encoding, resolved_path = _read_text_file_robust(file_path, encoding)
    result = ce_client.send_command("auto_assemble", {"script": script, "id": id, "disable": False})
    return format_result(_attach_source_metadata(result, resolved_path, used_encoding, len(script)))

@threaded_tool()
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(ce_client.send_command("ping"))

@threaded_tool()
def status() -> str:
    """Full bridge state: attached process, architecture, DBK/DBVM availability,
    active and completed bounded breakpoints, DBVM watches, stored AutoAssembler
    scripts, and whether scan results are available. Start troubleshooting here."""
    result = ce_client.send_command("status")
    if isinstance(result, dict):
        result = dict(result)
        result["mcp_client"] = {
            "pipe": PIPE_NAME,
            "idle_disconnect_ms": CE_IDLE_DISCONNECT_MS,
            "timeout_ms": CE_READ_TIMEOUT_MS,
            "lock_timeout_ms": CE_LOCK_TIMEOUT_MS,
            "auth_configured": bool(CE_AUTH_TOKEN),
        }
    return format_result(result)

@threaded_tool()
def cleanup() -> str:
    """Release all breakpoints, DBVM watches and scan objects held by the bridge,
    without reloading the Lua script in Cheat Engine. AutoAssembler scripts are left
    alone - revert those with auto_assemble(disable=True)."""
    return format_result(ce_client.send_command("cleanup"))

@threaded_tool()
def disconnect() -> str:
    """Close this MCP server's CE named-pipe handle right away.

    Normally unnecessary: the handle is released automatically after
    CE_MCP_IDLE_DISCONNECT_MS of inactivity (default 3s) and the next tool call
    reconnects. Call it only to hand CE to another client immediately."""
    ce_client.disconnect()
    return format_result({
        "success": True,
        "message": "CE MCP client handle closed",
        "pipe": PIPE_NAME,
        "idle_disconnect_ms": CE_IDLE_DISCONNECT_MS,
    })

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v11/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
