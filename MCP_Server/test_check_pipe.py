"""Offline and isolated-pipe tests for check_pipe.py (no Cheat Engine required)."""

import ast
import io
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

MCP_SERVER_DIR = str(Path(__file__).resolve().parent)
if MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, MCP_SERVER_DIR)

import check_pipe


def _make_pipe(name, out_buf=4096, in_buf=4096):
    return check_pipe.win32pipe.CreateNamedPipe(
        name,
        check_pipe.win32pipe.PIPE_ACCESS_DUPLEX,
        check_pipe.win32pipe.PIPE_TYPE_BYTE | check_pipe.win32pipe.PIPE_WAIT,
        1,
        out_buf,
        in_buf,
        0,
        None,
    )


def _accept_pipe(pipe):
    try:
        check_pipe.win32pipe.ConnectNamedPipe(pipe, None)
    except check_pipe.pywintypes.error as exc:
        if exc.winerror != 535:  # ERROR_PIPE_CONNECTED
            raise


def _pipe_read_exact(pipe, size):
    chunks = []
    got = 0
    while got < size:
        _, data = check_pipe.win32file.ReadFile(pipe, size - got)
        if not data:
            raise EOFError("pipe closed")
        chunks.append(data)
        got += len(data)
    return b"".join(chunks)


def _pipe_write_framed(pipe, body_bytes, chunk_size=None):
    frame = struct.pack("<I", len(body_bytes)) + body_bytes
    if not chunk_size:
        check_pipe.win32file.WriteFile(pipe, frame)
        return
    for offset in range(0, len(frame), chunk_size):
        check_pipe.win32file.WriteFile(pipe, frame[offset : offset + chunk_size])


class CheckPipeDependencyAndCliTests(unittest.TestCase):
    def test_zero_mcp_dependency(self):
        source = Path(MCP_SERVER_DIR, "check_pipe.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("mcp", imported)

    def test_normalize_pipe_name_arg_env_and_full_path(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                check_pipe.normalize_pipe_name(None),
                r"\\.\pipe\CE_MCP_Bridge_v99",
            )
            self.assertEqual(
                check_pipe.normalize_pipe_name("custom_bridge"),
                r"\\.\pipe\custom_bridge",
            )
            self.assertEqual(
                check_pipe.normalize_pipe_name(r"\\.\pipe\full_path_pipe"),
                r"\\.\pipe\full_path_pipe",
            )

        with patch.dict(os.environ, {"CE_MCP_PIPE_NAME": "CE_MCP_Bridge_env"}, clear=True):
            self.assertEqual(
                check_pipe.normalize_pipe_name(None),
                r"\\.\pipe\CE_MCP_Bridge_env",
            )
            self.assertEqual(
                check_pipe.normalize_pipe_name(""),
                r"\\.\pipe\CE_MCP_Bridge_env",
            )
            self.assertEqual(
                check_pipe.normalize_pipe_name("arg_overrides_env"),
                r"\\.\pipe\arg_overrides_env",
            )

        with patch.dict(os.environ, {"CE_MCP_PIPE_NAME": r"\\.\pipe\env_full"}, clear=True):
            self.assertEqual(
                check_pipe.normalize_pipe_name(None),
                r"\\.\pipe\env_full",
            )

    def test_parse_args_timeout_default_and_minimum(self):
        default_args = check_pipe.parse_args([])
        self.assertEqual(default_args.timeout_ms, 15000)

        clamped_args = check_pipe.parse_args(["--timeout-ms", "200"])
        self.assertEqual(clamped_args.timeout_ms, 1000)

        custom_args = check_pipe.parse_args(["--timeout-ms", "30000"])
        self.assertEqual(custom_args.timeout_ms, 30000)


class PipeClientConnectTests(unittest.TestCase):
    def test_connect_rides_out_transient_file_not_found(self):
        client = check_pipe.PipeClient(r"\\.\pipe\CE_MCP_mock_gap", connect_wait_ms=1000)
        fake_handle = object()
        missing = check_pipe.pywintypes.error(
            check_pipe.ERROR_FILE_NOT_FOUND, "CreateFile", "not found"
        )
        with patch.object(
            check_pipe.win32file,
            "CreateFile",
            side_effect=[missing, missing, fake_handle],
        ) as create_file, patch.object(check_pipe.time, "sleep") as sleep_mock:
            self.assertTrue(client.connect())
        self.assertIs(client.handle, fake_handle)
        self.assertEqual(create_file.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 2)
        flags = create_file.call_args[0][5]
        self.assertEqual(flags, check_pipe.win32con.FILE_FLAG_OVERLAPPED)

    def test_connect_rides_out_transient_pipe_busy(self):
        client = check_pipe.PipeClient(r"\\.\pipe\CE_MCP_mock_busy", connect_wait_ms=2500)
        fake_handle = object()
        busy = check_pipe.pywintypes.error(
            check_pipe.ERROR_PIPE_BUSY, "CreateFile", "all pipe instances are busy"
        )
        with patch.object(
            check_pipe.win32file,
            "CreateFile",
            side_effect=[busy, fake_handle],
        ) as create_file, patch.object(check_pipe.win32pipe, "WaitNamedPipe") as wait_pipe:
            self.assertTrue(client.connect())
        self.assertIs(client.handle, fake_handle)
        self.assertEqual(create_file.call_count, 2)
        wait_pipe.assert_called_once()
        self.assertEqual(wait_pipe.call_args[0][0], r"\\.\pipe\CE_MCP_mock_busy")
        self.assertLessEqual(wait_pipe.call_args[0][1], 1000)
        self.assertGreater(wait_pipe.call_args[0][1], 0)

    def test_connect_real_pipe_busy_and_recreation_gap(self):
        name = rf"\\.\pipe\CE_MCP_check_gap_{os.getpid()}_{time.monotonic_ns()}"
        pipe = _make_pipe(name)
        first = check_pipe.PipeClient(name, connect_wait_ms=500)
        second = check_pipe.PipeClient(name, connect_wait_ms=1000)
        recreated = []
        try:
            self.assertTrue(first.connect())

            busy_client = check_pipe.PipeClient(name, connect_wait_ms=150)
            self.assertFalse(busy_client.connect())
            self.assertIsNotNone(busy_client.last_connect_error)
            self.assertIn("busy", busy_client.last_connect_error.lower())

            first.close()
            check_pipe.win32file.CloseHandle(pipe)
            pipe = None

            def recreate():
                time.sleep(0.12)
                recreated.append(_make_pipe(name))

            thread = threading.Thread(target=recreate)
            thread.start()
            try:
                self.assertTrue(second.connect(), second.last_connect_error)
            finally:
                thread.join(timeout=2)
                if recreated:
                    pipe = recreated[0]
        finally:
            first.close()
            second.close()
            if pipe is not None:
                check_pipe.win32file.CloseHandle(pipe)

    def test_connect_missing_pipe_and_unexpected_error_report_cleanly(self):
        missing_client = check_pipe.PipeClient(
            r"\\.\pipe\CE_MCP_does_not_exist_check_pipe",
            connect_wait_ms=150,
        )
        started = time.monotonic()
        self.assertFalse(missing_client.connect())
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIsNotNone(missing_client.last_connect_error)
        self.assertIn("does not exist", missing_client.last_connect_error)

        denied = check_pipe.pywintypes.error(5, "CreateFile", "access denied")
        err_client = check_pipe.PipeClient(r"\\.\pipe\CE_MCP_denied", connect_wait_ms=100)
        with patch.object(check_pipe.win32file, "CreateFile", side_effect=denied), patch.object(
            check_pipe.time, "sleep"
        ):
            self.assertFalse(err_client.connect())
        self.assertIsNotNone(err_client.last_connect_error)
        self.assertIn("CreateFile failed", err_client.last_connect_error)


class PipeClientRoundTripTests(unittest.TestCase):
    def test_real_pipe_small_and_multichunk_over_64kb_roundtrip(self):
        name = rf"\\.\pipe\CE_MCP_rt_{os.getpid()}_{time.monotonic_ns()}"
        pipe = _make_pipe(name, out_buf=4096, in_buf=4096)
        client = check_pipe.PipeClient(name, connect_wait_ms=1000, timeout_ms=5000)
        observed_requests = []
        server_errors = []

        def serve():
            try:
                _accept_pipe(pipe)
                for idx in range(2):
                    hdr = _pipe_read_exact(pipe, 4)
                    req_len = struct.unpack("<I", hdr)[0]
                    raw_req = _pipe_read_exact(pipe, req_len)
                    observed_requests.append(raw_req)
                    req = json.loads(raw_req.decode("utf-8"))
                    if idx == 0:
                        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True}}
                        _pipe_write_framed(pipe, json.dumps(resp).encode("utf-8"))
                    else:
                        big_blob = "X" * 96 * 1024  # > 64 KB response
                        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"blob": big_blob}}
                        _pipe_write_framed(
                            pipe,
                            json.dumps(resp).encode("utf-8"),
                            chunk_size=8192,
                        )
            except Exception as exc:
                server_errors.append(exc)

        thread = threading.Thread(target=serve)
        try:
            self.assertTrue(client.connect(), client.last_connect_error)
            thread.start()

            with patch.object(
                check_pipe.win32event,
                "CreateEvent",
                wraps=check_pipe.win32event.CreateEvent,
            ) as create_event:
                res1 = client.call("ping")
                res2 = client.call("big_payload", {"count": 1})

            self.assertEqual(res1, {"ok": True})
            self.assertEqual(len(res2["blob"]), 96 * 1024)
            self.assertEqual(res2["blob"], "X" * 96 * 1024)
            # Reused Win32 event handle across write + read calls.
            self.assertEqual(create_event.call_count, 1)
            # Compact JSON separators (",", ":").
            self.assertNotIn(b": ", observed_requests[0])
            self.assertNotIn(b", ", observed_requests[0])
        finally:
            client.close()
            thread.join(timeout=2)
            check_pipe.win32file.CloseHandle(pipe)
        self.assertEqual(server_errors, [])

    def test_partial_write_loops_until_all_bytes_sent(self):
        client = check_pipe.PipeClient(r"\\.\pipe\CE_MCP_partial_write")
        client.handle = object()
        payload = b"0123456789"
        writes = []

        def fake_write(_handle, chunk, _overlapped):
            writes.append(bytes(chunk))
            return (0, 0)

        with patch.object(check_pipe.win32file, "WriteFile", side_effect=fake_write), patch.object(
            check_pipe.win32event,
            "WaitForSingleObject",
            return_value=check_pipe.win32con.WAIT_OBJECT_0,
        ), patch.object(
            check_pipe.win32file,
            "GetOverlappedResult",
            side_effect=[3, 4, 3],
        ):
            client._write_exact(payload, timeout_ms=1000)

        self.assertEqual(writes, [b"0123456789", b"3456789", b"789"])
        client._discard_io_event()

    def test_real_pipe_read_timeout_cancels_then_recovers(self):
        name = rf"\\.\pipe\CE_MCP_to_{os.getpid()}_{time.monotonic_ns()}"
        pipe = _make_pipe(name)
        client = check_pipe.PipeClient(name, connect_wait_ms=1000, timeout_ms=1000)
        try:
            self.assertTrue(client.connect(), client.last_connect_error)
            _accept_pipe(pipe)

            with self.assertRaises(TimeoutError):
                client._read_exact(4, timeout_ms=30)

            check_pipe.win32file.WriteFile(pipe, b"test")
            self.assertEqual(client._read_exact(4, timeout_ms=1000), b"test")
        finally:
            client.close()
            check_pipe.win32file.CloseHandle(pipe)

    def test_timeout_cancels_and_drains_before_closing_event(self):
        client = check_pipe.PipeClient(r"\\.\pipe\CE_MCP_drain")
        client.handle = object()
        events = []

        def cancelled(*args):
            self.assertIs(args[2], True)
            events.append("completed")
            raise check_pipe.pywintypes.error(995, "GetOverlappedResult", "aborted")

        with patch.object(check_pipe.win32file, "ReadFile"), patch.object(
            check_pipe.win32event,
            "WaitForSingleObject",
            return_value=check_pipe.win32con.WAIT_TIMEOUT,
        ), patch.object(
            check_pipe.win32file,
            "CancelIo",
            side_effect=lambda *_: events.append("cancel"),
        ), patch.object(
            check_pipe.win32file,
            "GetOverlappedResult",
            side_effect=cancelled,
        ), patch.object(
            check_pipe.win32api,
            "CloseHandle",
            side_effect=lambda handle: (events.append("closed"), handle.Close()),
        ):
            with self.assertRaises(TimeoutError):
                client._read_exact(4, timeout_ms=1000)
        self.assertEqual(events, ["cancel", "completed", "closed"])

    def test_zero_length_response_rejected(self):
        name = rf"\\.\pipe\CE_MCP_zero_{os.getpid()}_{time.monotonic_ns()}"
        pipe = _make_pipe(name)
        client = check_pipe.PipeClient(name, connect_wait_ms=1000, timeout_ms=2000)
        server_errors = []

        def serve():
            try:
                _accept_pipe(pipe)
                req_len = struct.unpack("<I", _pipe_read_exact(pipe, 4))[0]
                _pipe_read_exact(pipe, req_len)
                check_pipe.win32file.WriteFile(pipe, struct.pack("<I", 0))
            except Exception as exc:
                server_errors.append(exc)

        thread = threading.Thread(target=serve)
        try:
            self.assertTrue(client.connect(), client.last_connect_error)
            thread.start()
            with self.assertRaisesRegex(ConnectionError, "Empty response"):
                client.call("ping")
        finally:
            client.close()
            thread.join(timeout=2)
            check_pipe.win32file.CloseHandle(pipe)
        self.assertEqual(server_errors, [])

    def test_mismatched_response_id_and_non_dict_rejected(self):
        for payload, pattern in (
            (b'{"jsonrpc":"2.0","id":999,"result":{"ok":true}}', "Mismatched response id"),
            (b"[1,2,3]", "expected object"),
        ):
            with self.subTest(pattern=pattern):
                name = rf"\\.\pipe\CE_MCP_bad_{os.getpid()}_{time.monotonic_ns()}"
                pipe = _make_pipe(name)
                client = check_pipe.PipeClient(name, connect_wait_ms=1000, timeout_ms=2000)
                server_errors = []

                def serve(body=payload):
                    try:
                        _accept_pipe(pipe)
                        req_len = struct.unpack("<I", _pipe_read_exact(pipe, 4))[0]
                        _pipe_read_exact(pipe, req_len)
                        _pipe_write_framed(pipe, body)
                    except Exception as exc:
                        server_errors.append(exc)

                thread = threading.Thread(target=serve)
                try:
                    self.assertTrue(client.connect(), client.last_connect_error)
                    thread.start()
                    with self.assertRaisesRegex(ConnectionError, pattern):
                        client.call("ping")
                finally:
                    client.close()
                    thread.join(timeout=2)
                    check_pipe.win32file.CloseHandle(pipe)
                self.assertEqual(server_errors, [])

    def test_oversized_response_rejected_and_null_id_error_vs_result(self):
        name = rf"\\.\pipe\CE_MCP_len_{os.getpid()}_{time.monotonic_ns()}"
        pipe = _make_pipe(name)
        client = check_pipe.PipeClient(name, connect_wait_ms=1000, timeout_ms=2000, auth_token="tok-123")
        server_errors = []
        seen_tokens = []

        def serve():
            try:
                _accept_pipe(pipe)
                # 1. JSON-RPC error with id=null is accepted and surfaces RuntimeError
                req_len = struct.unpack("<I", _pipe_read_exact(pipe, 4))[0]
                req1 = json.loads(_pipe_read_exact(pipe, req_len).decode("utf-8"))
                seen_tokens.append(req1.get("auth_token"))
                _pipe_write_framed(pipe, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}')

                # 2. Oversized length rejected
                req_len = struct.unpack("<I", _pipe_read_exact(pipe, 4))[0]
                _pipe_read_exact(pipe, req_len)
                check_pipe.win32file.WriteFile(
                    pipe, struct.pack("<I", check_pipe.MAX_RESPONSE_BYTES + 1)
                )
            except Exception as exc:
                server_errors.append(exc)

        thread = threading.Thread(target=serve)
        try:
            self.assertTrue(client.connect(), client.last_connect_error)
            thread.start()
            with self.assertRaisesRegex(RuntimeError, "CE error"):
                client.call("ping")
            with self.assertRaisesRegex(ConnectionError, "too large"):
                client.call("ping")
        finally:
            client.close()
            thread.join(timeout=2)
            check_pipe.win32file.CloseHandle(pipe)
        self.assertEqual(server_errors, [])
        self.assertEqual(seen_tokens, ["tok-123"])

        # 3. Result frame with id=null must be rejected as mismatched id
        name2 = rf"\\.\pipe\CE_MCP_nullid_{os.getpid()}_{time.monotonic_ns()}"
        pipe2 = _make_pipe(name2)
        client2 = check_pipe.PipeClient(name2, connect_wait_ms=1000, timeout_ms=2000)
        server_errors2 = []

        def serve2():
            try:
                _accept_pipe(pipe2)
                req_len = struct.unpack("<I", _pipe_read_exact(pipe2, 4))[0]
                _pipe_read_exact(pipe2, req_len)
                _pipe_write_framed(pipe2, b'{"jsonrpc":"2.0","id":null,"result":{"ok":true}}')
            except Exception as exc:
                server_errors2.append(exc)

        t2 = threading.Thread(target=serve2)
        try:
            self.assertTrue(client2.connect(), client2.last_connect_error)
            t2.start()
            with self.assertRaisesRegex(ConnectionError, "Mismatched response id"):
                client2.call("ping")
        finally:
            client2.close()
            t2.join(timeout=2)
            check_pipe.win32file.CloseHandle(pipe2)
        self.assertEqual(server_errors2, [])


class FileAndSummaryTests(unittest.TestCase):
    def test_read_text_file_decodes_and_enforces_size_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lua_path = Path(tmpdir) / "helper.lua"
            lua_path.write_text("-- 你好世界\nreturn 42\n", encoding="utf-8")

            text, encoding = check_pipe.read_text_file(str(lua_path))
            self.assertIn(encoding, ("utf-8-sig", "utf-8"))
            self.assertIn("return 42", text)

            gbk_path = Path(tmpdir) / "gbk.lua"
            gbk_path.write_bytes("-- 中文编码\nreturn 7\n".encode("gb18030"))
            gbk_text, gbk_enc = check_pipe.read_text_file(str(gbk_path))
            self.assertEqual(gbk_enc, "gb18030")
            self.assertIn("中文编码", gbk_text)

            with patch.object(check_pipe, "MAX_LOCAL_FILE_BYTES", 8):
                with self.assertRaisesRegex(ValueError, "too large"):
                    check_pipe.read_text_file(str(lua_path))

    def test_main_prints_connect_failure_checklist(self):
        stderr = io.StringIO()
        with patch.object(
            check_pipe.PipeClient,
            "connect",
            return_value=False,
        ), patch("sys.stderr", stderr):
            rc = check_pipe.main(["--pipe", "missing_pipe", "--ping"])
        self.assertEqual(rc, 1)
        err_text = stderr.getvalue()
        self.assertIn("FAILED to connect", err_text)
        self.assertIn("Checklist:", err_text)
        self.assertIn("CE_MCP_PIPE_NAME", err_text)

    def test_print_summary_displays_new_bridge_fields(self):
        mock_client = Mock()
        mock_client.call.side_effect = [
            {
                "version": "11.6.3",
                "pipe_name": "CE_MCP_Bridge_v99",
                "worker_running": True,
                "worker_hot_reload": True,
                "idle_kick_ms": 60000,
                "process_id": 1234,
                "process_attached": True,
                "architecture": "x64",
                "debugger_started": True,
                "dbk_loaded": False,
                "dbvm_active": False,
                "hw_breakpoint_slots_used": 1,
                "hw_breakpoint_slots_total": 4,
                "breakpoints": [{"id": "bp1"}],
                "completed_breakpoints": [{"id": "bp_old1"}, {"id": "bp_old2"}],
                "dbvm_watches": [],
                "auto_assemble_scripts": [],
                "scan_results_available": False,
            },
            {
                "process_name": "game.exe",
                "process_name_resolved": True,
                "total_modules": 42,
            },
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            check_pipe.print_summary(mock_client)
        out = buf.getvalue()
        self.assertIn("worker hot reload     : True", out)
        self.assertIn("idle kick ms          : 60000", out)
        self.assertIn("debugger started      : True", out)
        self.assertIn("completed breakpoints : 2", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
