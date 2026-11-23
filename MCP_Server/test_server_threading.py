"""Run with Python unittest or pytest: exercises installed FastMCP, without live CE.

No test attaches to or changes a process.
"""
import asyncio
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

_MCP_SERVER_DIR = str(Path(__file__).resolve().parent)
if _MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, _MCP_SERVER_DIR)

import mcp_cheatengine as server


class ServerThreadingTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_pipe_does_not_block_protocol_loop(self):
        entered = threading.Event()
        release = threading.Event()
        calling_threads = []
        timed_out = []

        def slow_command(*args, **kwargs):
            calling_threads.append(threading.get_ident())
            entered.set()
            if not release.wait(2):
                timed_out.append(True)
            return {"success": True}

        with patch.object(server.ce_client, "send_command", side_effect=slow_command):
            tool = server.mcp._tool_manager.get_tool("set_breakpoint")
            task = asyncio.create_task(tool.run({"address": "0x401000"}))
            try:
                async with asyncio.timeout(1):
                    while not entered.is_set():
                        await asyncio.sleep(0.005)
                # This runs while the registered MCP tool is still waiting for CE.
                self.assertFalse(task.done())
                self.assertNotEqual(calling_threads, [threading.get_ident()])
                listed = await server.mcp.list_tools()
                self.assertTrue(any(t.name == "status" for t in listed))
            finally:
                release.set()
                result = await task
            self.assertFalse(timed_out)
            self.assertTrue(json.loads(result)["success"])

    async def test_tool_schema_and_breakpoint_deadline(self):
        tools = await server.mcp.list_tools()
        self.assertTrue(all(server.mcp._tool_manager.get_tool(t.name).is_async for t in tools))
        bp = next(t for t in tools if t.name == "set_breakpoint")
        self.assertEqual(bp.inputSchema["required"], ["address"])
        self.assertTrue(bp.inputSchema["properties"]["one_shot"]["default"])
        with patch.object(server.ce_client, "send_command", return_value={"success": True}) as send:
            for name in ("set_breakpoint", "set_data_breakpoint"):
                await server.mcp._tool_manager.get_tool(name).run({"address": "0x401000"})
                self.assertEqual(send.call_args.kwargs["timeout_ms"], server.CE_BREAKPOINT_TIMEOUT_MS)
                self.assertEqual(send.call_args.kwargs["max_retries"], 1)

    async def test_transport_error_is_tool_error_and_server_remains_usable(self):
        tool = server.mcp._tool_manager.get_tool("set_breakpoint")
        with patch.object(server.ce_client, "send_command", side_effect=ConnectionError("CE timeout")):
            with self.assertRaisesRegex(Exception, "CE timeout"):
                await tool.run({"address": "0x401000"})
        self.assertGreater(len(await server.mcp.list_tools()), 0)


class PipeSerializationTests(unittest.TestCase):
    def test_real_named_pipe_read_timeout_cancels_then_recovers(self):
        # An isolated pipe with no CE/target process. Hold a response to exercise
        # genuine overlapped cancellation, then read again on the same handle.
        name = rf"\\.\pipe\CE_MCP_test_{os.getpid()}_{time.monotonic_ns()}"
        pipe = server.win32pipe.CreateNamedPipe(
            name, server.win32pipe.PIPE_ACCESS_DUPLEX,
            server.win32pipe.PIPE_TYPE_BYTE | server.win32pipe.PIPE_WAIT,
            1, 4096, 4096, 0, None)
        client = server.CEBridgeClient()
        try:
            client.handle = server.win32file.CreateFile(
                name, server.win32file.GENERIC_READ | server.win32file.GENERIC_WRITE,
                0, None, server.win32file.OPEN_EXISTING,
                server.win32con.FILE_FLAG_OVERLAPPED, None)
            try:
                server.win32pipe.ConnectNamedPipe(pipe, None)
            except server.pywintypes.error as exc:
                if exc.winerror != 535:  # ERROR_PIPE_CONNECTED
                    raise
            with self.assertRaises(TimeoutError):
                client._read(4, timeout_ms=30)
            server.win32file.WriteFile(pipe, b"test")
            self.assertEqual(client._read(4, timeout_ms=1000), b"test")
        finally:
            client.close()
            server.win32file.CloseHandle(pipe)

    def test_timeout_waits_for_cancellation_before_closing_event(self):
        client = server.CEBridgeClient()
        client.handle = object()
        for operation in (lambda: client._read(4, timeout_ms=1000),
                          lambda: client._write(b"test", timeout_ms=1000)):
            events = []
            def cancelled(*args):
                self.assertIs(args[2], True)
                events.append("completed")
                raise server.pywintypes.error(995, "GetOverlappedResult", "aborted")
            with patch.object(server.win32file, "ReadFile"), patch.object(server.win32file, "WriteFile"), patch.object(server.win32event, "WaitForSingleObject", return_value=server.win32con.WAIT_TIMEOUT), patch.object(server.win32file, "CancelIo", side_effect=lambda *_: events.append("cancel")), patch.object(server.win32file, "GetOverlappedResult", side_effect=cancelled), patch.object(server.win32api, "CloseHandle", side_effect=lambda handle: (events.append("closed"), handle.Close())):
                with self.assertRaises(TimeoutError):
                    operation()
            self.assertEqual(events, ["cancel", "completed", "closed"])

    def test_failed_cancel_still_drains_pending_io_before_closing_event(self):
        client = server.CEBridgeClient()
        client.handle = object()
        events = []

        def cancel(_handle):
            events.append("cancel")
            raise server.pywintypes.error(1, "CancelIo", "cancel failed")

        def drain(_handle, _overlapped, wait):
            self.assertTrue(wait)
            events.append("completed")
            return 4

        def close(handle):
            events.append("closed")
            handle.Close()

        with patch.object(server.win32file, "ReadFile"), \
             patch.object(server.win32event, "WaitForSingleObject", return_value=server.win32con.WAIT_TIMEOUT), \
             patch.object(server.win32file, "CancelIo", side_effect=cancel), \
             patch.object(server.win32file, "GetOverlappedResult", side_effect=drain), \
             patch.object(server.win32api, "CloseHandle", side_effect=close):
            with self.assertRaisesRegex(server.pywintypes.error, "cancel failed"):
                client._read(4, timeout_ms=1000)
        self.assertEqual(events, ["cancel", "completed", "closed"])

    def test_busy_command_and_disconnect_do_not_touch_handle(self):
        client = server.CEBridgeClient()
        with patch.object(server, "CE_LOCK_TIMEOUT_MS", 20), patch.object(client, "connect") as connect, patch.object(client, "close") as close:
            client._lock.acquire()
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(ConnectionError, "not sent"):
                    client.send_command("status")
                with self.assertRaisesRegex(ConnectionError, "not sent"):
                    client.disconnect()
                self.assertLess(time.monotonic() - start, 1)
                connect.assert_not_called()
                close.assert_not_called()
            finally:
                client._lock.release()
            client.disconnect()
            close.assert_called_once()

    def test_delivered_breakpoint_is_not_retried_after_timeout(self):
        client = server.CEBridgeClient()
        client.handle = object()
        with patch.object(client, "_write") as write, patch.object(client, "_read", side_effect=TimeoutError("no response")), patch.object(client, "close"):
            with self.assertRaisesRegex(ConnectionError, "not safe to retry"):
                client.send_command("set_breakpoint", {"address": "0x401000"})
            self.assertEqual(write.call_count, 1)  # combined header + body
        self.assertTrue(client._lock.acquire(blocking=False))
        client._lock.release()

    def test_queue_wait_is_capped_by_the_total_budget(self):
        client = server.CEBridgeClient()
        client._lock = Mock()
        client._lock.acquire.return_value = False
        with patch.object(server.time, "monotonic", return_value=0.0), \
             patch.object(server, "CE_LOCK_TIMEOUT_MS", 15000), \
             patch.object(client, "connect") as connect:
            with self.assertRaisesRegex(ConnectionError, "not sent"):
                client.send_command("status", timeout_ms=20)
        client._lock.acquire.assert_called_once_with(timeout=0.02)
        client._lock.release.assert_not_called()
        connect.assert_not_called()

    def test_request_stages_and_retry_share_one_deadline(self):
        client = server.CEBridgeClient()
        now = 10.0
        stages = []
        body = b'{"jsonrpc":"2.0","id":2,"result":{"success":true}}'
        client._lock = Mock()

        def step(stage, deadline=11.0):
            nonlocal now
            self.assertEqual(deadline, 11.0)
            self.assertLess(now, deadline)
            stages.append(stage)
            now += 0.125

        def acquire(*, timeout):
            self.assertEqual(timeout, 1.0)
            step("queue")
            return True

        def connect(*, deadline):
            step("connect", deadline)
            client.handle = object()
            return True

        def write(_data, *, deadline):
            step("write", deadline)

        def read(size, *, deadline):
            step("header" if size == 4 else "body", deadline)
            if client._next_request_id == 1:
                raise ConnectionError("pipe disconnected")
            return len(body).to_bytes(4, "little") if size == 4 else body

        client._lock.acquire.side_effect = acquire
        with patch.object(server.time, "monotonic", side_effect=lambda: now), \
             patch.object(server, "CE_IDLE_DISCONNECT_MS", -1), \
             patch.object(client, "connect", side_effect=connect), \
             patch.object(client, "_write", side_effect=write), \
             patch.object(client, "_read", side_effect=read), \
             patch.object(client, "close", side_effect=lambda: setattr(client, "handle", None)):
            self.assertEqual(client.send_command("status", timeout_ms=1000), {"success": True})
        self.assertEqual(stages, ["queue", "connect", "write", "header",
                                  "connect", "write", "header", "body"])
        self.assertEqual(now, 11.0)

    def test_connection_stops_when_remaining_request_budget_is_spent(self):
        client = server.CEBridgeClient()
        now = 0.0

        def wait_on_busy_pipe(_name, duration_ms):
            nonlocal now
            self.assertEqual(duration_ms, 25)
            now += duration_ms / 1000

        busy = server.pywintypes.error(server.ERROR_PIPE_BUSY, "CreateFile", "busy")
        with patch.object(server.time, "monotonic", side_effect=lambda: now), \
             patch.object(server.win32file, "CreateFile", side_effect=busy) as create, \
             patch.object(server.win32pipe, "WaitNamedPipe", side_effect=wait_on_busy_pipe) as wait:
            with self.assertRaisesRegex(ConnectionError, "another MCP client"):
                client.send_command("status", timeout_ms=25)
        self.assertEqual(now, 0.025)
        self.assertEqual(create.call_count, 1)
        self.assertEqual(wait.call_count, 1)

    def test_readonly_retry_stops_when_the_deadline_has_elapsed(self):
        client = server.CEBridgeClient()
        client.handle = object()
        now = 0.0

        def timeout_after_pipe_wait(_size, *, deadline):
            nonlocal now
            now = deadline
            raise TimeoutError("no response")

        with patch.object(server.time, "monotonic", side_effect=lambda: now), \
             patch.object(client, "_write") as write, \
             patch.object(client, "_read", side_effect=timeout_after_pipe_wait), \
             patch.object(client, "connect") as connect, \
             patch.object(client, "close", side_effect=lambda: setattr(client, "handle", None)):
            with self.assertRaisesRegex(ConnectionError, "no response"):
                client.send_command("status", timeout_ms=35)
        self.assertEqual(now, 0.035)
        write.assert_called_once()
        connect.assert_not_called()

    def test_ambiguous_write_failure_does_not_replay_side_effecting_request(self):
        for method, params in (("set_breakpoint", {"address": "0x401000"}),
                               ("get_process_info", {"refresh_symbols": True})):
            with self.subTest(method=method):
                client = server.CEBridgeClient()
                client.handle = object()
                with patch.object(client, "_write", side_effect=TimeoutError("write completion uncertain")) as write, \
                     patch.object(client, "_read") as read, \
                     patch.object(client, "connect") as connect, \
                     patch.object(client, "close", side_effect=lambda: setattr(client, "handle", None)):
                    with self.assertRaisesRegex(ConnectionError, "may have reached CE"):
                        client.send_command(method, params)
                write.assert_called_once()
                read.assert_not_called()
                connect.assert_not_called()

    def test_io_event_is_reused_across_multiple_pipe_roundtrips(self):
        name = rf"\\.\pipe\CE_MCP_reuse_{os.getpid()}_{time.monotonic_ns()}"
        pipe = server.win32pipe.CreateNamedPipe(
            name, server.win32pipe.PIPE_ACCESS_DUPLEX,
            server.win32pipe.PIPE_TYPE_BYTE | server.win32pipe.PIPE_WAIT,
            1, 4096, 4096, 0, None)
        client = server.CEBridgeClient()
        try:
            client.handle = server.win32file.CreateFile(
                name, server.win32file.GENERIC_READ | server.win32file.GENERIC_WRITE,
                0, None, server.win32file.OPEN_EXISTING,
                server.win32con.FILE_FLAG_OVERLAPPED, None)
            try:
                server.win32pipe.ConnectNamedPipe(pipe, None)
            except server.pywintypes.error as exc:
                if exc.winerror != 535:
                    raise

            with patch.object(server.win32event, "CreateEvent", wraps=server.win32event.CreateEvent) as create_ev:
                for payload in (b"ping", b"pong", b"done"):
                    client._write(payload, timeout_ms=1000)
                    _, got = server.win32file.ReadFile(pipe, len(payload))
                    self.assertEqual(got, payload)
                    server.win32file.WriteFile(pipe, payload)
                    self.assertEqual(client._read(len(payload), timeout_ms=1000), payload)
                self.assertEqual(create_ev.call_count, 1)
        finally:
            client.close()
            server.win32file.CloseHandle(pipe)

    def test_parallel_commands_serialize_without_failing_fast(self):
        client = server.CEBridgeClient()
        self.assertGreaterEqual(server.CE_LOCK_TIMEOUT_MS, 15000)
        entered_first = threading.Event()
        release_first = threading.Event()
        results = []

        def slow_first():
            with client.command_lock():
                entered_first.set()
                release_first.wait(1)
                results.append("first")

        def second():
            entered_first.wait(1)
            with client.command_lock():
                results.append("second")

        t1 = threading.Thread(target=slow_first)
        t2 = threading.Thread(target=second)
        t1.start()
        t2.start()
        time.sleep(0.15)
        release_first.set()
        t1.join(2)
        t2.join(2)
        self.assertEqual(results, ["first", "second"])


class IdleReleaseTests(unittest.TestCase):
    """CE serves one pipe client; an idle handle must not lock out other AI sessions."""

    def _make_single_instance_pipe(self):
        name = rf"\\.\pipe\CE_MCP_idle_{os.getpid()}_{time.monotonic_ns()}"
        return name, self._make_pipe_named(name)

    def test_idle_handle_is_released_so_second_client_can_connect(self):
        name, pipe = self._make_single_instance_pipe()
        first, second = server.CEBridgeClient(), server.CEBridgeClient()
        try:
            with patch.object(server, "PIPE_NAME", name), \
                 patch.object(server, "CE_IDLE_DISCONNECT_MS", 100), \
                 patch.object(server, "CE_CONNECT_WAIT_MS", 400), \
                 patch.object(server, "CE_CONNECT_RETRIES", 1):
                with first.command_lock():
                    self.assertTrue(first.connect())
                # The only instance is taken: a second AI session is locked out.
                self.assertFalse(second.connect())
                self.assertIn("another MCP client", second.last_connect_error)

                deadline = time.monotonic() + 2
                while first.handle and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertIsNone(first.handle, "idle handle was never released")

                # CE's worker destroys the instance and recreates it ~50 ms later;
                # the reconnect must ride out that window with no pipe at all.
                server.win32file.CloseHandle(pipe)
                recreated = []
                def recreate():
                    time.sleep(0.15)
                    recreated.append(self._make_pipe_named(name))
                t = threading.Thread(target=recreate)
                t.start()
                self.assertTrue(second.connect(), second.last_connect_error)
                t.join()
                pipe = recreated[0]
        finally:
            first.close()
            second.close()
            server.win32file.CloseHandle(pipe)

    def _make_pipe_named(self, name):
        return server.win32pipe.CreateNamedPipe(
            name, server.win32pipe.PIPE_ACCESS_DUPLEX,
            server.win32pipe.PIPE_TYPE_BYTE | server.win32pipe.PIPE_WAIT,
            1, 4096, 4096, 0, None)

    def test_running_command_is_never_released_mid_flight(self):
        client = server.CEBridgeClient()
        client.handle = object()
        with patch.object(server, "CE_IDLE_DISCONNECT_MS", 50), patch.object(client, "close") as close:
            with client.command_lock():
                client._last_used = time.monotonic() - 10
                client._release_if_idle()          # lock held -> must not close
                close.assert_not_called()
            self.assertIsNotNone(client._idle_deadline)  # re-armed by the finished command
            deadline = time.monotonic() + 1.0
            while close.call_count == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            close.assert_called_once()

    def test_zero_closes_after_each_command_and_negative_keeps_it(self):
        client = server.CEBridgeClient()
        with patch.object(client, "close") as close:
            client.handle = object()
            with patch.object(server, "CE_IDLE_DISCONNECT_MS", 0):
                with client.command_lock():
                    pass
            close.assert_called_once()
            with patch.object(server, "CE_IDLE_DISCONNECT_MS", -1):
                with client.command_lock():
                    pass
            close.assert_called_once()
            self.assertIsNone(client._idle_deadline)

    def test_missing_pipe_fails_fast(self):
        client = server.CEBridgeClient()
        with patch.object(server, "PIPE_NAME", r"\\.\pipe\CE_MCP_does_not_exist_x"), \
             patch.object(server, "CE_PIPE_MISSING_GRACE_MS", 200):
            start = time.monotonic()
            self.assertFalse(client.connect())
            self.assertLess(time.monotonic() - start, 1.5)
            self.assertIn("does not exist", client.last_connect_error)


class HardeningAndValidationTests(unittest.TestCase):
    def test_set_binary_mode_handles_none_and_pseudofiles(self):
        self.assertFalse(server._set_binary_mode(None))
        self.assertFalse(server._set_binary_mode(object()))
        self.assertFalse(server._set_binary_mode(io.StringIO("captured")))

        class BrokenStream:
            def __init__(self, exc):
                self._exc = exc

            def fileno(self):
                raise self._exc

        for exc in (
            io.UnsupportedOperation("pseudofile"),
            OSError("bad fd"),
            ValueError("closed"),
            AttributeError("no fileno"),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertFalse(server._set_binary_mode(BrokenStream(exc)))

        real_like = Mock()
        real_like.fileno.return_value = 7
        with patch.object(server.msvcrt, "setmode") as setmode:
            self.assertTrue(server._set_binary_mode(real_like))
            setmode.assert_called_once_with(7, os.O_BINARY)
        with patch.object(server.msvcrt, "setmode", side_effect=OSError("invalid fd")):
            self.assertFalse(server._set_binary_mode(real_like))

    def test_wait_failed_cancels_io_discards_event_and_raises_connection_error(self):
        client = server.CEBridgeClient()
        client.handle = object()
        for operation in (
            lambda: client._read(4, timeout_ms=1000),
            lambda: client._write(b"test", timeout_ms=1000),
        ):
            events = []

            def cancelled(*args):
                self.assertIs(args[2], True)
                events.append("completed")
                raise server.pywintypes.error(995, "GetOverlappedResult", "aborted")

            with patch.object(server.win32file, "ReadFile"), \
                 patch.object(server.win32file, "WriteFile"), \
                 patch.object(server.win32event, "WaitForSingleObject", return_value=server.win32con.WAIT_FAILED), \
                 patch.object(server.win32file, "CancelIo", side_effect=lambda *_: events.append("cancel")), \
                 patch.object(server.win32file, "GetOverlappedResult", side_effect=cancelled), \
                 patch.object(server.win32api, "CloseHandle", side_effect=lambda h: (events.append("closed"), h.Close())):
                with self.assertRaisesRegex(ConnectionError, "wait failed"):
                    operation()
            self.assertEqual(events, ["cancel", "completed", "closed"])
            self.assertIsNone(client._io_event)

    def test_write_zero_copy_and_read_fast_path(self):
        for payload in (b"hello", bytearray(b"world")):
            with self.subTest(kind=type(payload).__name__):
                client = server.CEBridgeClient()
                client.handle = object()
                written = []
                with patch.object(server.win32file, "WriteFile", side_effect=lambda _h, c, _ov: written.append(c)), \
                     patch.object(client, "_wait_for_io", return_value=len(payload)):
                    client._write(payload, timeout_ms=1000)
                self.assertIs(written[0], payload)

        client = server.CEBridgeClient()
        client.handle = object()
        buf = bytearray(8)
        with patch.object(server.win32file, "AllocateReadBuffer", return_value=buf), \
             patch.object(server.win32file, "ReadFile", side_effect=lambda _h, b, _ov: b.__setitem__(slice(0, 4), b"abcd")), \
             patch.object(client, "_wait_for_io", return_value=4):
            self.assertEqual(client._read(4, timeout_ms=1000), b"abcd")

    def test_empty_response_frame_raises_connection_error(self):
        client = server.CEBridgeClient()
        client.handle = object()
        with patch.object(client, "_write"), \
             patch.object(client, "_read", return_value=b"\x00\x00\x00\x00") as read, \
             patch.object(client, "close", side_effect=lambda: setattr(client, "handle", None)) as close:
            with self.assertRaisesRegex(ConnectionError, "Empty response frame"):
                client.send_command("status", max_retries=1)
        read.assert_called_once()
        close.assert_called()
        self.assertIsNone(client.handle)

    def test_non_dict_json_response_raises_connection_error(self):
        for payload in (b"[]", b'"text"', b"123", b"null"):
            with self.subTest(payload=payload):
                client = server.CEBridgeClient()
                client.handle = object()
                header = len(payload).to_bytes(4, "little")
                with patch.object(client, "_write"), \
                     patch.object(client, "_read", side_effect=[header, payload]), \
                     patch.object(client, "close", side_effect=lambda: setattr(client, "handle", None)) as close:
                    with self.assertRaisesRegex(ConnectionError, "expected object"):
                        client.send_command("status", max_retries=1)
                close.assert_called()
                self.assertIsNone(client.handle)

    def test_oversized_request_rejected_before_writing(self):
        client = server.CEBridgeClient()
        client.handle = object()
        with patch.object(server, "MAX_REQUEST_BYTES", 64), \
             patch.object(client, "_write") as write, \
             patch.object(client, "close") as close:
            with self.assertRaisesRegex(ValueError, "Request too large"):
                client.send_command("evaluate_lua", {"code": "x" * 100})
        write.assert_not_called()
        close.assert_not_called()

    def test_max_retries_zero_executes_single_attempt(self):
        client = server.CEBridgeClient()
        client.handle = object()
        body = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
        with patch.object(client, "_write") as write, \
             patch.object(client, "_read", side_effect=[len(body).to_bytes(4, "little"), body]):
            self.assertEqual(client.send_command("status", max_retries=0), {"ok": True})
        write.assert_called_once()

        failing = server.CEBridgeClient()
        failing.handle = object()
        with patch.object(failing, "_write") as write_fail, \
             patch.object(failing, "_read", side_effect=ConnectionError("pipe lost")), \
             patch.object(failing, "close", side_effect=lambda: setattr(failing, "handle", None)):
            with self.assertRaisesRegex(ConnectionError, "pipe lost"):
                failing.send_command("status", max_retries=0)
        write_fail.assert_called_once()

    def test_close_handles_handle_errors_cleanly(self):
        client = server.CEBridgeClient()
        client.handle = object()
        client._io_event = object()
        with patch.object(server.win32file, "CloseHandle", side_effect=OSError("bad handle")), \
             patch.object(server.win32api, "CloseHandle") as close_event:
            client.close()
        self.assertIsNone(client.handle)
        self.assertIsNone(client._io_event)
        close_event.assert_called_once()

    def test_region_tools_refresh_parameter(self):
        with patch.object(server.ce_client, "send_command", return_value={"success": True}) as send:
            server.get_memory_regions()
            self.assertEqual(send.call_args.args, ("get_memory_regions", {"max": 100}))

            server.get_memory_regions(max=50, protection="+X", refresh=True)
            self.assertEqual(
                send.call_args.args,
                ("get_memory_regions", {"max": 50, "protection": "+X", "refresh": True}),
            )

            server.enum_memory_regions_full()
            self.assertEqual(send.call_args.args, ("enum_memory_regions_full", {"max": 500}))

            server.enum_memory_regions_full(max=250, refresh=True)
            self.assertEqual(
                send.call_args.args,
                ("enum_memory_regions_full", {"max": 250, "refresh": True}),
            )

    def test_analysis_and_dbvm_parameter_clamping(self):
        with patch.object(server.ce_client, "send_command", return_value={"success": True}) as send:
            server.get_scan_results(max=0)
            self.assertEqual(send.call_args.args[1]["max"], 1)
            server.get_scan_results(max=999_999)
            self.assertEqual(send.call_args.args[1]["max"], 10000)

            server.find_function_boundaries("0x401000", max_search=-10)
            self.assertEqual(send.call_args.args[1]["max_search"], 0)
            server.find_function_boundaries("0x401000", max_search=9_999_999)
            self.assertEqual(send.call_args.args[1]["max_search"], 1048576)

            server.start_dbvm_watch("0x401000", max_entries=0)
            self.assertEqual(send.call_args.args[1]["max_entries"], 1)
            server.start_dbvm_watch("0x401000", max_entries=999_999)
            self.assertEqual(send.call_args.args[1]["max_entries"], 100000)

            server.poll_dbvm_watch("0x401000", max_results=-5)
            self.assertEqual(send.call_args.args[1]["max_results"], 1)
            server.poll_dbvm_watch("0x401000", max_results=50_000)
            self.assertEqual(send.call_args.args[1]["max_results"], 10000)

    def test_write_memory_validation(self):
        with patch.object(server.ce_client, "send_command", return_value={"success": True}) as send:
            server.write_memory("0x401000", [0, 0x90, 255])
            self.assertEqual(send.call_args.args, ("write_memory", {"address": "0x401000", "bytes": [0, 144, 255]}))

            server.write_memory("0x401000", (0x90, 0xC3))
            self.assertEqual(send.call_args.args, ("write_memory", {"address": "0x401000", "bytes": [144, 195]}))

            server.write_memory("0x401000", [0] * 65536)
            self.assertEqual(len(send.call_args.args[1]["bytes"]), 65536)

        invalid_inputs = [
            [],
            (),
            None,
            123,
            "90",
            b"\x90",
            bytearray(b"\x90"),
            {1, 2},
            {"a": 1},
            [-1],
            [256],
            [True],
            [False],
            [1.5],
            ["90"],
            [None],
            [0] * 65537,
        ]
        with patch.object(server.ce_client, "send_command") as send:
            for bad in invalid_inputs:
                with self.subTest(bad=repr(bad)[:40]):
                    with self.assertRaises(ValueError):
                        server.write_memory("0x401000", bad)
            send.assert_not_called()

    def test_read_text_file_robust_enforces_size_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "script.lua"
            file_path.write_bytes(b"print('hello world!')")  # 21 bytes

            with patch.object(server, "MAX_LOCAL_FILE_BYTES", 10), \
                 patch.object(Path, "read_bytes") as read_bytes:
                with self.assertRaisesRegex(ValueError, "File too large"):
                    server._read_text_file_robust(str(file_path))
                read_bytes.assert_not_called()

            with patch.object(server, "MAX_LOCAL_FILE_BYTES", 21):
                content, enc, resolved = server._read_text_file_robust(str(file_path))
                self.assertEqual(content, "print('hello world!')")
                self.assertEqual(enc, "utf-8-sig")
                self.assertEqual(resolved, str(file_path.resolve()))

    def test_status_includes_timeouts_in_mcp_client_metadata(self):
        with patch.object(server.ce_client, "send_command", return_value={"success": True}):
            payload = json.loads(server.status())
        self.assertEqual(payload["mcp_client"]["timeout_ms"], server.CE_READ_TIMEOUT_MS)
        self.assertEqual(payload["mcp_client"]["lock_timeout_ms"], server.CE_LOCK_TIMEOUT_MS)
        self.assertIn("auth_configured", payload["mcp_client"])

    def test_read_text_file_robust_enforces_limit_during_read_even_if_stat_lags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "growing.lua"
            file_path.write_bytes(b"A" * 30)
            fake_stat = Mock(st_size=5)
            with patch.object(server, "MAX_LOCAL_FILE_BYTES", 10), \
                 patch.object(Path, "stat", return_value=fake_stat):
                with self.assertRaisesRegex(ValueError, "exceeded limit"):
                    server._read_text_file_robust(str(file_path))

    def test_send_command_requires_matching_id_for_results_and_allows_null_for_errors(self):
        client = server.CEBridgeClient()
        client.handle = object()

        null_result = b'{"jsonrpc":"2.0","id":null,"result":{"success":true}}'
        with patch.object(client, "_write"), \
             patch.object(client, "_read", side_effect=[len(null_result).to_bytes(4, "little"), null_result]), \
             patch.object(client, "close") as close:
            with self.assertRaisesRegex(ConnectionError, "Mismatched response id"):
                client.send_command("ping", max_retries=1)
        close.assert_called()

        null_error = b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}'
        client.handle = object()
        with patch.object(client, "_write"), \
             patch.object(client, "_read", side_effect=[len(null_error).to_bytes(4, "little"), null_error]):
            res = client.send_command("ping", max_retries=1)
        self.assertEqual(res["success"], False)
        self.assertEqual(res["error_code"], -32700)

    def test_send_command_attaches_auth_token_when_configured(self):
        client = server.CEBridgeClient()
        client.handle = object()
        written = []
        resp = b'{"jsonrpc":"2.0","id":1,"result":{"success":true}}'
        with patch.object(server, "CE_AUTH_TOKEN", "shared-secret"), \
             patch.object(client, "_write", side_effect=lambda data, **_: written.append(data)), \
             patch.object(client, "_read", side_effect=[len(resp).to_bytes(4, "little"), resp]):
            self.assertEqual(client.send_command("ping", max_retries=1), {"success": True})
        sent_obj = json.loads(written[0][4:].decode("utf-8"))
        self.assertEqual(sent_obj.get("auth_token"), "shared-secret")

    def test_registered_write_memory_tool_rejects_coercible_non_ints_before_pipe(self):
        tool = server.mcp._tool_manager.get_tool("write_memory")
        with patch.object(server.ce_client, "send_command", return_value={"success": True}) as send:
            for bad in ([True], [False], ["90"], [1.0]):
                with self.subTest(bad=bad):
                    with self.assertRaises(Exception):
                        asyncio.run(tool.run({"address": "0x401000", "bytes": bad}))
            send.assert_not_called()
            ok = asyncio.run(tool.run({"address": "0x401000", "bytes": [0x90, 0xC3]}))
            self.assertTrue(json.loads(ok)["success"])
            send.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
