# Cheat Engine MCP Bridge (Hardened Edition)

[![Version](https://img.shields.io/badge/bridge-v11.6.3--hardened-blue.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6.svg)](#)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A hardened, high-throughput **Model Context Protocol (MCP)** server and Cheat Engine Lua bridge for Windows reverse engineering, memory inspection, disassembly, bounded hardware breakpoint sampling, and optional DBVM hypervisor tracing.

> [!NOTE]
> Standalone hardened edition derived from [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) (MIT License).

---

## Key Improvements in This Edition

- **Non-blocking MCP event loop & safe Win32 overlapped I/O**: Every tool runs blocking named-pipe I/O off FastMCP's event loop, reuses a single Win32 event handle, shares one monotonic request deadline across queue/connect/read/write/retries, cancels and drains pending overlapped I/O before releasing buffers, and never replays ambiguous side-effecting writes.
- **No multi-session pipe lockouts**: Cheat Engine serves one pipe client at a time. The Python client automatically releases idle pipe handles (`CE_MCP_IDLE_DISCONNECT_MS`, default 3 s) and transparently reconnects with a `CreateFile`-first retry loop; the Lua bridge enforces a 60 s idle watchdog as a server-side safety net.
- **Shared-host authentication (`CE_MCP_AUTH_TOKEN`)**: Optional constant-time shared-secret token verification across the Lua dispatcher, `mcp_cheatengine.py`, and `check_pipe.py` to guard against untrusted local accounts on shared Windows hosts.
- **Hot-reloadable Lua dispatcher**: Re-executing `ce_mcp_bridge.lua` updates handlers in place without stopping an active pipe worker or deadlocking Cheat Engine.
- **Safe bounded hardware breakpoints**: Refuses implicit debugger auto-start from synchronous pipe dispatch, verifies native install/remove state against CE's breakpoint list, defaults to `one_shot=True` + `max_triggers=256`, supports register/memory pre-capture conditions, and captures stack frames via single bulk reads while preserving `[RSP + i*ptrSize]` offsets.
- **Large x64 process performance**: Eliminates multi-second `enumMemoryRegions()` sort/cache stalls, adds precomputed `HEX_BYTE` lookup tables, anchor-relative AOB scanning, multi-window scanning (`max_windows` up to 64), O(N) DBVM ring compaction, and cached disassembly on `stop_dbvm_watch`.
- **Standalone diagnostics & 298 offline checks**: Includes `check_pipe.py` (zero `mcp` dependency) plus offline Lua 5.3/5.4 (245 checks) and Python/isolated-pipe (53 tests, 35 subtests) regression suites.

---

## Architecture

```mermaid
flowchart LR
    AI["AI Client (Claude / Codex / Cursor / IDE)"]
    MCP["mcp_cheatengine.py\nFastMCP + Worker Threads"]
    PIPE["\\\\.\\pipe\\CE_MCP_Bridge_v99\nLength-Prefixed JSON-RPC 2.0"]
    WORKER["ce_mcp_bridge.lua\nPipeWorker Thread"]
    MAIN["Cheat Engine Main Thread\nHot-Reloadable Dispatcher"]
    TARGET["Attached Target Process"]

    AI <-->|"MCP over stdio (LF)"| MCP
    MCP <-->|"Win32 Overlapped I/O"| PIPE
    PIPE <-->|"Blocking Pipe I/O"| WORKER
    WORKER <-->|"thread.synchronize"| MAIN
    MAIN <-->|"Read / Write / Debug / DBVM"| TARGET
```

---

## Requirements & Installation

- **OS**: Windows (uses Win32 Named Pipes via `pywin32`)
- **Python**: 3.10+
- **Cheat Engine**: 7.5+ / 7.6 (64-bit recommended)

Install dependencies:

```bash
pip install -r MCP_Server/requirements.txt
```

Or manually:

```bash
pip install "mcp>=1.2.0,<2.0" pywin32
```

> [!IMPORTANT]
> Keep `mcp` pinned to `>=1.2.0,<2.0`. Versions `1.0.x`–`1.1.x` lack `FastMCP` / `mcp.shared.message`, and `2.x` removed `FastMCP`.

---

## Quick Start

### 1. Start the Bridge in Cheat Engine

1. Open Cheat Engine and attach to your target process.
2. Open **File → Execute Script** (or **Table → Show Cheat Table Lua Script**), load `MCP_Server/ce_mcp_bridge.lua`, and execute it.
3. Confirm the Lua console prints:

```text
[MCP v11.6.3] MCP Server Listening on: CE_MCP_Bridge_v99
```

Re-running `ce_mcp_bridge.lua` hot-swaps command handlers in place while preserving the running pipe worker.

### 2. Configure Your MCP Client

Add an entry to your IDE / agent MCP config (e.g. `mcp_config.json`):

```json
{
  "servers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:/path/to/MCP_Server/mcp_cheatengine.py"]
    }
  }
}
```

Restart your IDE or MCP host, then call `ping` or `status` to verify connectivity.

### 3. Verify Directly with `check_pipe.py`

`check_pipe.py` speaks directly to the named pipe using only `pywin32` (no `mcp` SDK), making it easy to separate CE bridge issues from MCP client configuration issues:

```bash
python MCP_Server/check_pipe.py --summary
python MCP_Server/check_pipe.py --ping --repeat 5 --timeout-ms 30000
python MCP_Server/check_pipe.py --lua-file "C:/path/to/helper.lua"
python MCP_Server/check_pipe.py --call read_integer --params "{\"address\":\"game.exe+1000\"}"
```

---

## Configuration & Security

### Environment Variables (`mcp_cheatengine.py` / `check_pipe.py`)

| Variable | Default | Description |
|---|---|---|
| `CE_MCP_PIPE_NAME` | `CE_MCP_Bridge_v99` | Short pipe name or full `\\.\pipe\...` path (also via `--pipe`) |
| `CE_MCP_SERVER_NAME` | `cheatengine` | FastMCP server name exposed to the MCP host |
| `CE_MCP_AUTH_TOKEN` | *(unset)* | Optional shared-secret token attached to every pipe request |
| `CE_MCP_TIMEOUT_MS` | `120000` | Total monotonic budget (ms) shared by queue, connect, I/O, and safe retries |
| `CE_MCP_BREAKPOINT_TIMEOUT_MS` | `10000` | Total request budget (ms) for breakpoint install calls (never retried) |
| `CE_MCP_LOCK_TIMEOUT_MS` | `15000` | Max time (ms) a concurrent request waits for the serialized pipe lock |
| `CE_MCP_CONNECT_WAIT_MS` | `3000` | Base wait per connect attempt (multiplied by `CE_MCP_CONNECT_RETRIES`, default `3`) |
| `CE_MCP_CONNECT_RETRY_DELAY_MS` | `250` | Delay (ms) between retries on unexpected connection errors |
| `CE_MCP_PIPE_MISSING_GRACE_MS` | `1000` | Grace window (ms) to ride out CE's ~50 ms pipe recreation gap |
| `CE_MCP_IDLE_DISCONNECT_MS` | `3000` | Idle time (ms) before releasing the pipe handle (`0` = every call, `< 0` = never) |
| `CE_MCP_MAX_RESPONSE_BYTES` | `67108864` (64 MB) | Hard limit on a single CE response frame |
| `CE_MCP_MAX_LOCAL_FILE_BYTES` | `16777216` (16 MB) | Hard limit for `evaluate_lua_file`, `auto_assemble_file`, and `check_pipe.py --lua-file` (min 1 MB) |
| `CE_MCP_MAX_SCAN_BUDGET` | `200000` | Max address budget per scan window |

### Lua-Side Overrides (Set in CE Console Before Executing Script)

```lua
CE_MCP_PIPE_NAME = "CE_MCP_Bridge_alt"       -- pair with --pipe CE_MCP_Bridge_alt
CE_MCP_IDLE_KICK_MS = 60000                  -- kick silent client after 60s (0 disables)
CE_MCP_AUTH_TOKEN = "replace-with-a-secret"  -- require matching auth_token on every request
```

### Security & Local Pipe Trust Boundary

Cheat Engine's built-in `createPipe()` creates a Windows Named Pipe without a per-user ACL, meaning other local accounts on a shared Windows machine can connect to the pipe and execute Lua inside Cheat Engine.

On any shared or multi-user machine, set `CE_MCP_AUTH_TOKEN` on **both** Cheat Engine and your MCP client / `check_pipe.py` (`--auth-token` or `$env:CE_MCP_AUTH_TOKEN`). Requests missing a valid token are rejected with JSON-RPC error `-32001` (`Unauthorized`), and `status` reports `auth_required` / `auth_configured` without exposing the secret.

---

## Available MCP Tools (48)

| Category | Tools |
|---|---|
| **Process & Symbols (6)** | `get_process_info`, `enum_modules`, `get_thread_list`, `get_symbol_address`, `get_address_info`, `get_rtti_classname` |
| **Memory Read (6)** | `read_memory`, `read_integer`, `read_string`, `read_pointer`, `read_pointer_chain`, `checksum_memory` |
| **Memory Write (3)** | `write_integer`, `write_memory`, `write_string` |
| **Scanning & Regions (8)** | `scan_all`, `get_scan_results`, `next_scan`, `aob_scan`, `search_string`, `generate_signature`, `get_memory_regions`, `enum_memory_regions_full` |
| **Disassembly & Xrefs (7)** | `disassemble`, `get_instruction_info`, `find_function_boundaries`, `analyze_function`, `find_references`, `find_call_references`, `dissect_structure` |
| **Hardware Breakpoints (6)** | `set_breakpoint`, `set_data_breakpoint`, `remove_breakpoint`, `list_breakpoints`, `clear_all_breakpoints`, `get_breakpoint_hits` |
| **DBVM Hypervisor (4)** | `get_physical_address`, `start_dbvm_watch`, `poll_dbvm_watch`, `stop_dbvm_watch` |
| **Scripting & Files (4)** | `evaluate_lua`, `auto_assemble`, `evaluate_lua_file`, `auto_assemble_file` |
| **Bridge Control (4)** | `ping`, `status`, `cleanup`, `disconnect` |

See [AI_Context/MCP_Bridge_Command_Reference.md](AI_Context/MCP_Bridge_Command_Reference.md) for detailed parameter and response schemas.

---

## Operational Notes

### Multi-Window Scanning & Region Cache
- `aob_scan`, `search_string`, `find_references`, and `find_call_references` scan 200,000-address windows and accept `max_windows` (up to `64`) bounded by `time_budget_ms`, returning `next_start_address` for seamless continuation (including exact resume cursors when hitting `limit`).
- Low-entropy unbounded AOB patterns are refused unless `allow_unsafe_global=True` or bounded by `start_address` + `size`.
- Memory region enumeration is cached for 15 seconds to prevent multi-second stalls on large x64 processes. Pass `refresh=True` to `get_memory_regions` or `enum_memory_regions_full` after target allocations change.

### Safe Bounded Hardware Breakpoints
- Start the debugger directly in Cheat Engine first (e.g. `debugProcess()` in CE's Lua console) and confirm `status.debugger_started == true`. Breakpoint tools intentionally refuse installation when the debugger is not running to avoid freezing CE's main thread during native attach dialogs.
- `set_breakpoint` and `set_data_breakpoint` default to `one_shot=True` and `max_triggers=256`, and support ANDed `register` / `memory` conditions (`eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in`, `mask_eq`) evaluated before register or stack capture:

```json
{
  "address": "module+0x1234",
  "id": "watch_once",
  "one_shot": true,
  "max_triggers": 256,
  "capture_stack": true,
  "conditions": [
    {"kind": "register", "register": "R8", "operator": "in", "values": [42, 123]},
    {"kind": "memory", "base_register": "RDX", "offset": 0, "size": 1, "operator": "eq", "value": 1}
  ]
}
```

### Local Script Execution
`evaluate_lua_file` and `auto_assemble_file` read local `.lua` / `.cea` files with automatic encoding detection (UTF-8, UTF-16, GB18030/CP936), bounded streaming reads (`CE_MCP_MAX_LOCAL_FILE_BYTES`), and return `source_file`, `source_encoding`, and `source_length` metadata.

### Cheat Engine Stability & DBVM Caution
> [!CAUTION]
> Disable **Cheat Engine → Settings → Extra → "Query memory region routines"** when working with protected processes or DBVM to avoid `CLOCK_WATCHDOG_TIMEOUT` BSODs.

Standard memory reads, scans, and hardware breakpoints do **not** require DBK or DBVM. Enable DBVM only when explicitly using `*_dbvm_watch` tools in a disposable test environment.

---

## Project Structure

```text
MCP_Server/
├── ce_mcp_bridge.lua           # Cheat Engine Lua bridge (worker thread + hot-reloadable dispatcher)
├── mcp_cheatengine.py          # FastMCP Python server (overlapped Win32 named-pipe client)
├── check_pipe.py               # Standalone pipe diagnostic CLI (pywin32 only)
├── requirements.txt            # Runtime Python dependencies
├── test_offline.py             # Offline Lua 5.3/5.4 regression suite (245 checks via lupa)
├── test_server_threading.py    # Offline FastMCP threading, validation & pipe tests (36 tests)
├── test_check_pipe.py          # Offline check_pipe.py & isolated named-pipe tests (17 tests)
└── test_mcp.py                 # Live integration suite (requires CE + attached process)

AI_Context/
├── MCP_Bridge_Command_Reference.md        # Bridge command reference
├── AI_Guide_MCP_Server_Implementation.md  # Implementation & architecture notes
└── CE_LUA_Documentation.md                # Links to official Cheat Engine Lua docs
```

---

## Testing

### Offline Suites (No Cheat Engine Required)

**Python server & `check_pipe.py` tests** (built-in `unittest`, no extra packages required):

```bash
python -m unittest discover -s MCP_Server -p "test_server_threading.py" -v
python -m unittest discover -s MCP_Server -p "test_check_pipe.py" -v
```

Or with `pytest` (`pip install pytest`):

```bash
python -m pytest MCP_Server/test_server_threading.py MCP_Server/test_check_pipe.py -v
```

**Lua bridge offline regression suite** (embeds Lua 5.3/5.4 with stubbed CE APIs):

```bash
pip install lupa
python MCP_Server/test_offline.py
```

### Live Integration Suite (Requires Cheat Engine + Attached Process)

```bash
python MCP_Server/test_mcp.py
```

---

## License & Attribution

- Licensed under the [MIT License](LICENSE).
- Original project: [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) (`Copyright (c) 2025 miscusi-peek`).

## Disclaimer

This software is intended strictly for authorized debugging, reverse engineering, security research, and educational software analysis. Do not use it to violate Terms of Service, bypass DRM unlawfully, or cheat in online multiplayer games.
