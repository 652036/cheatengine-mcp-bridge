# AI Agent Guide: Building a Full MCP Server for CheatEngine

---

## ⚠️ CRITICAL CONFIGURATION

### 1. BSOD PREVENTION
**You MUST disable:** Cheat Engine → Settings → Extra → **"Query memory region routines"**.
- **Enabled:** Causes `CLOCK_WATCHDOG_TIMEOUT` BSODs due to conflicts with DBVM/Anti-Cheat when scanning protected pages.
- **Disabled:** Scanning works perfectly and safely (v11 verified).

### 2. ANTI-CHEAT SAFETY
- **DO NOT** use software breakpoints (0xCC/Int3). Use **Hardware Debug Registers (DR0-DR3)** breakpoints.
- **DO NOT** write to memory.
- **USE** DBVM tools (`start_dbvm_watch`) for invisible tracing at Ring -1.

---

## 1. OBJECTIVE

A **production-grade Model Context Protocol (MCP) server** acts as the "Universal Key" to the game engine, allowing AI agents to:
1.  **Read & Analyze** any part of memory (static or dynamic).
2.  **Trace Execution** invisible to anti-cheat (Hypervisor/Hardware BPs).
3.  **Reverse Engineer** complex structures and functions on the fly.

### Performance Targets
- **Architecture:** Multi-Threaded Named Pipe (Async I/O).
- **Latency:** <2ms per command.
- **Reliability:** 100% Robust against freezes via `thread.synchronize`.

---

## 2. SYSTEM ARCHITECTURE (v11.6.2)

### The "v11/v99" Bridge
The system uses a highly optimized Named Pipe architecture with a dedicated worker thread in Lua to handle blocking I/O, ensuring the main Cheat Engine GUI/Thread never freezes.

### Universal 32/64-bit Architecture Support
The bridge automatically adapts to the target process architecture:
- **`getArchInfo()`** - Dynamically detects 32-bit vs 64-bit target
- **`captureRegisters()`** - Captures RAX/RBX (x64) or EAX/EBX (x86) correctly
- **`captureStack()`** - Reads stack with correct pointer size (8/4 bytes)
- **`readPointer()`** - Used throughout for automatic pointer size handling
- **Function Analysis** - Detects both x86 (`55 8B EC`) and x64 (`55 48 89 E5`, `48 83 EC xx`) prologues

**Connection Details:**
- **Pipe Name:** `\\.\pipe\CE_MCP_Bridge_v99`
- **Protocol:** Length-Prefixed JSON-RPC
- **Flow:** Python `FastMCP` Server <-> Named Pipe <-> Lua Worker Thread <-> Main Thread (`synchronize`)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AI Agent (Claude/Cursor/Copilot)                                      │
│       │                                                                 │
│       ▼ MCP Protocol (JSON-RPC over stdio)                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  mcp_cheatengine.py (Python MCP Server)                         │   │
│  │  - Translates MCP tools to JSON-RPC                             │   │
│  │  - Connects to \\.\pipe\CE_MCP_Bridge_v99                       │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │ Named Pipe (Async)                      │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  CheatEngine (Running, attached to .exe)                        │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │  ce_mcp_bridge.lua                                      │    │   │
│  │  │  ┌─────────────────┐      ┌─────────────────────┐       │    │   │
│  │  │  │ Worker Thread   │◄────►│ Main Thread (GUI)   │       │    │   │
│  │  │  │ (Blocking I/O)  │ Sync │ (Safe API Execution)│       │    │   │
│  │  │  └─────────────────┘      └─────────────────────┘       │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. COMPREHENSIVE TOOLSET (48 Commands)

The v11.6.2 implementation provides a complete arsenal for reverse engineering with full 32/64-bit compatibility.

### 🔍 Memory Reading & Scanning
| Tool | Description |
|------|-------------|
| `read_memory(addr, size)` | Read raw bytes. |
| `read_integer(addr, type)` | Read Byte, Word, Dword, Qword, Float, Double. |
| `read_string(addr, len)` | Read ASCII/UTF-16 strings. Valid UTF-8 is preserved. |
| `read_pointer_chain(base, offsets)` | **CRITICAL**: Follow dynamic pointer paths `[base+10]+20`. |
| `scan_all(val, type, prot)` | Full memory scanner (like CE GUI). One window per call. |
| `aob_scan(pattern, max_windows)` | Find array of bytes `48 8B 05 ??`. Raise `max_windows` to cover more ground per call. |
| `generate_signature(addr)` | Create unique AOB signature for an address. |

> All scans are bounded by an address budget **and** a time budget. Always read
> `truncated` and `next_start_address` before concluding a pattern is absent.

### 🛠️ Bridge Control
| Tool | Description |
|------|-------------|
| `status()` | Process, architecture, DBK/DBVM state, live breakpoints, watches, AA scripts. **Call this first.** |
| `cleanup()` | Release all breakpoints, DBVM watches and scan objects. |
| `auto_assemble(script, id)` | Run `[ENABLE]`; revert later with `disable=True` and the same `id`. |

### 🧬 Structure & Code Analysis
| Tool | Description |
|------|-------------|
| `dissect_structure(addr)` | **AI-Powered**: Auto-guess fields, types, and values at address. |
| `get_rtti_classname(addr)` | Identify C++ object types (e.g., `NpcUser`, `CItem`). |
| `analyze_function(addr)` | Find all `CALL`s made by a function. |
| `find_references(addr)` | Find what code uses this data (Cross-References). |
| `find_call_references(func)` | Find who calls this function (Call Graph). |
| `find_function_boundaries(addr)` | Locate function start/end/prologue. |

### 🐞 Debugging (Bounded Hardware Breakpoints)
| Tool | Description |
|------|-------------|
| `set_breakpoint(addr)` | **Hardware BP**: one-shot by default; supports register/memory conditions and hit/trigger caps. 4 slots total. |
| `set_data_breakpoint(addr)` | **Watchpoint**: same bounded controls. `"r"` also fires on writes — debug registers have no read-only condition. |
| `get_breakpoint_hits()` | Retrieve hits plus auto-retirement state. One-shot results survive hardware-slot release. |

Hardware breakpoints do not patch target code, but each trigger still causes a brief
debugger stop and is detectable. Do not install persistent unbounded breakpoints on
high-frequency APIs.

### 🚀 DBVM Hypervisor (Ring -1)
| Tool | Description |
|------|-------------|
| `start_dbvm_watch(addr)` | Hypervisor-level watch using physical-memory tracing; requires an active DBVM setup. |
| `get_physical_address(addr)` | Resolve Virtual -> Physical address. |

Full commands list at `MCP_Bridge_Command_Reference.md`

---

## 4. CURRENT STATUS

| Component | Status | Version | Notes |
|-----------|--------|---------|-------|
| **Lua Bridge** | ✅ **ACTIVE** | v11.6.2 | `ce_mcp_bridge.lua` (Load in CE) |
| **Python Server** | ✅ **ACTIVE** | v11.6.2 | `mcp_cheatengine.py` (Run in Agent) |
| **Offline Tests** | ✅ **VERIFIED** | — | `test_offline.py` (stubbed CE, no target needed) |
| **Live Test Suite** | ⚠️ **NEEDS CE** | v3 | `test_mcp.py` (requires attached process) |
| **Pipe Diagnostic** | ✅ **ACTIVE** | — | `check_pipe.py` (pywin32 only) |
| **Documentation** | ✅ **UPDATED** | v5.2 | `MCP_Bridge_Command_Reference.md` |

### Recent Fixes (v11.6.2)

- **Non-blocking handler hot reload**: the long-lived pipe worker resolves a global
  dispatcher for each request, so re-executing the script replaces command handlers
  without stopping the worker. This replaces the v11.6.1 synchronous auto-restart,
  which could deadlock CE while a connected worker was waiting on the main thread.

### Earlier Fixes (v11.6.0)

- **Safe one-shot defaults**: execution and data breakpoints now remove themselves
  after the first matching hit unless repeated sampling is explicitly requested.
- **Pre-capture conditions**: register and memory conditions run before expensive
  register/stack capture. A total `max_triggers` cap prevents a never-matching
  condition from remaining on a hot path indefinitely.
- **Reliable continuation**: callback work is isolated from the continue path;
  capture/condition failures auto-retire the breakpoint after attempting to resume
  the target.
- **Retained completion state**: auto-retired breakpoint hits and counters remain
  readable while the scarce hardware debug-register slot is released immediately.

### Earlier Fixes (v11.5.0)

Transport and encoding correctness — these caused silent wrong answers, not visible errors:

- **64-bit address precision**: the Lua JSON encoder used `%.14g`, which rounds any
  address needing 15 significant digits. `0x7FF6A0001000` came back as
  `1.4069453816627e+14`, i.e. 2 bytes off. Integral values are now emitted exactly.
- **Non-ASCII request parsing**: `\uXXXX` was decoded with `string.char(codepoint)`,
  which raises above U+00FF. Any request carrying Chinese/UTF-8 text failed to parse.
  Now decoded to UTF-8 (including surrogate pairs); Python sends `ensure_ascii=False`.
- **Large responses**: the Python client issued a single `ReadFile`, so any reply
  exceeding CE's 64 KB pipe buffer failed as "Incomplete response body". Both sides
  now loop until the full length is read.
- **Frozen target after clearing hits**: `get_breakpoint_hits()` replaced the whole
  hit table, after which the debugger callback hit `table.insert(nil, ...)` and never
  reached `debug_continueFromBreakpoint`. Buckets are cleared in place, callbacks are
  pcall-wrapped so the continue always runs, and hits are capped at 500 per breakpoint.
- **Serialization failures hung the client**: `json.encode` in the dispatcher was
  unprotected, so a circular table produced no response at all. All paths now return
  a valid JSON-RPC envelope.
- **Unsafe retries**: a lost reply re-sent the request, which could apply
  `write_memory` or `auto_assemble` twice. Only read-only methods retry now.

Analysis and scanning:

- **Prologue search** read one byte at a time (up to ~16k cross-process reads per
  call); now block-based. Function end is found by walking instructions, so a `0xC3`
  inside an operand no longer terminates the function early.
- **Multi-window scans**: `max_windows` (up to 64) lets one call walk several regions
  instead of forcing the caller to chain `next_start_address`.
- **Broad-pattern guard**: `classifyUnsafeGlobalAob` was dead code, so
  `allow_unsafe_global` did nothing and `?? ?? ?? ??` scanned everything. Now enforced.
- **`find_call_references` time budget** used `os.clock()` (CPU time) while blocked on
  I/O, so it never expired. Uses wall clock now.
- **`dissect_structure`** called CE class methods with `:` instead of the documented
  `.`, shifting every argument; it silently returned zero fields for any address.
- **`get_memory_regions`** probed nine hardcoded 32-bit addresses; now enumerates real
  regions with an optional protection filter.
- **`get_process_info`** no longer falls back to a hardcoded `"L2.exe"`, and reports
  architecture and pointer size.

New:

- **`status`** — attached process, architecture, DBK/DBVM availability, live
  breakpoints with buffered hit counts, DBVM watches, stored AA scripts. First call
  when troubleshooting.
- **`cleanup`** — release breakpoints, watches and scan objects without reloading.
- **`auto_assemble(disable=True, id=...)`** — the `[ENABLE]` run's disableInfo used to
  be discarded, so injected code could never be reverted through the bridge.

### Previous Fixes (v11.4.0)
- **Zombie Cleanup**: Added `cleanupZombieState()` to remove orphaned breakpoints/watches on reload
- **Script Reload Safety**: Prevents game freezes when reloading script with active resources

### Previous Fixes (v11.3.1)
- **Pointer Chain Reading**: Fixed to use `readPointer()` for final values (32/64-bit safe)
- **Function Analysis**: Enhanced to detect x86 and x64 function prologues
- **CALL Detection**: Now includes indirect CALL instructions (`FF /2`)
- **Architecture Field**: All analysis commands include `arch` field in response

---

## 5. BEST PRACTICES FOR AGENTS

1.  **Start with `status()`**: one call reports connection, attached process,
    architecture, DBK/DBVM availability and every resource the bridge holds.
2.  **Use `read_pointer_chain`**: simpler and faster than multiple `read_pointer` calls.
3.  **Structure Analysis**: Use `dissect_structure` on unknown pointers to understand their layout immediately.
4.  **Respect `truncated`**: every scan is bounded by an address budget and a time
    budget. `truncated: true` means the scan ran out of budget — **not** that the
    pattern is absent. Continue from `next_start_address` or raise `max_windows`.
5.  **Bound scans**: pass `start_address` + `size`, or scan a single module. Broad
    low-entropy AOB patterns are refused unless `allow_unsafe_global` is set.
6.  **RTTI is King**: Use `get_rtti_classname` to identify what an object is instantly.
7.  **Check Architecture**: `get_process_info()` returns `architecture` and
    `pointer_size` directly.
8.  **DBVM for Stealth**: Use `start_dbvm_watch` for invisible Ring -1 tracing (only
    when `status` reports `dbvm_active: true`).
9.  **Poll breakpoint hits regularly**: each breakpoint buffers at most 500 hits and
    drops the oldest first.
10. **Clean up**: `cleanup` releases breakpoints, watches and scans in one call.
    Auto Assembler scripts are separate — revert those with
    `auto_assemble(disable=True, id=...)` so allocations and hooks are undone.

---

## 6. VERIFICATION

Two suites, for two different situations.

**Offline** — no Cheat Engine and no target process required. Loads
`ce_mcp_bridge.lua` into a real Lua interpreter with the CE API stubbed, then drives
the dispatcher against a synthetic memory map. Run this after any bridge edit:

```
pip install lupa
python test_offline.py
```

Covers the JSON encoder's numeric precision, `\uXXXX` decoding, the scan-window
walker, the broad-pattern guard, the prologue search, and JSON-RPC error envelopes.

**Live** — requires CE running with the bridge loaded and a process attached:

```
python test_mcp.py
```

Includes a "Regression Guards" category that re-checks the 11.5.0 fixes against a real
target: 64-bit address precision, non-ASCII round trips, and the Auto Assembler
enable/disable cycle. `generate_signature` is skipped by default because
`getUniqueAOB` blocks CE while it scans all memory.

**Pipe-level** — when the MCP layer itself is suspect:

```
python check_pipe.py --summary
```
