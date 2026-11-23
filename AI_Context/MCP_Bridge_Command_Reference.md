# MCP Bridge Command Reference (v11.6.2)

> **For AI Agents**: This document describes all available commands in the Cheat Engine MCP Bridge. Use these commands to perform memory analysis, reverse engineering, and dynamic tracing on target processes.
>
> **Architecture Support**: All commands automatically adapt to 32-bit or 64-bit targets. Pointer operations use `readPointer()` for automatic size handling.
>
> **Start with `status`** when anything is unclear or failing: it reports the attached
> process, architecture, DBK/DBVM availability, live breakpoints and their buffered
> hits, DBVM watches, and whether scan results are available.
>
> **Scan windows**: `aob_scan`, `search_string` and `find_references` cover up to
> 200,000 addresses per window and return `next_start_address`. Raise `max_windows`
> (up to 64) to walk several consecutive regions in one call instead of chaining
> requests. `time_budget_ms` bounds the whole call either way.

---

## Table of Contents

1. [Basic & Utility](#1-basic--utility) — `ping`, `status`, `cleanup`
2. [Process & Modules](#2-process--modules)
3. [Memory Read](#3-memory-read)
4. [Memory Write](#4-memory-write)
5. [Pattern Scanning](#5-pattern-scanning)
6. [Disassembly & Analysis](#6-disassembly--analysis)
7. [Breakpoints (Hardware Debug Registers)](#7-breakpoints-hardware-debug-registers)
8. [Memory Regions](#8-memory-regions)
9. [Lua Evaluation](#9-lua-evaluation)
10. [High-Level Analysis Tools](#10-high-level-analysis-tools)
11. [DBVM Hypervisor Tools (Ring -1)](#11-dbvm-hypervisor-tools-ring--1)

---

## 1. Basic & Utility

### `ping`
**Purpose**: Verify the MCP bridge is running and responsive.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "version": "11.6.2",
  "timestamp": 1733540000,
  "process_id": 1234,
  "message": "CE MCP Bridge v11.6.2 alive"
}
```

**Usage**: Call this first to verify connectivity before performing operations.

---

### `status`
**Purpose**: Report the full state of the bridge, the target and CE's capabilities.
This is the first call to make when something is failing or unclear.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "version": "11.6.2",
  "pipe_name": "CE_MCP_Bridge_v99",
  "client_connected": true,
  "worker_running": true,
  "process_id": 1234,
  "process_attached": true,
  "architecture": "x64",
  "dbk_loaded": true,
  "dbvm_active": false,
  "hw_breakpoint_slots_used": 1,
  "hw_breakpoint_slots_total": 4,
  "breakpoints": [
    {"id": "bp1", "address": "0x00401000", "type": "execute", "slot": 1, "active": true, "buffered_hits": 12}
  ],
  "completed_breakpoints": [],
  "dbvm_watches": [],
  "auto_assemble_scripts": ["last"],
  "scan_results_available": true,
  "max_scan_budget": 200000,
  "max_buffered_hits": 500
}
```

**Notes**:
- `dbvm_active: false` means the DBVM tools will fail; enable it in
  CE → Settings → Debugger.
- `buffered_hits` counts hits waiting to be read. Each breakpoint buffers at most
  `max_buffered_hits`, dropping the oldest first, so poll `get_breakpoint_hits`
  regularly on a hot instruction.

---

### `cleanup`
**Purpose**: Release every breakpoint, DBVM watch and scan object the bridge holds,
without reloading the Lua script in Cheat Engine.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "removed_breakpoints": 2,
  "stopped_dbvm_watches": 1,
  "released_scan_objects": 2
}
```

**Notes**: AutoAssembler scripts are deliberately left alone — revert those with
`auto_assemble` and `disable: true`, which runs their `[DISABLE]` section.

---

## 2. Process & Modules

### `get_process_info`
**Purpose**: Get information about the currently attached process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "process_name": "game.exe",
  "process_name_resolved": true,
  "process_id": 12345,
  "architecture": "x64",
  "is_64bit": true,
  "pointer_size": 8,
  "module_count": 50,
  "total_modules": 137,
  "modules_truncated": true,
  "modules": [
    {"name": "game.exe", "address": "0x00400000", "size": 1234567},
    {"name": "ntdll.dll", "address": "0x77000000", "size": 2345678}
  ]
}
```

**Notes**:
- `modules` is capped at 50 entries; `total_modules` is the real count. Use
  `enum_modules` for the full list.
- `process_name_resolved: false` means CE could not name the process (anti-cheat may
  be hiding it) and the name shown is a best-effort fallback, or `"unknown"`.
- The global MZ AOB fallback for hidden modules is disabled: it would exceed the
  200,000-address scan budget. `module_fallback_skipped` reports when this applies.

---

### `enum_modules`
**Purpose**: List all modules loaded in the target process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 15,
  "modules": [
    {"name": "kernel32.dll", "address": "0x76000000", "size": 1234567}
  ]
}
```

---

### `get_symbol_address`
**Purpose**: Resolve a symbol name to its memory address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `symbol` | string | Yes | Symbol name (e.g., "kernel32.GetProcAddress", "L2.exe+0x1000") |

**Returns**:
```json
{
  "success": true,
  "symbol": "kernel32.GetProcAddress",
  "address": "0x76001234"
}
```

---

## 3. Memory Read

### `read_memory` / `read_bytes`
**Purpose**: Read raw bytes from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to read |
| `size` | int | No | 16 | Number of bytes to read (max 65536) |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "length": 16,
  "hex": "4D 5A 90 00 03 00 00 00",
  "bytes": [77, 90, 144, 0, 3, 0, 0, 0]
}
```

---

### `read_integer`
**Purpose**: Read an integer value from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `type` | string | No | "dword" | "byte", "word", "dword", or "qword" |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "value": 905969664,
  "hex": "0x36005A4D"
}
```

---

### `read_string`
**Purpose**: Read a null-terminated string from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `max_length` | int | No | 256 | Maximum characters to read |
| `wide` | bool | No | false | Read as UTF-16 (widechar) |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "value": "MZ",
  "wide": false
}
```

---

### `read_pointer`
**Purpose**: Read a pointer value (4 bytes on 32-bit, 8 bytes on 64-bit).

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Memory address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "pointer": "0x12345678",
  "arch": "x86"
}
```

**Note**: Uses Cheat Engine's `readPointer()` which automatically reads 4 bytes for 32-bit targets and 8 bytes for 64-bit targets.

---

## 4. Memory Write

### `write_integer`
**Purpose**: Write a numeric value to memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to write to |
| `value` | int/float | Yes | - | Value to write |
| `type` | string | No | "dword" | "byte", "word", "dword", "qword", "float", "double" |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "value": 100,
  "type": "dword"
}
```

---

### `write_memory`
**Purpose**: Write raw bytes to memory.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Memory address to write to |
| `bytes` | array | Yes | Array of byte values (0-255) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "bytes_written": 8
}
```

**Example**:
```json
{"address": "0x12345678", "bytes": [0x90, 0x90, 0x90]}  // Write 3 NOP instructions
```

---

### `write_string`
**Purpose**: Write a string to memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to write to |
| `value` | string | Yes | - | String to write |
| `wide` | bool | No | false | Write as UTF-16 (widechar) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "length": 12,
  "wide": false
}
```

> **Caution**: Writing to memory can crash the target process. Ensure the address is writable and the data is valid.

---

## 5. Pattern Scanning

### `aob_scan` / `pattern_scan`
**Purpose**: Scan memory for a byte pattern (Array of Bytes).

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `pattern` | string | Yes | - | AOB pattern with wildcards (e.g., "4D 5A ?? 00") |
| `limit` | int | No | 100 | Maximum results to return |

**Returns**:
```json
{
  "success": true,
  "pattern": "4D 5A ?? 00",
  "count": 3,
  "addresses": ["0x00400000", "0x10000000", "0x20000000"]
}
```

**Tip**: Use `??` as wildcard for unknown bytes.

---

### `scan_all`
**Purpose**: Perform a value-based memory scan (like CE's memory scanner), bounded to
one scan window per call.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | string/int/float | Yes | - | Value to search for |
| `type` | string | No | "dword" | "byte", "word", "dword", "qword", "float", "double", "string" |
| `protection` | string | No | "+W-C" | CE protection filter for the scanned region |
| `start_address` | string | No | auto | Start of an explicit window |
| `size` | int | No | auto | Size of the explicit window (capped at 200,000) |
| `max_scan` | int | No | 200000 | Address budget when the window is chosen automatically |

**Returns**:
```json
{
  "success": true,
  "count": 47,
  "start_address": "0x00400000",
  "scanned_addresses": 200000,
  "max_scan_budget": 200000,
  "auto_window": true,
  "truncated": true,
  "next_start_address": "0x00430D40"
}
```

`count` is the number of matches; call `get_scan_results` to read them. When
`truncated` is true, continue from `next_start_address`.

---

### `get_scan_results`
**Purpose**: Retrieve results from the last `scan_all` / `next_scan` operation.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max` | int | No | 100 | Maximum results to return |

**Returns**:
```json
{
  "success": true,
  "total": 47,
  "returned": 2,
  "results": [
    {"address": "0x12345678", "value": "100"},
    {"address": "0x23456789", "value": "100"}
  ]
}
```

---

### `next_scan`
**Purpose**: Filter results from a previous scan (narrowing down addresses).

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | string | Yes | - | New value to scan for (used with "exact", "bigger", "smaller") |
| `scan_type` | string | No | "exact" | "exact", "increased", "decreased", "changed", "unchanged", "bigger", "smaller" |

**Returns**:
```json
{
  "success": true,
  "count": 15
}
```

**Workflow**:
```
1. scan_all(value="100")       → 50000 results
2. next_scan(scan_type="decreased")  → 500 results (value went down)
3. next_scan(value="95", scan_type="exact")  → 3 results
4. get_scan_results()          → ["0x12345678", "0x23456789", "0x34567890"]
```

**Note**: Requires a previous `scan_all` to be executed first.

---

### `search_string`
**Purpose**: Search for a text string in memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `string` | string | Yes | - | String to search for |
| `wide` | bool | No | false | Search as UTF-16 |
| `limit` | int | No | 100 | Maximum results |
| `start_address` | string | No | auto | Start of an explicit window |
| `size` | int | No | auto | Size of the explicit window |
| `max_scan` | int | No | 200000 | Address budget per window |
| `time_budget_ms` | int | No | 1500 | Wall-clock budget for the whole call |
| `max_windows` | int | No | 1 | Consecutive windows to walk in one call (max 64) |

**Returns**:
```json
{
  "success": true,
  "count": 3,
  "addresses": [
    {"address": "0x12345678", "preview": "Player"},
    {"address": "0x23456789", "preview": "PlayerName"}
  ],
  "start_address": "0x00400000",
  "scanned_bytes": 200000,
  "windows_scanned": 1,
  "truncated": true,
  "next_start_address": "0x00430D40"
}
```

---

## 6. Disassembly & Analysis

### `disassemble`
**Purpose**: Disassemble instructions starting from an address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Starting address |
| `count` | int | No | 10 | Number of instructions |

**Returns**:
```json
{
  "success": true,
  "start_address": "0x00400000",
  "instruction_count": 10,
  "instructions": [
    {"address": "0x00400000", "bytes": "55", "instruction": "push ebp", "size": 1},
    {"address": "0x00400001", "bytes": "8B EC", "instruction": "mov ebp,esp", "size": 2}
  ]
}
```

---

### `get_instruction_info`
**Purpose**: Get detailed information about a single instruction.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Instruction address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "instruction": "push ebp",
  "size": 1,
  "bytes": "55",
  "is_call": false,
  "is_jump": false,
  "is_ret": false
}
```

---

### `find_function_boundaries`
**Purpose**: Locate the start and end of a function containing the given address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Address within the function |
| `max_search` | int | No | 4096 | Maximum bytes to search |

**Returns**:
```json
{
  "success": true,
  "found": true,
  "query_address": "0x00401050",
  "function_start": "0x00401000",
  "function_end": "0x00401100",
  "function_size": 256
}
```

**Note**: Returns `found: false` if no standard prologue/epilogue is detected.

---

### `find_references`
**Purpose**: Find all code locations that reference a specific address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Target address to find references to |
| `limit` | int | No | 50 | Maximum results |

**Returns**:
```json
{
  "success": true,
  "target": "0x00401000",
  "count": 5,
  "references": [
    {"ref_address": "0x00402000", "instruction": "call 0x00401000"}
  ]
}
```

---

### `find_call_references`
**Purpose**: Find all CALL instructions that target a specific function.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `function_address` | string/int | Yes | - | Function address |
| `limit` | int | No | 100 | Maximum results |

**Returns**:
```json
{
  "success": true,
  "function_address": "0x00401000",
  "caller_count": 10,
  "callers": [
    {"caller_address": "0x00402050", "instruction": "call 0x00401000"}
  ]
}
```

---

### `analyze_function`
**Purpose**: Analyze a function to find all CALL instructions it makes.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Any address inside the function |
| `max_instructions` | int | No | 2000 | Maximum instructions to walk |
| `max_bytes` | int | No | 8192 | Maximum body size to read (0x100 - 0x10000) |

The address does not have to be the function start: the prologue is located by
searching backwards first.

**Returns**:
```json
{
  "success": true,
  "function_start": "0x00401000",
  "function_end": "0x004010F0",
  "arch": "x64",
  "prologue_type": "x64_standard",
  "instructions_analyzed": 50,
  "bytes_analyzed": 240,
  "truncated": false,
  "call_count": 2,
  "calls": [
    {
      "call_site": "0x00401020",
      "target": "0x00405000",
      "type": "relative"
    },
    {
      "call_site": "0x00401035",
      "instruction": "call qword ptr [rax+10]",
      "type": "indirect"
    }
  ]
}
```

`truncated` is true when the walk stopped on the instruction/byte cap rather than on
a `ret`. Indirect calls report no `target` because the destination is only known at
run time — set a breakpoint at the `call_site` to resolve it.

**Prologue Detection**:
- `x86_standard`: `55 8B EC` (push ebp; mov ebp, esp)
- `x64_standard`: `55 48 89 E5` (push rbp; mov rbp, rsp)
- `x64_leaf`: `48 83 EC xx` (sub rsp, xx) - leaf functions without frame pointer
- `unknown`: Non-standard or mid-function address

**Note**: Detects both direct CALL (E8) and indirect CALL (FF /2) instructions.

---

## 7. Breakpoints (Hardware Debug Registers)

> **Important**: All breakpoints use **hardware debug registers** (`bpmDebugRegister`), so no target instruction bytes are patched. They are still debugger events: each trigger briefly stops the thread while the callback runs, and hardware debug registers are detectable. Maximum 4 active breakpoints at a time (CPU limitation).

### `set_breakpoint` / `set_execution_breakpoint`
**Purpose**: Set a hardware breakpoint that triggers when code executes at the address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Code address |
| `id` | string | No | address | Unique identifier for this breakpoint |
| `capture_registers` | bool | No | true | Capture CPU registers on hit |
| `capture_stack` | bool | No | false | Capture stack values |
| `stack_depth` | int | No | 16 | Number of stack entries to capture |
| `one_shot` | bool | No | true | Remove after the first matching hit |
| `max_hits` | int | No | 1/0 | Defaults to 1 in one-shot mode and 0 when `one_shot=false` |
| `max_triggers` | int | No | 256 | Total event cap, including condition misses; 0 explicitly disables the cap |
| `conditions` | array | No | [] | ANDed register/memory conditions evaluated before capture |

**Condition forms**:
```json
[
  {"kind": "register", "register": "R8", "operator": "in", "values": [42, 123, 387]},
  {"kind": "memory", "base_register": "RDX", "offset": 0, "size": 1, "operator": "eq", "value": 1}
]
```

Memory conditions can use a direct `address` instead of `base_register`. Supported
sizes are 1, 2, 4, and 8 bytes. Supported operators are `eq`, `ne`, `lt`, `le`,
`gt`, `ge`, `in`, and `mask_eq` (`mask_eq` also requires `mask`).

**Returns**:
```json
{
  "success": true,
  "id": "bp1",
  "address": "0x00401000",
  "slot": 1,
  "active": true,
  "one_shot": true,
  "max_hits": 1,
  "max_triggers": 256,
  "condition_count": 0,
  "method": "hardware_debug_register"
}
```

Use the default one-shot mode on hot functions. Conditions reduce capture work but
cannot prevent the CPU/debugger event itself. If an MCP request is cancelled after it
was sent, call `status` before retrying because the breakpoint may already be active.
The bridge verifies installation and removal against `debug_getBreakpointList`. If
automatic removal cannot be verified, it sets `retirement_pending`, keeps the slot
tracked, and returns control to CE without resuming into another hit.

---

### `set_data_breakpoint` / `set_write_breakpoint`
**Purpose**: Set a hardware breakpoint that triggers on memory read/write access.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Data address to monitor |
| `id` | string | No | address | Unique identifier |
| `access_type` | string | No | "w" | "r" (read), "w" (write), "rw" (both) |
| `size` | int | No | 4 | Bytes to monitor (1, 2, 4, or 8) |
| `capture_registers` | bool | No | true | Capture CPU registers on a matching hit |
| `capture_stack` | bool | No | false | Capture stack values on a matching hit |
| `stack_depth` | int | No | 16 | Number of stack entries to capture |
| `one_shot` | bool | No | true | Remove after the first matching hit |
| `max_hits` | int | No | 1/0 | Defaults to 1 in one-shot mode and 0 when `one_shot=false` |
| `max_triggers` | int | No | 256 | Total event cap including misses |
| `conditions` | array | No | [] | Same condition format as `set_breakpoint` |

**Returns**:
```json
{
  "success": true,
  "id": "health_write",
  "address": "0x12345678",
  "slot": 2,
  "access_type": "w",
  "method": "hardware_debug_register"
}
```

---

### `get_breakpoint_hits`
**Purpose**: Retrieve logged breakpoint hits.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `id` | string | No | - | Specific breakpoint ID (omit for all) |
| `clear` | bool | No | false | Clear hits after retrieval |

**Returns**:
```json
{
  "success": true,
  "count": 5,
  "active": false,
  "retired_reason": "one_shot_complete",
  "trigger_count": 5,
  "matched_count": 1,
  "hits": [
    {
      "id": "bp1",
      "address": "0x00401000",
      "timestamp": 1733540000,
      "breakpoint_type": "hardware_execute",
      "registers": {"EAX": "0x00000001", "EBX": "0x00000000"}
    }
  ]
}
```

Completed one-shot/capped state is retained after the hardware slot is released.
`remove_breakpoint` discards both the retained state and any unread hits.

---

### `remove_breakpoint`
**Purpose**: Remove a breakpoint by ID.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `id` | string | Yes | Breakpoint ID to remove |

**Returns**:
```json
{
  "success": true,
  "id": "bp1"
}
```

---

### `list_breakpoints`
**Purpose**: List all active breakpoints.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 2,
  "breakpoints": [
    {"id": "bp1", "address": "0x00401000", "type": "execute", "slot": 1},
    {"id": "health_write", "address": "0x12345678", "type": "data", "slot": 2}
  ]
}
```

---

### `clear_all_breakpoints`
**Purpose**: Remove all active breakpoints.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "removed": 4
}
```

---

## 8. Memory Regions

### `get_memory_regions`
**Purpose**: Get memory regions using page protection sampling.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max` | int | No | 1000 | Maximum regions to return |

**Returns**:
```json
{
  "success": true,
  "count": 50,
  "regions": [
    {"address": "0x00400000", "readable": true, "writable": false, "executable": true}
  ]
}
```

---

### `enum_memory_regions_full`
**Purpose**: Get comprehensive memory map using native CE API.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max` | int | No | 10000 | Maximum regions |

**Returns**:
```json
{
  "success": true,
  "count": 500,
  "regions": [
    {
      "base_address": "0x00400000",
      "allocation_base": "0x00400000",
      "region_size": 4096,
      "state": "MEM_COMMIT",
      "protect": "PAGE_EXECUTE_READ",
      "type": "MEM_IMAGE",
      "readable": true,
      "writable": false,
      "executable": true
    }
  ]
}
```

---

## 9. Lua Evaluation

### `evaluate_lua`
**Purpose**: Execute arbitrary Lua code in Cheat Engine's context.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `code` | string | Yes | Lua code to execute |

**Returns**:
```json
{
  "success": true,
  "result": "return value as string"
}
```

**Example**:
```json
{"code": "return 1 + 1"}
→ {"success": true, "result": "2"}
```

> **Caution**: Use responsibly. Avoid infinite loops or memory-intensive operations.

---

## 10. High-Level Analysis Tools

### `dissect_structure`
**Purpose**: Automatically analyze memory and guess data types.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Base address |
| `size` | int | No | 256 | Bytes to analyze |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "size": 256,
  "element_count": 15,
  "elements": [
    {"offset": 0, "type": "Pointer", "size": 4, "value": "0x00401000"},
    {"offset": 4, "type": "4 Bytes", "size": 4, "value": "100"},
    {"offset": 8, "type": "Float", "size": 4, "value": "3.14159"}
  ]
}
```

---

### `get_thread_list`
**Purpose**: List all threads in the target process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 8,
  "threads": ["1234", "5678", "9012"]
}
```

---

### `auto_assemble`
**Purpose**: Execute a Cheat Engine Auto Assembler script.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `script` | string | Yes | Auto Assembler script |

**Returns**:
```json
{
  "success": true,
  "message": "Script assembled successfully"
}
```

> **Warning**: This can modify game memory. Use with caution.

---

### `read_pointer_chain`
**Purpose**: Follow a chain of pointers to resolve a dynamic address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `base` | string/int | Yes | Base address or symbol |
| `offsets` | array | Yes | Array of offsets to apply |

**Returns**:
```json
{
  "success": true,
  "base": "0x00400000",
  "offsets": [60, 0, 24],
  "final_address": "0x12345678",
  "final_value": 100,
  "arch": "x86",
  "chain": [
    {"step": 0, "address": "0x00400000", "read_value": "0x00500000"},
    {"step": 1, "address": "0x00500000", "offset_applied": 60, "read_value": "0x00600000"},
    {"step": 2, "address": "0x00600018", "offset_applied": 24, "read_value": "0x12345678"}
  ]
}
```

**Note**: Uses `readPointer()` for all dereference operations, automatically handling 32-bit (4-byte) and 64-bit (8-byte) pointers.

---

### `get_rtti_classname`
**Purpose**: Get C++ class name from RTTI information.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Object address (pointer to vtable) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "class_name": "CPlayer",
  "found": true
}
```

---

### `get_address_info`
**Purpose**: Convert a raw address to a symbolic name.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `include_modules` | bool | No | true | Include module names |
| `include_symbols` | bool | No | true | Include symbol names |
| `include_sections` | bool | No | false | Include section names |

**Returns**:
```json
{
  "success": true,
  "address": "0x00401000",
  "symbolic_name": "L2.exe+1000",
  "is_in_module": true
}
```

---

### `checksum_memory`
**Purpose**: Calculate MD5 hash of a memory region.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Start address |
| `size` | int | No | 256 | Bytes to hash |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "size": 256,
  "md5_hash": "d41d8cd98f00b204e9800998ecf8427e"
}
```

**Use Case**: Detect if game code has been modified (anti-tampering check).

---

### `generate_signature`
**Purpose**: Generate a unique AOB signature for an address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Target address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00401000",
  "signature": "55 8B EC 83 EC ?? 53 56 57",
  "offset_from_start": 0,
  "byte_count": 10,
  "usage_hint": "aob_scan('55 8B EC 83 EC ?? 53 56 57') then add offset 0 to reach target"
}
```

> ⚠️ **Warning**: This command calls `getUniqueAOB()` which scans ALL memory to find unique patterns. It can take **several minutes** and will block the pipe. Use only on specific code addresses, not generic locations like PE headers.

**Use Case**: Find the same code location after game updates (signature scanning).

---

## 11. DBVM Hypervisor Tools (Ring -1)

> **These tools require DBVM to be activated** (Edit → Settings → Debugger → Use DBVM). They operate at the hypervisor level (Ring -1), making them **100% invisible to anti-cheat software**.

### `get_physical_address`
**Purpose**: Convert a virtual address to its physical RAM address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Virtual memory address |

**Returns**:
```json
{
  "success": true,
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "physical_int": 439041101
}
```

**Note**: Requires DBK kernel driver to be loaded.

---

### `start_dbvm_watch` / `find_what_writes_safe`
**Purpose**: Start hypervisor-level memory access monitoring.

This is the **anti-cheat safe** equivalent of "Find what writes to this address".

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Address to monitor |
| `mode` | string | No | "w" | "w" (write), "r" (read), "rw" (both), "x" (execute) |
| `max_entries` | int | No | 1000 | Log buffer size |

**Returns**:
```json
{
  "success": true,
  "status": "monitoring",
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "watch_id": 1,
  "mode": "w",
  "note": "Call stop_dbvm_watch to retrieve results and stop monitoring"
}
```

---

### `stop_dbvm_watch` / `get_watch_results`
**Purpose**: Stop monitoring and retrieve all logged memory accesses.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Address that was being monitored |

**Returns**:
```json
{
  "success": true,
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "mode": "w",
  "hit_count": 3,
  "duration_seconds": 10,
  "hits": [
    {
      "hit_number": 1,
      "instruction_address": "0x00402000",
      "instruction": "mov [ecx+4], eax",
      "registers": {
        "RAX": "0x00000064",
        "RCX": "0x12345674",
        "RIP": "0x00402000"
      }
    }
  ],
  "note": "Found instructions that accessed the memory"
}
```

---

## Workflow Examples

### Example 1: Find and Monitor Health Value

```
1. scan_all(value="100", value_type="4Bytes")
2. get_scan_results() → [0x12345678, ...]
3. start_dbvm_watch(address="0x12345678", mode="w")
4. [Player takes damage in game]
5. stop_dbvm_watch(address="0x12345678")
   → Shows instruction at 0x00402000 wrote to health
6. disassemble(address="0x00402000", count=20)
   → Understand the damage calculation code
7. generate_signature(address="0x00402000")
   → Create AOB for future updates
```

### Example 2: Trace Pointer Chain

```
1. get_process_info() → main module at 0x00400000
2. read_pointer_chain(base="0x00400000", offsets=[0x1000, 0x10, 0x4])
   → Resolves to player structure at 0x12345678
3. dissect_structure(address="0x12345678", size=512)
   → Auto-detect fields (health at offset +0x100, mana at +0x104, etc.)
```

### Example 3: Find All Callers of a Function

```
1. aob_scan(pattern="55 8B EC 83 EC ?? A1 ?? ?? ?? ??")
   → Function at 0x00401000
2. find_call_references(function_address="0x00401000")
   → 15 callers found
3. For each caller, use disassemble() to understand context
```

---

## Error Handling

All commands return `success: false` with an `error` message on failure:

```json
{
  "success": false,
  "error": "Invalid address"
}
```

Common errors:
- `"Invalid address"` - Address could not be parsed
- `"Failed to read at 0x..."` - Memory is not readable
- `"No free hardware breakpoint slots"` - All 4 debug registers in use
- `"DBK driver not loaded"` - DBVM/DBK not initialized
- `"DBVM watch returned nil"` - DBVM not activated in CE settings

---

## Best Practices

1. **Call `status` first** to verify connectivity, process identity, and debugger capabilities
2. **Use `get_process_info`** to confirm the correct process is attached and check `targetIs64Bit`
3. **Use bounded one-shot breakpoints** and conditions on hot paths; never leave a high-frequency API unbounded
4. **Use DBVM only when explicitly needed and already active**; it is not required for normal MCP operation
5. **Clear breakpoints** when done to free debug register slots
6. **Generate signatures** for important addresses to survive game updates
7. **Use `checksum_memory`** to detect if code regions have changed
8. **Use `analyze_function`** to understand what a function calls before hooking
9. **Check `arch` field** in responses to verify 32/64-bit handling
