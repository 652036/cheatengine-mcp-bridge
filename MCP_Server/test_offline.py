#!/usr/bin/env python3
"""Offline regression tests for the Cheat Engine MCP bridge.

Unlike test_mcp.py, this needs neither Cheat Engine nor an attached process: it
loads ce_mcp_bridge.lua into a real Lua interpreter with the Cheat Engine API
stubbed out, and drives the command dispatcher against a synthetic memory map.

    pip install lupa
    python test_offline.py

Covers the defects fixed in 11.5.0 and 11.6.0:
  - JSON number precision (64-bit addresses were rounded by "%.14g")
  - \\uXXXX decoding (string.char raised for any codepoint above U+00FF)
  - the broad-pattern guard, which was defined but never called
  - multi-window scanning and the block-based prologue search
  - JSON-RPC error envelopes for malformed input
  - bounded conditional breakpoints that always continue and auto-retire
"""

import json
import os
import sys

try:
    import lupa
except ImportError:
    print("lupa is required for the offline tests: pip install lupa")
    sys.exit(0)

LUA = getattr(lupa, "lua54", None) or getattr(lupa, "lua53", None)
if LUA is None:
    print("lupa without a Lua 5.3/5.4 runtime; skipping")
    sys.exit(0)

BRIDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ce_mcp_bridge.lua")

FAILURES = []
CHECKS = 0


def check(name, ok, detail=""):
    global CHECKS
    CHECKS += 1
    print(("  PASS " if ok else "  FAIL ") + name + ("" if ok else "  -> " + str(detail)))
    if not ok:
        FAILURES.append(name)


def section(title):
    print("\n" + title)


# ===========================================================================
# Part 1: the embedded JSON library
# ===========================================================================

def test_json():
    src = open(BRIDGE, encoding="utf-8").read()
    start = src.index("local json = {}")
    end = src.index("-- COMMAND HANDLERS - PROCESS & MODULES")
    part = src[start:end]
    part = part[: part.rindex("json.decode = decode") + len("json.decode = decode")]

    rt = LUA.LuaRuntime()
    lua_json = rt.execute(part + "\nreturn json")
    encode = lua_json["encode"]
    raw_decode = lua_json["decode"]

    def decode(text):
        result = raw_decode(text)
        return result[0] if isinstance(result, tuple) else result

    section("[json] number precision - 64-bit addresses must survive intact")
    check("x64 pointer 0x7FF6A0001000", encode(140694538166272) == "140694538166272", encode(140694538166272))
    check("x64 pointer 0x7FFFFFFEFFFF", encode(140737488289791) == "140737488289791", encode(140737488289791))
    check("max 64-bit signed int", encode(0x7FFFFFFFFFFFFFFF) == "9223372036854775807", encode(0x7FFFFFFFFFFFFFFF))
    check("small integer", encode(4096) == "4096", encode(4096))
    check("negative integer", encode(-1) == "-1", encode(-1))
    check("float round-trips", float(encode(3.14)) == 3.14, encode(3.14))
    check("0.1 round-trips", float(encode(0.1)) == 0.1, encode(0.1))

    section("[json] table encoding & strict decode validation")
    check("empty table encodes as array", encode(rt.eval("{}")) == "[]", encode(rt.eval("{}")))
    check("dense 1..n table encodes as array", encode(rt.eval("{10, 20, 30}")) == "[10,20,30]", encode(rt.eval("{10, 20, 30}")))
    mixed_decoded = json.loads(encode(rt.eval('{"a", foo = "bar"}')))
    check("mixed table preserves both array and string keys",
          mixed_decoded == {"1": "a", "foo": "bar"}, mixed_decoded)
    zero_indexed = json.loads(encode(rt.eval('{[0] = "rsp0", [1] = "rsp8"}')))
    check("0-indexed table preserves key 0", zero_indexed == {"0": "rsp0", "1": "rsp8"}, zero_indexed)
    sparse = json.loads(encode(rt.eval('{[1] = "a", [3] = "c"}')))
    check("sparse array encodes as object without dropping [3]", sparse == {"1": "a", "3": "c"}, sparse)

    res_trail = raw_decode('{"a": 1} trailing')
    check("top-level decode rejects trailing garbage",
          isinstance(res_trail, tuple) and res_trail[0] is None and res_trail[1] == "trailing data",
          res_trail)
    res_null_trail = raw_decode('null garbage')
    check("top-level decode rejects trailing garbage after null",
          isinstance(res_null_trail, tuple) and res_null_trail[0] is None and res_null_trail[1] == "trailing data",
          res_null_trail)
    check("top-level decode allows trailing whitespace",
          decode('{"a": 1}   \n\t')["a"] == 1)
    for bad_u in ('"\\u12"', '"\\u+123"', '"\\u 041"', '"\\ud83d\\u12"', '"\\ud83d\\u+123"'):
        res_u = raw_decode(bad_u)
        check("rejects malformed \\u escape " + bad_u,
              isinstance(res_u, tuple) and res_u[0] is None, res_u)
    res_lone_esc = rt.execute(part + '\nreturn {unescapeJsonString("abc\\\\")}')
    check("unescapeJsonString rejects trailing lone backslash",
          res_lone_esc[1] is None and res_lone_esc[2] == "trailing backslash",
          (res_lone_esc[1], res_lone_esc[2]))

    section("[json] \\uXXXX decoding - non-ASCII must not raise")
    check("chinese", decode('"\\u4f60\\u597d"') == "你好")
    check("ascii escape", decode('"\\u0041"') == "A")
    check("latin-1", decode('"\\u00e9"') == "é")
    check("surrogate pair", decode('"\\ud83d\\ude00"') == "\U0001f600")
    check("escaped backslash before u", decode('"\\\\u0041"') == "\\u0041")
    check("standard escapes", decode('"a\\tb\\nc\\"d"') == 'a\tb\nc"d')

    section("[json] a request exactly as the Python server sends it")
    for ensure_ascii in (True, False):
        wire = json.dumps({
            "jsonrpc": "2.0",
            "method": "write_string",
            "params": {"address": "game.exe+1000", "value": "你好世界", "wide": True},
            "id": 7,
        }, ensure_ascii=ensure_ascii)
        parsed = decode(wire)
        label = "ensure_ascii=%s" % ensure_ascii
        check(label + " method", parsed["method"] == "write_string")
        check(label + " non-ascii value", parsed["params"]["value"] == "你好世界")
        check(label + " bool", parsed["params"]["wide"] is True)
        check(label + " id", parsed["id"] == 7)

    section("[json] lua encode -> python json.loads")
    payload = rt.eval('{address = "0x7FF6A0001000", value = 140694538166272}')
    decoded = json.loads(encode(payload))
    check("address parses exactly", decoded["value"] == 140694538166272, decoded)
    check("stays an int", isinstance(decoded["value"], int), type(decoded["value"]))


# ===========================================================================
# Part 2: the dispatcher, against a stubbed Cheat Engine
# ===========================================================================

REGION_A = 0x400000
REGION_B = 0x500000
REGION_SIZE = 0x40000          # larger than the 200,000-address window budget
NEEDLE = [0x48, 0x8B, 0x05, 0xDE, 0xAD, 0xBE, 0xEF]
NEEDLE_A_OFF = 0x1000
NEEDLE_B_OFF = 0x2000
PROLOGUE_OFF = 0x10000
FUNC = [0x55, 0x48, 0x89, 0xE5] + [0x90] * 8 + [0xC3]   # push rbp; mov rbp,rsp; nops; ret

STUBS = """
_G.getTickCount = function() return os.clock() * 1000 end
_G.__force_pid_failure = false
_G.getOpenedProcessID = function()
    if _G.__force_pid_failure then error("forced PID query failure") end
    return 4242
end
_G.targetIs64Bit = function() return true end
_G.processMessages = function() end
_G.print = function() end
_G.sleep = function() end
_G.createThread = function() return nil end
_G.reinitializeSymbolhandler = function() end
_G.disassemble = function() return "stub_insn" end
_G.getInstructionSize = function() return 1 end
_G.readString = function() return "" end
_G.getAddressSafe = function(v)
    if type(v) == "number" then return v end
    local hex = tostring(v):match("^0[xX](%%x+)$")
    if hex then return tonumber(hex, 16) end
    return tonumber(v)
end
_G.enumMemoryRegions = function()
    return {
        {BaseAddress = %d, RegionSize = %d, State = 0x1000, Protect = 0x20},
        {BaseAddress = %d, RegionSize = %d, State = 0x1000, Protect = 0x20},
    }
end
_G.readBytes = function(addr, size, asTable)
    if not asTable then return py_read_byte(addr) end
    local out = {}
    for i = 0, size - 1 do out[i + 1] = py_read_byte(addr + i) end
    return out
end
_G.bptExecute = 0
_G.bptWrite = 1
_G.bptAccess = 2
_G.bpmDebugRegister = 3
_G.co_run = 0
_G.RDX = 0
_G.R8 = 0
_G.RSP = 0x700000
_G.RIP = 0x401000
_G.__bp_callbacks = {}
_G.__installed_breakpoints = {}
_G.__removed_breakpoints = {}
_G.__continue_count = 0
_G.__force_install_failure = false
_G.__force_remove_failure = false
_G.__force_continue_failure = false
_G.debug_isDebugging = function() return true end
_G.debug_setBreakpoint = function(addr, size, trigger, method, callback)
    if not _G.__force_install_failure then
        _G.__bp_callbacks[addr] = callback
        _G.__installed_breakpoints[addr] = true
    end
    -- Real CE does not document a success return.
    return nil
end
_G.debug_removeBreakpoint = function(addr)
    if _G.__force_remove_failure then return false end
    _G.__bp_callbacks[addr] = nil
    _G.__installed_breakpoints[addr] = nil
    _G.__removed_breakpoints[addr] = true
    return true
end
_G.debug_getBreakpointList = function()
    local result = {}
    for addr in pairs(_G.__installed_breakpoints) do
        table.insert(result, addr)
    end
    if #result == 0 then return nil end
    return result
end
_G.debug_continueFromBreakpoint = function(mode)
    if _G.__force_continue_failure then error("forced continue failure") end
    _G.__continue_count = _G.__continue_count + 1
end
""" % (REGION_A, REGION_SIZE, REGION_B, REGION_SIZE)


def build_runtime():
    memory = {}
    for base, off in ((REGION_A, NEEDLE_A_OFF), (REGION_B, NEEDLE_B_OFF)):
        for i, b in enumerate(NEEDLE):
            memory[base + off + i] = b
    for i, b in enumerate(FUNC):
        memory[REGION_A + PROLOGUE_OFF + i] = b

    rt = LUA.LuaRuntime()
    rt.globals()["py_read_byte"] = lambda addr: memory.get(int(addr), 0)
    rt.execute(STUBS)

    src = open(BRIDGE, encoding="utf-8").read()
    src = src.replace("\nStartMCPBridge(false)", "\n-- autostart disabled for offline tests")
    src += "\n_G.__TEST = { executeCommand = executeCommand, idleWatchdogTick = idleWatchdogTick }\n"

    chunk = rt.eval("load")(src, "bridge")
    if chunk is None:
        raise SystemExit("ce_mcp_bridge.lua failed to load")
    chunk()
    return rt.globals()["__TEST"]["executeCommand"], rt


def test_debugger_preflight():
    execute, rt = build_runtime()

    def call(method, params=None):
        return json.loads(execute(json.dumps({"jsonrpc": "2.0", "method": method,
                                             "params": params or {}, "id": 1})))["result"]

    section("[breakpoints] inactive/unknown debugger never reaches native installation")
    rt.execute('debug_setBreakpoint = function() error("must not install") end')
    for probe in ('function() return false end', 'nil',
                  'function() error("probe failed") end', 'function() return nil end'):
        rt.execute('debug_isDebugging = ' + probe)
        for method in ("set_breakpoint", "set_data_breakpoint",
                       "set_execution_breakpoint", "set_write_breakpoint"):
            r = call(method, {"address": "0x401000", "id": "guarded"})
            check(method + " refuses " + probe, r.get("success") is False and
                  "must not install" not in r.get("error", ""), r)
        r = call("status")
        check("failed preflight leaves no tracked slot", r["hw_breakpoint_slots_used"] == 0, r)
        check("status reports debugger requirement", r["breakpoint_requires_started_debugger"] is True, r)

    # Refusal must preserve an existing breakpoint when a replacement is requested.
    execute, rt = build_runtime()
    call("set_breakpoint", {"address": "0x401000", "id": "keep"})
    rt.execute('debug_isDebugging = function() return false end')
    call("set_breakpoint", {"address": "0x401000", "id": "keep"})
    check("preflight refusal preserves existing breakpoint",
          rt.globals()["__installed_breakpoints"][0x401000] is True)
    check("status reports debugger not started", call("status")["debugger_started"] is False)


def test_dispatcher():
    execute, rt = build_runtime()
    counter = [0]

    def call(method, params=None):
        counter[0] += 1
        raw = execute(json.dumps({"jsonrpc": "2.0", "method": method,
                                  "params": params or {}, "id": counter[0]}))
        envelope = json.loads(raw)
        assert envelope.get("id") == counter[0], envelope
        return envelope.get("result", envelope)

    needle = " ".join("%02X" % b for b in NEEDLE)

    section("[aob_scan] one window by default")
    r = call("aob_scan", {"pattern": needle, "protection": "+X", "limit": 10})
    check("succeeds", r.get("success") is True, r)
    check("finds the needle", r.get("count") == 1, r.get("count"))
    check("exact address", r.get("addresses", [{}])[0].get("address", "").upper().endswith("401000"),
          r.get("addresses"))
    check("region bigger than budget is truncated", r.get("truncated") is True, r)
    check("one window scanned", r.get("windows_scanned") == 1, r.get("windows_scanned"))
    check("returns a continuation cursor", isinstance(r.get("next_start_address"), str), r)

    section("[aob_scan] max_windows walks into the next region")
    r = call("aob_scan", {"pattern": needle, "protection": "+X", "limit": 10,
                          "max_windows": 8, "time_budget_ms": 10000})
    addrs = [a["address"].upper() for a in r.get("addresses", [])]
    check("finds both needles", r.get("count") == 2, addrs)
    check("reached the second region", any(a.endswith("502000") for a in addrs), addrs)
    check("used more than one window", r.get("windows_scanned", 0) > 1, r.get("windows_scanned"))

    section("[aob_scan] broad-pattern guard")
    r = call("aob_scan", {"pattern": "?? ?? ?? ??", "protection": "+X"})
    check("refuses wildcard-only unbounded scan", r.get("success") is False, r)
    check("says why", "low-entropy" in str(r.get("error", "")), r.get("error"))
    r = call("aob_scan", {"pattern": "?? ?? ?? ??", "protection": "+X", "allow_unsafe_global": True})
    check("allowed on explicit opt-in", r.get("success") is True, r)
    r = call("aob_scan", {"pattern": "?? ?? ?? ??", "start_address": hex(REGION_A), "size": 4096})
    check("allowed inside a bounded window", r.get("success") is True, r)

    section("[aob_scan] explicit start_address + size")
    r = call("aob_scan", {"pattern": needle, "start_address": hex(REGION_A), "size": 0x2000})
    check("finds needle inside the range", r.get("count") == 1, r)
    check("flagged as bounded", r.get("bounded") is True, r)
    r = call("aob_scan", {"pattern": needle, "start_address": hex(REGION_A), "size": 0x100})
    check("finds nothing outside the range", r.get("count") == 0, r)

    section("[find_function_boundaries] prologue search from mid-function")
    r = call("find_function_boundaries",
             {"address": hex(REGION_A + PROLOGUE_OFF + 6), "max_search": 4096})
    check("succeeds", r.get("success") is True, r)
    check("found a prologue", r.get("found") is True, r)
    check("correct start", r.get("function_start", "").upper().endswith("410000"),
          r.get("function_start"))
    check("x64 prologue detected", r.get("prologue_type") == "x64_standard", r.get("prologue_type"))
    check("found the ret", r.get("function_end", "").upper().endswith("41000C"),
          r.get("function_end"))

    section("[dispatcher] JSON-RPC error envelopes")
    r = call("no_such_method")
    check("unknown method -> -32601", r.get("error", {}).get("code") == -32601, r)
    check("parse error -> -32700",
          json.loads(execute("{not json"))["error"]["code"] == -32700)
    check("non-object params -> -32602",
          json.loads(execute(json.dumps({"method": "ping", "params": "nope", "id": 1})))
          ["error"]["code"] == -32602)

    section("[breakpoints] conditional one-shot capture and reliable continue")
    bp_address = REGION_A + 0x3000
    r = call("set_breakpoint", {
        "address": hex(bp_address),
        "id": "conditional_once",
        "one_shot": True,
        "max_triggers": 8,
        "capture_registers": True,
        "conditions": [
            {"kind": "register", "register": "R8", "operator": "in", "values": [42, 123]},
            {"kind": "memory", "base_register": "RDX", "offset": 0,
             "size": 1, "operator": "eq", "value": NEEDLE[0]},
        ],
    })
    check("installs bounded breakpoint", r.get("success") is True and r.get("active") is True, r)

    rt.globals()["RDX"] = REGION_A + NEEDLE_A_OFF
    rt.globals()["R8"] = 41
    rt.globals()["__bp_callbacks"][bp_address]()
    r = call("get_breakpoint_hits", {"id": "conditional_once", "clear": False})
    check("condition miss is not buffered", r.get("count") == 0, r)
    check("condition miss keeps breakpoint active", r.get("active") is True, r)
    check("condition miss still continues target", rt.globals()["__continue_count"] == 1,
          rt.globals()["__continue_count"])

    rt.globals()["R8"] = 42
    rt.globals()["__bp_callbacks"][bp_address]()
    r = call("get_breakpoint_hits", {"id": "conditional_once", "clear": False})
    check("matching hit is buffered", r.get("count") == 1, r)
    check("one-shot auto-retires", r.get("active") is False, r)
    check("retirement reason is retained", r.get("retired_reason") == "one_shot_complete", r)
    check("both debugger events continued", rt.globals()["__continue_count"] == 2,
          rt.globals()["__continue_count"])
    r = call("list_breakpoints")
    check("auto-retirement releases hardware slot", r.get("count") == 0, r)

    section("[breakpoints] trigger cap prevents endless condition misses")
    capped_address = REGION_A + 0x3100
    r = call("set_breakpoint", {
        "address": hex(capped_address),
        "id": "never_matches",
        "one_shot": True,
        "max_triggers": 2,
        "capture_registers": False,
        "conditions": [
            {"kind": "register", "register": "R8", "operator": "eq", "value": 999},
        ],
    })
    check("installs capped breakpoint", r.get("success") is True, r)
    capped_callback = rt.globals()["__bp_callbacks"][capped_address]
    capped_callback()
    capped_callback()
    r = call("get_breakpoint_hits", {"id": "never_matches", "clear": False})
    check("trigger cap auto-retires", r.get("active") is False, r)
    check("trigger cap reason retained", r.get("retired_reason") == "max_triggers_reached", r)
    check("trigger cap counted misses", r.get("trigger_count") == 2, r)
    check("invalid register rejected before install",
          call("set_breakpoint", {
              "address": hex(REGION_A + 0x3200),
              "conditions": [{"kind": "register", "register": "NOPE",
                              "operator": "eq", "value": 1}],
          }).get("success") is False)

    section("[breakpoints] data watch uses the same bounded lifecycle")
    data_address = REGION_A + NEEDLE_A_OFF
    r = call("set_data_breakpoint", {
        "address": hex(data_address),
        "id": "data_once",
        "size": 1,
        "capture_registers": False,
    })
    check("installs one-shot data breakpoint", r.get("success") is True and r.get("active") is True, r)
    rt.globals()["__bp_callbacks"][data_address]()
    r = call("get_breakpoint_hits", {"id": "data_once", "clear": False})
    check("data hit captured", r.get("count") == 1, r)
    check("data hit value matches memory", r.get("hits", [{}])[0].get("value") == "0x00000048", r)
    check("data breakpoint releases slot", r.get("active") is False, r)

    section("[breakpoints] install/remove/continue failure paths stay observable")
    failed_install_address = REGION_A + 0x3300
    rt.globals()["__force_install_failure"] = True
    r = call("set_breakpoint", {
        "address": hex(failed_install_address),
        "id": "install_fails",
    })
    check("missing CE breakpoint is rejected", r.get("success") is False, r)
    rt.globals()["__force_install_failure"] = False
    check("failed install does not consume a slot",
          call("list_breakpoints").get("count") == 0)

    remove_failure_address = REGION_A + 0x3400
    r = call("set_breakpoint", {
        "address": hex(remove_failure_address),
        "id": "remove_fails",
    })
    check("remove-failure test installs", r.get("success") is True, r)
    remove_failure_callback = rt.globals()["__bp_callbacks"][remove_failure_address]
    rt.globals()["__force_remove_failure"] = True
    continues_before_remove_failure = rt.globals()["__continue_count"]
    callback_result = remove_failure_callback()
    r = call("get_breakpoint_hits", {"id": "remove_fails", "clear": False})
    check("failed auto-remove stays tracked", r.get("active") is True, r)
    check("failed auto-remove returns control to CE", callback_result == 0, callback_result)
    check("failed auto-remove does not resume into another hit",
          rt.globals()["__continue_count"] == continues_before_remove_failure,
          rt.globals()["__continue_count"])
    check("failed auto-remove exposes error", bool(r.get("retire_error")), r)
    check("failed auto-remove marks retirement pending", r.get("retirement_pending") is True, r)
    rt.globals()["__force_remove_failure"] = False
    check("manual retry removes retained breakpoint",
          call("remove_breakpoint", {"id": "remove_fails"}).get("success") is True)

    continue_failure_address = REGION_A + 0x3500
    r = call("set_breakpoint", {
        "address": hex(continue_failure_address),
        "id": "continue_fails",
    })
    check("continue-failure test installs", r.get("success") is True, r)
    continue_failure_callback = rt.globals()["__bp_callbacks"][continue_failure_address]
    rt.globals()["__force_continue_failure"] = True
    callback_result = continue_failure_callback()
    rt.globals()["__force_continue_failure"] = False
    r = call("get_breakpoint_hits", {"id": "continue_fails", "clear": False})
    check("continue failure returns control to CE", callback_result == 0, callback_result)
    check("continue failure is reported", bool(r.get("continue_error")), r)
    check("one-shot removed before failed continue", r.get("active") is False, r)

    pid_guard_address = REGION_A + 0x3580
    r = call("set_breakpoint", {
        "address": hex(pid_guard_address),
        "id": "pid_guard",
        "capture_registers": False,
    })
    check("PID guard test installs", r.get("success") is True, r)
    rt.globals()["__force_pid_failure"] = True
    r = call("list_breakpoints")
    check("PID query failure is reported", r.get("success") is False, r)
    rt.globals()["__force_pid_failure"] = False
    r = call("list_breakpoints")
    check("PID query failure preserves active state",
          r.get("count") == 1 and r.get("breakpoints", [{}])[0].get("id") == "pid_guard", r)
    check("PID guard cleanup succeeds",
          call("remove_breakpoint", {"id": "pid_guard"}).get("success") is True)

    section("[breakpoints] repeated sampling requires explicit limits")
    repeated_address = REGION_A + 0x3600
    r = call("set_breakpoint", {
        "address": hex(repeated_address),
        "id": "bounded_repeat",
        "one_shot": False,
        "max_triggers": 3,
        "capture_registers": False,
    })
    check("one_shot false defaults to unlimited matching hits", r.get("max_hits") == 0, r)
    repeated_callback = rt.globals()["__bp_callbacks"][repeated_address]
    repeated_callback()
    repeated_callback()
    r = call("get_breakpoint_hits", {"id": "bounded_repeat", "clear": False})
    check("repeated breakpoint remains active before trigger cap", r.get("active") is True, r)
    check("repeated breakpoint retained two hits", r.get("count") == 2, r)
    repeated_callback()
    r = call("get_breakpoint_hits", {"id": "bounded_repeat", "clear": False})
    check("trigger cap retires repeated breakpoint", r.get("active") is False, r)
    check("unaligned data breakpoint rejected",
          call("set_data_breakpoint", {
              "address": hex(REGION_A + 1),
              "size": 4,
          }).get("success") is False)

    section("[lifecycle] handler reload never synchronously restarts a live worker")
    rt.execute("""
        _G.createThread = function(fn)
            return {
                Terminated = false,
                terminate = function()
                    _G.__CE_MCP_BRIDGE_STATE.workerDone = true
                end,
                destroy = function() end
            }
        end
    """)
    state = rt.globals()["__CE_MCP_BRIDGE_STATE"]
    state["workerThread"] = rt.globals()["createThread"](None)
    state["workerDone"] = False
    state["workerVersion"] = "11.6.2"
    state["workerTransportVersion"] = 1
    state["workerPipeName"] = "CE_MCP_Bridge_v99"
    state["workerHotReload"] = True
    state["workerGeneration"] = 10
    check("global dispatcher is published",
          rt.globals()["__CE_MCP_BRIDGE_DISPATCHER"] is not None and
          state["dispatcherVersion"] == "11.6.3")
    reload_src = open(BRIDGE, encoding="utf-8").read()
    reload_chunk = rt.eval("load")(reload_src, "bridge_hot_reload")
    reload_chunk()
    check("full script hot reload preserves live worker",
          state["workerGeneration"] == 10 and
          state["dispatcherVersion"] == "11.6.3")

    state["workerPipeName"] = "CE_MCP_Bridge_other"
    incompatible_reload_chunk = rt.eval("load")(reload_src, "bridge_pipe_change")
    incompatible_reload_chunk()
    check("pipe-name change never auto-restarts worker",
          state["workerGeneration"] == 10 and state["workerDone"] is False)

    state["workerPipeName"] = "CE_MCP_Bridge_v99"
    state["workerHotReload"] = False
    legacy_reload_chunk = rt.eval("load")(reload_src, "bridge_legacy_reload")
    legacy_reload_chunk()
    check("legacy worker is not restarted from script load",
          state["workerGeneration"] == 10 and state["workerDone"] is False)

    state["dispatchInProgress"] = True
    check("stop is refused from active MCP dispatch",
          rt.globals()["StopMCPBridge"]() is False and
          state["workerGeneration"] == 10)
    state["dispatchInProgress"] = False

    state["workerThread"] = None
    state["workerDone"] = True
    check("fresh worker enables hot reload",
          rt.globals()["StartMCPBridge"](False) is True and
          state["workerGeneration"] == 11 and
          state["workerVersion"] == "11.6.3" and
          state["workerHotReload"] is True and
          state["workerPipeName"] == "CE_MCP_Bridge_v99")


def test_idle_watchdog():
    execute, rt = build_runtime()
    tick = rt.globals()["__TEST"]["idleWatchdogTick"]
    rt.execute("""
        _G.__now = 0
        _G.getTickCount = function() return _G.__now end
        _G.__kicks = 0
        _G.__make_pipe = function()
            return { disconnect = function() _G.__kicks = _G.__kicks + 1 end }
        end
    """)
    state = rt.globals()["__CE_MCP_BRIDGE_STATE"]
    g = rt.globals()

    def at(ms):
        g["__now"] = ms
        tick()

    section("[idle] watchdog drops a silent client so others can connect")
    state["workerPipe"] = g["__make_pipe"]()
    state["connected"] = True
    state["dispatchInProgress"] = False
    at(1000)
    at(1000 + 59000)
    check("idle client below limit is kept", g["__kicks"] == 0, g["__kicks"])

    g["__now"] = 30000
    execute(json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1}))
    at(30000 + 59000)
    check("request activity restarts the idle clock", g["__kicks"] == 0, g["__kicks"])
    at(30000 + 60000)
    check("client silent for 60s is disconnected", g["__kicks"] == 1, g["__kicks"])

    state["workerPipe"] = g["__make_pipe"]()   # worker re-listened; a new client arrived
    at(200000)
    check("new client is not kicked for the previous client's idleness", g["__kicks"] == 1, g["__kicks"])

    state["dispatchInProgress"] = True
    at(500000)
    check("never kicks while a command executes", g["__kicks"] == 1, g["__kicks"])
    state["dispatchInProgress"] = False

    status = json.loads(execute(json.dumps({"jsonrpc": "2.0", "method": "status",
                                            "params": {}, "id": 2})))["result"]
    check("status reports idle kick limit", status.get("idle_kick_ms") == 60000, status)

    state["workerWriting"] = True
    at(30000 + 120000)
    check("never kicks while worker writes response", g["__kicks"] == 1, g["__kicks"])
    state["workerWriting"] = False

    state["connected"] = False
    state["workerPipe"] = None


def test_optimizations_and_edge_fixes():
    execute, rt = build_runtime()
    counter = [0]

    def call(method, params=None):
        counter[0] += 1
        raw = execute(json.dumps({"jsonrpc": "2.0", "method": method,
                                  "params": params or {}, "id": counter[0]}))
        return json.loads(raw)

    section("[fixes] UTF-8 sanitization, malformed JSON, 64-bit hex, read_memory/string, DBVM/AA")

    # 1. Invalid UTF-8 lead bytes (0xF5..0xFF) must be escaped rather than passed through
    rt.execute('_G.readString = function() return string.char(0xFF, 0x80, 0x80, 0x41) end')
    r = call("read_string", {"address": "0x401000"})["result"]
    check("read_string escapes 0xFF lead byte", r.get("value") == "\\xFF\\x80\\x80A" and r.get("contains_escaped_bytes") is True, r)

    # 2. read_string failure returns success=False
    rt.execute('_G.readString = function() return nil end')
    r = call("read_string", {"address": "0x401000"})["result"]
    check("read_string returns success=False on nil", r.get("success") is False, r)

    # 3. Malformed nested JSON returns clean -32700 Parse error (not uncaught crash)
    for bad in ('{"jsonrpc":"2.0","method":"ping","params":[1, tru],"id":1}',
                '{"jsonrpc":"2.0","method":"ping","params":{"a": tru},"id":1}'):
        env = json.loads(execute(bad))
        check("malformed nested JSON -> -32700", env.get("error", {}).get("code") == -32700, env)

    # 4. get_process_info skips reinitializeSymbolhandler unless refresh_symbols=True
    rt.execute('_G.__reinit_calls = 0; _G.reinitializeSymbolhandler = function() _G.__reinit_calls = _G.__reinit_calls + 1 end')
    rt.execute('_G.enumModules = function() return {{Name="game.exe", Address=0x400000, Size=0x1000}} end')
    call("get_process_info")
    check("get_process_info skips symbol refresh by default", rt.globals()["__reinit_calls"] == 0)
    call("get_process_info", {"refresh_symbols": True})
    check("get_process_info refreshes symbols when requested", rt.globals()["__reinit_calls"] == 1)

    # 5. read_memory include_bytes=False omits bytes array
    r = call("read_memory", {"address": hex(REGION_A + NEEDLE_A_OFF), "size": 4, "include_bytes": False})["result"]
    check("read_memory include_bytes=False omits bytes", r.get("success") is True and "bytes" not in r and r.get("data") == "48 8B 05 DE", r)

    # 6. read_pointer_chain negative offset & high-bit 64-bit kernel pointer
    rt.execute('''
        _G.readPointer = function(addr)
            if addr == 0x401000 then return 0xFFFF800000001000 end
            return 42
        end
    ''')
    r = call("read_pointer_chain", {"base": "0x401000", "offsets": [-16]})["result"]
    check("negative offset formatted cleanly", r.get("chain", [{}])[1].get("hex_offset") == "-0x10", r)
    check("high-bit 64-bit address formatted unsigned", r.get("final_address") == "0xFFFF800000000FF0", r)

    # 7. find_call_references supports max_windows across regions
    rt.execute('''
        _G.__call_targets = {}
        local baseA = 0x400000
        local baseB = 0x500000
        local target = 0x400100
        _G.readBytes = function(addr, size, asTable)
            local out = {}
            for i = 0, size - 1 do
                local a = addr + i
                local b = 0
                if a == baseB + 0x10 then b = 0xE8
                elseif a >= baseB + 0x11 and a <= baseB + 0x14 then
                    local rel = target - ((baseB + 0x10) + 5)
                    if rel < 0 then rel = rel + 0x100000000 end
                    local shift = (a - (baseB + 0x11)) * 8
                    b = math.floor(rel / (2 ^ shift)) % 256
                end
                out[i + 1] = b
            end
            return out
        end
    ''')
    r = call("find_call_references", {"address": "0x400100", "max_windows": 8, "time_budget_ms": 5000})["result"]
    check("find_call_references walks multiple windows", r.get("success") is True and r.get("count") == 1 and r.get("windows_scanned", 0) > 1, r)

    # 8. auto_assemble reports real disable error and clears aa_scripts on PID change
    rt.execute('_G.autoAssemble = function(script, disableInfo) if disableInfo then return false, "hook modified externally" end return true, {symbols={}, allocs={}} end')
    r = call("auto_assemble", {"script": "[ENABLE]\n[DISABLE]", "id": "aa1"})["result"]
    check("auto_assemble stores script", r.get("success") is True and r.get("disable_available") is True, r)
    r = call("auto_assemble", {"disable": True, "id": "aa1"})["result"]
    check("auto_assemble disable surfaces error detail", r.get("success") is False and "hook modified externally" in r.get("error", ""), r)

    # 9. poll_dbvm_watch honors clear=False sticky buffering
    rt.execute('''
        _G.dbk_initialized = function() return true end
        _G.dbvm_initialized = function() return true end
        _G.dbk_getPhysicalAddress = function() return 0x123000 end
        _G.dbvm_watch_writes = function() return 7 end
        _G.__dbvm_batch = 0
        _G.dbvm_watch_retrievelog = function()
            _G.__dbvm_batch = _G.__dbvm_batch + 1
            if _G.__dbvm_batch == 1 then return {{RIP = 0x401000, RAX = 1, R8 = 9}} end
            if _G.__dbvm_batch == 2 then return {{RIP = 0x401010, RAX = 2, R8 = 10}} end
            return {}
        end
        _G.dbvm_watch_disable = function() return true end
    ''')
    call("start_dbvm_watch", {"address": "0x402000", "mode": "w"})
    r1 = call("poll_dbvm_watch", {"address": "0x402000", "clear": False})["result"]
    r2 = call("poll_dbvm_watch", {"address": "0x402000", "clear": True})["result"]
    r3 = call("poll_dbvm_watch", {"address": "0x402000", "clear": True})["result"]
    check("poll_dbvm_watch clear=False keeps buffered hits", r1.get("hit_count") == 1 and r2.get("hit_count") == 2 and r3.get("hit_count") == 0, (r1, r2, r3))
    check("poll_dbvm_watch includes 64-bit registers", r2.get("hits", [{}])[0].get("R8") == "0x00000009", r2)
    call("stop_dbvm_watch", {"address": "0x402000"})

    # 10. StopMCPBridge cleans up idleTimer
    rt.execute('''
        _G.__idle_destroyed = false
        _G.__CE_MCP_BRIDGE_STATE.idleTimer = { destroy = function() _G.__idle_destroyed = true end }
    ''')
    rt.globals()["StopMCPBridge"]()
    check("StopMCPBridge destroys idleTimer", rt.globals()["__idle_destroyed"] is True)

    # 11. Slow enumMemoryRegions() must not starve scan time_budget_ms
    execute2, rt2 = build_runtime()
    rt2.execute('''
        _G.__tick = 1000
        _G.getTickCount = function() return _G.__tick end
        _G.__orig_enum = _G.enumMemoryRegions
        _G.enumMemoryRegions = function()
            _G.__tick = _G.__tick + 5000  -- simulate 5s enumMemoryRegions
            return _G.__orig_enum()
        end
    ''')
    needle = " ".join("%02X" % b for b in NEEDLE)
    r_slow_enum = json.loads(execute2(json.dumps({
        "jsonrpc": "2.0", "method": "aob_scan",
        "params": {"pattern": needle, "protection": "+X", "time_budget_ms": 1500, "max_windows": 4},
        "id": 1,
    })))["result"]
    check("slow enumMemoryRegions still scans memory instead of 0 bytes",
          r_slow_enum.get("success") is True and r_slow_enum.get("scanned_bytes", 0) > 0 and r_slow_enum.get("count", 0) >= 1,
          r_slow_enum)


def test_bridge_hardening_regressions():
    execute, rt = build_runtime()
    counter = [0]

    def call(method, params=None):
        counter[0] += 1
        raw = execute(json.dumps({"jsonrpc": "2.0", "method": method,
                                  "params": params or {}, "id": counter[0]}))
        return json.loads(raw)

    section("[hardening] captureStack bulk read, [RSP+0] preserved, 32/64-bit, fallback")
    rt.execute('''
        _G.__stack_read_calls = 0
        _G.__qword_calls = 0
        _G.__dword_calls = 0
        _G.__orig_readBytes_stack = _G.readBytes
        _G.__stack_mem = {
            [0x700000] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x01}, -- 0x0177665544332211
            [0x700008] = {0x00, 0x10, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF}, -- 0xFFFF800000001000
            [0x700010] = {0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00}, -- 0xDEADBEEF
        }
        _G.readBytes = function(addr, size, asTable)
            if addr == 0x700000 then
                _G.__stack_read_calls = _G.__stack_read_calls + 1
                if _G.__force_stack_bulk_fail then return nil end
                local out = {}
                for i = 0, size - 1 do
                    local slotBase = addr + math.floor(i / 8) * 8
                    local slot = _G.__stack_mem[slotBase]
                    out[i + 1] = slot and slot[(i % 8) + 1] or 0
                end
                return out
            end
            return _G.__orig_readBytes_stack(addr, size, asTable)
        end
        _G.readQword = function(addr)
            _G.__qword_calls = _G.__qword_calls + 1
            if addr == 0x700000 then return 0x0177665544332211 end
            return 0x2222
        end
        _G.readInteger = function(addr)
            _G.__dword_calls = _G.__dword_calls + 1
            return 0xCAFEBABE
        end
    ''')
    bp_stack_1 = REGION_A + 0x3700
    call("set_breakpoint", {
        "address": hex(bp_stack_1),
        "id": "stack_d1",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 1,
    })
    rt.globals()["__bp_callbacks"][bp_stack_1]()
    r = call("get_breakpoint_hits", {"id": "stack_d1"})["result"]
    stack_1 = r.get("hits", [{}])[0].get("stack")
    check("captureStack depth=1 encodes as 1-element JSON array preserving [RSP+0]",
          isinstance(stack_1, list) and stack_1 == ["0x177665544332211"], (stack_1, r))
    check("captureStack used single bulk readBytes without readQword fallback",
          rt.globals()["__stack_read_calls"] == 1 and rt.globals()["__qword_calls"] == 0,
          (rt.globals()["__stack_read_calls"], rt.globals()["__qword_calls"]))

    bp_stack_3 = REGION_A + 0x3710
    call("set_breakpoint", {
        "address": hex(bp_stack_3),
        "id": "stack_d3",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 3,
    })
    rt.globals()["__bp_callbacks"][bp_stack_3]()
    r = call("get_breakpoint_hits", {"id": "stack_d3"})["result"]
    stack_3 = r.get("hits", [{}])[0].get("stack")
    check("captureStack depth=3 decodes all 3 slots including high-bit 64-bit",
          stack_3 == ["0x177665544332211", "0xFFFF800000001000", "0xDEADBEEF"], stack_3)

    rt.globals()["__force_stack_bulk_fail"] = True
    bp_stack_fb = REGION_A + 0x3720
    call("set_breakpoint", {
        "address": hex(bp_stack_fb),
        "id": "stack_fb",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 2,
    })
    rt.globals()["__bp_callbacks"][bp_stack_fb]()
    r = call("get_breakpoint_hits", {"id": "stack_fb"})["result"]
    stack_fb = r.get("hits", [{}])[0].get("stack")
    check("captureStack falls back to per-slot readQword on bulk readBytes failure",
          rt.globals()["__qword_calls"] == 2 and stack_fb == ["0x177665544332211", "0x00002222"],
          (rt.globals()["__qword_calls"], stack_fb))

    rt.execute('_G.targetIs64Bit = function() return false end; _G.ESP = 0x700000; _G.__force_stack_bulk_fail = false')
    bp_stack_32 = REGION_A + 0x3730
    call("set_breakpoint", {
        "address": hex(bp_stack_32),
        "id": "stack_32",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 2,
    })
    rt.globals()["__bp_callbacks"][bp_stack_32]()
    r = call("get_breakpoint_hits", {"id": "stack_32"})["result"]
    stack_32 = r.get("hits", [{}])[0].get("stack")
    check("captureStack 32-bit bulk read decodes 4-byte LE unsigned",
          stack_32 == ["0x44332211", "0x01776655"] and rt.globals()["__dword_calls"] == 0,
          (stack_32, rt.globals()["__dword_calls"]))
    rt.execute('_G.targetIs64Bit = function() return true end')

    # Offset preservation & partial bulk backfill tests
    rt.execute('''
        _G.__stack_partial_mode = false
        _G.__qword_slot_calls = {}
        _G.__force_stack_bulk_fail = true
        _G.__stack_qword_map = {
            [0x700000] = nil,
            [0x700008] = 0x2222,
            [0x700010] = 0x3333,
        }
        _G.readBytes = function(addr, size, asTable)
            if addr == 0x700000 then
                _G.__stack_read_calls = _G.__stack_read_calls + 1
                if _G.__force_stack_bulk_fail then return nil end
                if _G.__stack_partial_mode then
                    -- Return only 8 bytes (1 slot) even if depth=3
                    local slot = _G.__stack_mem[0x700000]
                    local out = {}
                    for i = 1, 8 do out[i] = slot[i] end
                    return out
                end
                local out = {}
                for i = 0, size - 1 do
                    local slotBase = addr + math.floor(i / 8) * 8
                    local slot = _G.__stack_mem[slotBase]
                    out[i + 1] = slot and slot[(i % 8) + 1] or 0
                end
                return out
            end
            return _G.__orig_readBytes_stack(addr, size, asTable)
        end
        _G.readQword = function(addr)
            _G.__qword_calls = _G.__qword_calls + 1
            table.insert(_G.__qword_slot_calls, addr)
            return _G.__stack_qword_map[addr]
        end
    ''')
    bp_stack_lead_nil = REGION_A + 0x3740
    call("set_breakpoint", {
        "address": hex(bp_stack_lead_nil),
        "id": "stack_lead_nil",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 3,
    })
    rt.globals()["__bp_callbacks"][bp_stack_lead_nil]()
    r_ln = call("get_breakpoint_hits", {"id": "stack_lead_nil"})["result"]
    stack_ln = r_ln.get("hits", [{}])[0].get("stack")
    check("captureStack preserves slot 0 as null when slot 0 read fails and slots 1..2 succeed",
          stack_ln == [None, "0x00002222", "0x00003333"], stack_ln)

    rt.execute('''
        _G.__force_stack_bulk_fail = false
        _G.__stack_partial_mode = true
        _G.__qword_slot_calls = {}
        _G.__stack_qword_map = {
            [0x700000] = 0x1111,
            [0x700008] = nil,
            [0x700010] = 0x3333,
        }
    ''')
    bp_stack_partial = REGION_A + 0x3750
    call("set_breakpoint", {
        "address": hex(bp_stack_partial),
        "id": "stack_partial",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 3,
    })
    rt.globals()["__bp_callbacks"][bp_stack_partial]()
    r_pt = call("get_breakpoint_hits", {"id": "stack_partial"})["result"]
    stack_pt = r_pt.get("hits", [{}])[0].get("stack")
    qword_slots = list(rt.globals()["__qword_slot_calls"].values())
    check("captureStack backfills uncovered slots after partial bulk read without re-reading slot 0",
          stack_pt == ["0x177665544332211", None, "0x00003333"] and qword_slots == [0x700008, 0x700010],
          (stack_pt, qword_slots))

    rt.execute('''
        _G.__stack_partial_mode = false
        _G.__force_stack_bulk_fail = true
        _G.__stack_qword_map = {}
    ''')
    bp_stack_all_nil = REGION_A + 0x3760
    call("set_breakpoint", {
        "address": hex(bp_stack_all_nil),
        "id": "stack_all_nil",
        "capture_registers": False,
        "capture_stack": True,
        "stack_depth": 3,
    })
    rt.globals()["__bp_callbacks"][bp_stack_all_nil]()
    r_an = call("get_breakpoint_hits", {"id": "stack_all_nil"})["result"]
    stack_an = r_an.get("hits", [{}])[0].get("stack")
    check("captureStack returns empty array when all slots fail",
          stack_an == [], stack_an)

    section("[hardening] HEX_BYTE output & strict RFC 3629 UTF-8 sanitization")
    rt.execute('_G.getPreviousOpcode = function(addr) return addr - 1 end')
    r_mem = call("read_memory", {"address": hex(REGION_A + NEEDLE_A_OFF), "size": 7})["result"]
    check("read_memory HEX_BYTE output", r_mem.get("data") == "48 8B 05 DE AD BE EF", r_mem)
    r_info = call("get_instruction_info", {"address": hex(REGION_A + NEEDLE_A_OFF)})["result"]
    check("get_instruction_info HEX_BYTE output", r_info.get("bytes") == "48", r_info)
    r_dis = call("disassemble", {"address": hex(REGION_A + NEEDLE_A_OFF), "count": 2})["result"]
    check("disassemble HEX_BYTE output",
          [ins.get("bytes") for ins in r_dis.get("instructions", [])] == ["48", "8B"], r_dis)

    rt.execute('''
        _G.__str_cases = {
            ascii = "Hello, World! ~123",
            tabs_ctrl = "A\\tB\\nC\\rD" .. string.char(0x00, 0x1F, 0x7F) .. "Z",
            valid_utf8 = string.char(0xE0, 0xA0, 0x80) .. string.char(0xED, 0x9F, 0xBF) ..
                         string.char(0xF0, 0x90, 0x80, 0x80) .. string.char(0xF4, 0x8F, 0xBF, 0xBF),
            overlong_3 = string.char(0xE0, 0x9F, 0xBF) .. "X",
            overlong_4 = string.char(0xF0, 0x8F, 0xBF, 0xBF) .. "X",
            surrogate = string.char(0xED, 0xA0, 0x80, 0xED, 0xBF, 0xBF),
            above_max = string.char(0xF4, 0x90, 0x80, 0x80),
        }
        _G.readString = function(addr) return _G.__str_cases[_G.__str_key] end
    ''')
    rt.globals()["__str_key"] = "ascii"
    r_ascii = call("read_string", {"address": "0x401000"})["result"]
    check("sanitizeForJson printable ASCII fast path",
          r_ascii.get("value") == "Hello, World! ~123" and r_ascii.get("contains_escaped_bytes") is False, r_ascii)
    rt.globals()["__str_key"] = "tabs_ctrl"
    r_ctrl = call("read_string", {"address": "0x401000"})["result"]
    check("sanitizeForJson clean runs + tab/nl/cr spaces + control escapes",
          r_ctrl.get("value") == "A B C D\\x00\\x1F\\x7FZ" and r_ctrl.get("contains_escaped_bytes") is True, r_ctrl)
    rt.globals()["__str_key"] = "valid_utf8"
    r_vutf = call("read_string", {"address": "0x401000"})["result"]
    check("sanitizeForJson allows valid RFC 3629 UTF-8 boundary codepoints",
          r_vutf.get("contains_escaped_bytes") is False and r_vutf.get("length") == 14, r_vutf)
    for k, expected in (
        ("overlong_3", "\\xE0\\x9F\\xBFX"),
        ("overlong_4", "\\xF0\\x8F\\xBF\\xBFX"),
        ("surrogate", "\\xED\\xA0\\x80\\xED\\xBF\\xBF"),
        ("above_max", "\\xF4\\x90\\x80\\x80"),
    ):
        rt.globals()["__str_key"] = k
        rk = call("read_string", {"address": "0x401000"})["result"]
        check("sanitizeForJson rejects " + k,
              rk.get("value") == expected and rk.get("contains_escaped_bytes") is True, rk)

    section("[hardening] JSON trailing garbage via dispatcher")
    env_trail = json.loads(execute('{"jsonrpc":"2.0","method":"ping","id":1} trailing'))
    check("dispatcher rejects JSON with trailing garbage -> -32700",
          env_trail.get("error", {}).get("code") == -32700, env_trail)

    section("[hardening] tickDiffMs wraparound across 0xFFFFFFFF -> 0")
    execute_w, rt_w = build_runtime()
    rt_w.execute('''
        _G.__ticks = {0xFFFFFF00, 0x00000100, 0x00000100}
        _G.__t_idx = 0
        _G.getTickCount = function()
            _G.__t_idx = math.min(_G.__t_idx + 1, #_G.__ticks)
            return _G.__ticks[_G.__t_idx]
        end
    ''')
    rt_w.globals()["__CE_MCP_BRIDGE_STATE"]["connected"] = True
    r_st_wrap = json.loads(execute_w(json.dumps({"jsonrpc": "2.0", "method": "status", "params": {}, "id": 1})))["result"]
    check("status tickDiffMs handles 0xFFFFFF00 -> 0x100 wraparound (512ms)",
          r_st_wrap.get("client_idle_ms") == 512, r_st_wrap.get("client_idle_ms"))

    # AOB scan across wraparound: must NOT immediately truncate when tick wraps
    execute_w2, rt_w2 = build_runtime()
    rt_w2.execute('''
        _G.__ticks = {0xFFFFFF80, 0xFFFFFF80, 0xFFFFFF90, 0x00000010, 0x00000020}
        _G.__t_idx = 0
        _G.getTickCount = function()
            _G.__t_idx = _G.__t_idx + 1
            return _G.__ticks[math.min(_G.__t_idx, #_G.__ticks)]
        end
    ''')
    needle = " ".join("%02X" % b for b in NEEDLE)
    r_wrap_scan = json.loads(execute_w2(json.dumps({
        "jsonrpc": "2.0", "method": "aob_scan",
        "params": {"pattern": needle, "protection": "+X", "time_budget_ms": 500},
        "id": 1,
    })))["result"]
    check("aob_scan completes cleanly across 32-bit tick wraparound",
          r_wrap_scan.get("success") is True and r_wrap_scan.get("count") == 1, r_wrap_scan)

    section("[hardening] scanAobRange anchor-relative offsets, search_string, processMessages pcall")
    execute_aob, rt_aob = build_runtime()
    rt_aob.execute('''
        local baseA = 0x400000
        local sample = {0x00, 0x00, 0x48, 0x8B} -- matches "00 00 48 8B" (anchor 0x48 at off 2, relOffs -2,-1,+1)
        local txt = "Hi"
        local wide_txt = {string.byte("W"), 0, string.byte("Z"), 0}
        local orig_rb = _G.readBytes
        _G.readBytes = function(addr, size, asTable)
            local out = orig_rb(addr, size, asTable)
            for i = 0, size - 1 do
                local a = addr + i
                if a >= baseA + 0x500 and a < baseA + 0x504 then
                    out[i + 1] = sample[(a - (baseA + 0x500)) + 1]
                elseif a >= baseA + 0x600 and a < baseA + 0x602 then
                    out[i + 1] = txt:byte((a - (baseA + 0x600)) + 1)
                elseif a >= baseA + 0x700 and a < baseA + 0x704 then
                    out[i + 1] = wide_txt[(a - (baseA + 0x700)) + 1]
                end
            end
            return out
        end
        _G.processMessages = function() error("ui pump warning") end
    ''')
    r_rel = json.loads(execute_aob(json.dumps({
        "jsonrpc": "2.0", "method": "aob_scan",
        "params": {"pattern": "00 00 48 8B", "start_address": "0x400400", "size": 0x200},
        "id": 1,
    })))["result"]
    check("aob_scan anchor-relative negative/positive relOffs matches & survives processMessages error",
          r_rel.get("success") is True and r_rel.get("count") == 1 and
          r_rel.get("addresses", [{}])[0].get("address", "").upper().endswith("400500"), r_rel)
    r_1b = json.loads(execute_aob(json.dumps({
        "jsonrpc": "2.0", "method": "aob_scan",
        "params": {"pattern": "?? 48 ??", "start_address": "0x4004FF", "size": 0x20},
        "id": 2,
    })))["result"]
    check("aob_scan fixedCount==0 single non-wildcard offset matches",
          r_1b.get("success") is True and r_1b.get("count") == 1 and
          r_1b.get("addresses", [{}])[0].get("address", "").upper().endswith("400501"), r_1b)
    r_2b = json.loads(execute_aob(json.dumps({
        "jsonrpc": "2.0", "method": "aob_scan",
        "params": {"pattern": "?? 00 48 8B ??", "start_address": "0x4004FF", "size": 0x20},
        "id": 3,
    })))["result"]
    check("aob_scan multi-fixed with leading wildcard matches",
          r_2b.get("success") is True and r_2b.get("count") == 1 and
          r_2b.get("addresses", [{}])[0].get("address", "").upper().endswith("400500"), r_2b)
    r_ss = json.loads(execute_aob(json.dumps({
        "jsonrpc": "2.0", "method": "search_string",
        "params": {"string": "WZ", "wide": True, "protection": "+X", "limit": 0, "time_budget_ms": 1},
        "id": 4,
    })))["result"]
    check("search_string wide HEX_BYTE + clamped limit/budget finds match",
          r_ss.get("success") is True and r_ss.get("count") == 1 and
          r_ss.get("addresses", [{}])[0].get("address", "").upper().endswith("400700"), r_ss)

    section("[hardening] invalid start_address rejected & no double lookup")
    rt.execute('''
        _G.__addr_lookups = {}
        _G.__orig_getAddressSafe = _G.getAddressSafe
        _G.getAddressSafe = function(v)
            _G.__addr_lookups[tostring(v)] = (_G.__addr_lookups[tostring(v)] or 0) + 1
            if v == "valid_sym" then return 0x400000 end
            return _G.__orig_getAddressSafe(v)
        end
    ''')
    for method, extra in (
        ("aob_scan", {"pattern": needle, "start_address": "bad_symbol"}),
        ("find_call_references", {"address": "0x400100", "start_address": "bad_symbol"}),
        ("find_references", {"address": "0x400100", "start_address": "bad_symbol"}),
        ("search_string", {"string": "test", "start_address": "bad_symbol"}),
        ("scan_all", {"value": 1, "start_address": "bad_symbol"}),
    ):
        r_bad_sa = call(method, extra)["result"]
        check(method + " rejects unresolvable start_address",
              r_bad_sa.get("success") is False and "Invalid start_address" in r_bad_sa.get("error", ""),
              r_bad_sa)

    rt.execute('_G.__addr_lookups = {}')
    r_sym = call("aob_scan", {"pattern": needle, "start_address": "valid_sym", "size": 0x2000})["result"]
    check("aob_scan resolves string start_address once (no double lookup)",
          r_sym.get("success") is True and rt.globals()["__addr_lookups"]["valid_sym"] == 1,
          (r_sym, rt.globals()["__addr_lookups"]["valid_sym"]))

    section("[hardening] find_references 64-bit high-bit, clamping & pcall(disassemble)")
    execute_ref, rt_ref = build_runtime()
    rt_ref.execute('''
        local target_bytes = {0x00, 0x10, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF} -- 0xFFFF800000001000
        local orig_rb = _G.readBytes
        _G.readBytes = function(addr, size, asTable)
            local out = orig_rb(addr, size, asTable)
            for i = 0, size - 1 do
                local a = addr + i
                if a >= 0x401200 and a < 0x401208 then
                    out[i + 1] = target_bytes[(a - 0x401200) + 1]
                end
            end
            return out
        end
        _G.disassemble = function(addr)
            if addr == 0x401200 then error("non-code page") end
            return "nop"
        end
    ''')
    r_ref64 = json.loads(execute_ref(json.dumps({
        "jsonrpc": "2.0", "method": "find_references",
        "params": {"address": "0xFFFF800000001000", "protection": "+X", "limit": 0, "time_budget_ms": 1},
        "id": 1,
    })))["result"]
    check("find_references finds high-bit 64-bit address and wraps disassemble in pcall",
          r_ref64.get("success") is True and r_ref64.get("count") == 1 and
          r_ref64.get("references", [{}])[0].get("address", "").upper().endswith("401200") and
          r_ref64.get("references", [{}])[0].get("instruction") == "???",
          r_ref64)

    section("[hardening] find_call_references scanned_bytes on limit hit & pcall(disassemble)")
    execute_call, rt_call = build_runtime()
    rt_call.execute('''
        local baseA = 0x400000
        local target = 0x400100
        _G.readBytes = function(addr, size, asTable)
            local out = {}
            for i = 0, size - 1 do
                local a = addr + i
                local b = 0
                if a == baseA + 0x10 or a == baseA + 0x30 then b = 0xE8
                elseif (a >= baseA + 0x11 and a <= baseA + 0x14) or (a >= baseA + 0x31 and a <= baseA + 0x34) then
                    local callSite = (a < baseA + 0x20) and (baseA + 0x10) or (baseA + 0x30)
                    local rel = target - (callSite + 5)
                    if rel < 0 then rel = rel + 0x100000000 end
                    local shift = (a - (callSite + 1)) * 8
                    b = math.floor(rel / (2 ^ shift)) % 256
                end
                out[i + 1] = b
            end
            return out
        end
        _G.disassemble = function() error("disasm failed") end
    ''')
    r_call = json.loads(execute_call(json.dumps({
        "jsonrpc": "2.0", "method": "find_call_references",
        "params": {"address": "0x400100", "limit": 1, "start_address": "0x400000", "size": 0x1000},
        "id": 1,
    })))["result"]
    check("find_call_references reports non-zero scanned_bytes on limit hit and survives disassemble error",
          r_call.get("success") is True and r_call.get("count") == 1 and
          r_call.get("scanned_bytes", 0) > 0 and r_call.get("truncated") is True and
          r_call.get("callers", [{}])[0].get("instruction") == "???",
          r_call)

    section("[hardening] analyze_function pcall(disassemble), max_search clamp & read_pointer(_chain) offsets")
    rt.execute('''
        local base = 0x420000
        local fn_bytes = {0x55, 0x48, 0x89, 0xE5, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xC3}
        local orig_rb = _G.readBytes
        _G.__max_read_size = 0
        _G.readBytes = function(addr, size, asTable)
            if size > _G.__max_read_size then _G.__max_read_size = size end
            local out = orig_rb(addr, size, asTable)
            for i = 0, size - 1 do
                local a = addr + i
                if a >= base and a < base + #fn_bytes then
                    out[i + 1] = fn_bytes[(a - base) + 1]
                end
            end
            return out
        end
        _G.getInstructionSize = function(addr)
            if addr == base then return 1 end
            if addr == base + 1 then return 3 end
            if addr == base + 4 then return 6 end
            return 1
        end
        _G.disassemble = function() error("bad insn") end
    ''')
    r_af = call("analyze_function", {"address": "0x420004"})["result"]
    check("analyze_function wraps disassemble in pcall for FF /2 indirect calls",
          r_af.get("success") is True and r_af.get("call_count") == 1 and
          r_af.get("calls", [{}])[0].get("instruction") == "???", r_af)
    rt.globals()["__max_read_size"] = 0
    r_fb_clamp = call("find_function_boundaries", {"address": "0x420004", "max_search": 999999999})["result"]
    check("find_function_boundaries clamps max_search to 1048576",
          r_fb_clamp.get("success") is True and r_fb_clamp.get("found") is True and
          rt.globals()["__max_read_size"] <= 1048576, (r_fb_clamp, rt.globals()["__max_read_size"]))

    rt.execute('''
        _G.readPointer = function(addr)
            if addr == 0x401000 then return 0x402000 end
            if addr == 0x402010 then return 0x403000 end
            return 99
        end
    ''')
    r_rp_hex = call("read_pointer", {"base": "0x401000", "offsets": ["0x10", "-0x10"]})["result"]
    check("read_pointer accepts hex string offsets",
          r_rp_hex.get("success") is True and r_rp_hex.get("final_address") == "0x00402FF0", r_rp_hex)
    r_rp_bad = call("read_pointer", {"base": "0x401000", "offsets": ["not_an_int"]})["result"]
    check("read_pointer rejects invalid offset",
          r_rp_bad.get("success") is False and "Invalid offset" in r_rp_bad.get("error", ""), r_rp_bad)
    r_rpc_hex = call("read_pointer_chain", {"base": "0x401000", "offsets": ["0x10", "-0x10"]})["result"]
    check("read_pointer_chain accepts hex string offsets",
          r_rpc_hex.get("success") is True and r_rpc_hex.get("final_address") == "0x00402FF0", r_rpc_hex)
    r_rpc_bad = call("read_pointer_chain", {"base": "0x401000", "offsets": [1.5]})["result"]
    check("read_pointer_chain rejects non-integer offset",
          r_rpc_bad.get("success") is False and "Invalid offset" in r_rpc_bad.get("error", ""), r_rpc_bad)

    section("[hardening] enum_memory_regions_full refresh, total_regions, truncated & RW+GUARD")
    execute_reg, rt_reg = build_runtime()
    rt_reg.execute('''
        _G.__enum_calls = 0
        _G.__tick_reg = 1000
        _G.getTickCount = function() return _G.__tick_reg end
        _G.enumMemoryRegions = function()
            _G.__enum_calls = _G.__enum_calls + 1
            return {
                {BaseAddress = 0x400000, AllocationBase = 0x400000, RegionSize = 0x1000, State = 0x1000, Protect = 0x104, Type = 0x20000},
                {BaseAddress = 0x500000, AllocationBase = 0x500000, RegionSize = 0x1000, State = 0x1000, Protect = 0x220, Type = 0x20000},
                {BaseAddress = 0x600000, AllocationBase = 0x600000, RegionSize = 0x1000, State = 0x2000, Protect = 0x01,  Type = 0x20000},
            }
        end
    ''')
    r_reg1 = json.loads(execute_reg(json.dumps({
        "jsonrpc": "2.0", "method": "enum_memory_regions_full", "params": {"max": 2}, "id": 1
    })))["result"]
    check("enum_memory_regions_full decodes RW+GUARD and RX+NOCACHE",
          r_reg1.get("success") is True and
          r_reg1.get("regions", [{}])[0].get("protect_string") == "RW+GUARD" and
          r_reg1.get("regions", [{}, {}])[1].get("protect_string") == "RX+NOCACHE", r_reg1)
    check("enum_memory_regions_full reports total_regions and truncated",
          r_reg1.get("count") == 2 and r_reg1.get("total_regions") == 3 and r_reg1.get("truncated") is True, r_reg1)
    json.loads(execute_reg(json.dumps({
        "jsonrpc": "2.0", "method": "enum_memory_regions_full", "params": {"max": 5}, "id": 2
    })))
    check("enum_memory_regions_full uses cache when refresh is false",
          rt_reg.globals()["__enum_calls"] == 1, rt_reg.globals()["__enum_calls"])
    r_reg_ref = json.loads(execute_reg(json.dumps({
        "jsonrpc": "2.0", "method": "enum_memory_regions_full", "params": {"max": 5, "refresh": True}, "id": 3
    })))["result"]
    check("enum_memory_regions_full honors refresh=True and decodes NOACCESS",
          rt_reg.globals()["__enum_calls"] == 2 and
          r_reg_ref.get("regions", [{}, {}, {}])[2].get("protect_string") == "NOACCESS",
          (rt_reg.globals()["__enum_calls"], r_reg_ref))

    section("[hardening] scan_all, next_scan, write_*, thread_list, dissect_structure")
    rt.execute('''
        _G.vtByte = 0; _G.vtWord = 1; _G.vtDword = 2; _G.vtQword = 3
        _G.vtSingle = 4; _G.vtDouble = 5; _G.vtString = 6
        _G.rtRounded = 0; _G.fsmNotAligned = 0
        _G.soExactValue = 0; _G.soIncreasedValue = 1; _G.soDecreasedValue = 2
        _G.soChanged = 3; _G.soUnchanged = 4; _G.soBiggerThan = 5; _G.soSmallerThan = 6
        _G.__ms_destroyed = 0
        _G.__fl_destroyed = 0
        _G.__next_scan_calls = {}
        _G.__force_fl_init_err = false
        _G.createMemScan = function()
            return {
                firstScan = function() end,
                nextScan = function(opt, rt_, val)
                    table.insert(_G.__next_scan_calls, {opt = opt, val = val})
                end,
                waitTillDone = function() end,
                destroy = function() _G.__ms_destroyed = _G.__ms_destroyed + 1 end,
            }
        end
        _G.createFoundList = function()
            return {
                initialize = function()
                    if _G.__force_fl_init_err then error("fl init failed") end
                end,
                getCount = function() return 3 end,
                destroy = function() _G.__fl_destroyed = _G.__fl_destroyed + 1 end,
            }
        end
    ''')
    check("scan_all rejects unknown type",
          call("scan_all", {"value": 100, "type": "bogus_type"})["result"].get("success") is False)
    rt.globals()["__force_fl_init_err"] = True
    r_sa_err = call("scan_all", {"value": 100, "type": "dword"})["result"]
    check("scan_all destroys ms and fl on error",
          r_sa_err.get("success") is False and
          rt.globals()["__ms_destroyed"] == 1 and rt.globals()["__fl_destroyed"] == 1,
          (r_sa_err, rt.globals()["__ms_destroyed"], rt.globals()["__fl_destroyed"]))
    rt.globals()["__force_fl_init_err"] = False
    r_sa_ok = call("scan_all", {"value": 100, "type": "dword"})["result"]
    check("scan_all succeeds cleanly", r_sa_ok.get("success") is True and r_sa_ok.get("count") == 3, r_sa_ok)

    check("next_scan rejects unknown scan_type",
          call("next_scan", {"value": 1, "scan_type": "invalid"})["result"].get("success") is False)
    for st in ("exact", "bigger", "smaller"):
        check("next_scan " + st + " rejects nil value",
              call("next_scan", {"scan_type": st})["result"].get("success") is False)
    call("next_scan", {"value": 42, "scan_type": "bigger"})
    call("next_scan", {"value": 99, "scan_type": "smaller"})
    nsc = rt.globals()["__next_scan_calls"]
    check("next_scan bigger and smaller pass tostring(value)",
          nsc[1]["opt"] == 5 and nsc[1]["val"] == "42" and nsc[2]["opt"] == 6 and nsc[2]["val"] == "99",
          (nsc[1]["opt"], nsc[1]["val"], nsc[2]["opt"], nsc[2]["val"]))

    fl_dest_before = rt.globals()["__fl_destroyed"]
    rt.globals()["__force_fl_init_err"] = True
    r_ns_err = call("next_scan", {"value": 10, "scan_type": "exact"})["result"]
    check("next_scan destroys newly created fl on error",
          r_ns_err.get("success") is False and rt.globals()["__fl_destroyed"] == fl_dest_before + 2,
          (r_ns_err, rt.globals()["__fl_destroyed"], fl_dest_before))
    rt.globals()["__force_fl_init_err"] = False

    rt.execute('''
        _G.writeInteger = function() return false end
        _G.writeBytes = function() return false end
        _G.writeString = function() return false end
    ''')
    check("write_integer returns success=False when CE write returns false",
          call("write_integer", {"address": "0x401000", "value": 5})["result"].get("success") is False)
    check("write_memory returns success=False when CE write returns false",
          call("write_memory", {"address": "0x401000", "bytes": [0x90]})["result"].get("success") is False)
    check("write_string returns success=False when CE write returns false",
          call("write_string", {"address": "0x401000", "value": "hi"})["result"].get("success") is False)
    for bad_bytes in ([], "not_a_list", [-1], [256], [1.5], ["90"], [0] * 65537):
        check("write_memory rejects invalid bytes " + repr(bad_bytes)[:24],
              call("write_memory", {"address": "0x401000", "bytes": bad_bytes})["result"].get("success") is False)

    rt.execute('''
        _G.__list_destroyed = 0
        _G.createStringlist = function()
            return { destroy = function() _G.__list_destroyed = _G.__list_destroyed + 1 end }
        end
        _G.getThreadlist = function() error("threadlist error") end
        _G.__struct_destroyed = 0
        _G.createStructure = function()
            return {
                autoGuess = function() end,
                Count = 1,
                Element = setmetatable({}, { __index = function() error("elem error") end }),
                destroy = function() _G.__struct_destroyed = _G.__struct_destroyed + 1 end,
            }
        end
    ''')
    r_tl = call("get_thread_list")["result"]
    check("get_thread_list destroys list on error",
          r_tl.get("success") is False and rt.globals()["__list_destroyed"] == 1,
          (r_tl, rt.globals()["__list_destroyed"]))
    r_ds = call("dissect_structure", {"address": "0x401000"})["result"]
    check("dissect_structure destroys struct on error",
          r_ds.get("success") is False and rt.globals()["__struct_destroyed"] == 1,
          (r_ds, rt.globals()["__struct_destroyed"]))

    section("[hardening] DBVM watch compaction, buffered merge, disasm cache, R8..R15")
    execute_db, rt_db = build_runtime()
    rt_db.execute('''
        _G.dbk_initialized = function() return true end
        _G.dbvm_initialized = function() return true end
        _G.dbk_getPhysicalAddress = function() return 0x123000 end
        _G.__start_max_entries = nil
        _G.dbvm_watch_writes = function(phys, sz, opts, maxE)
            _G.__start_max_entries = maxE
            return 9
        end
        _G.__disasm_calls = 0
        _G.disassemble = function(addr)
            _G.__disasm_calls = _G.__disasm_calls + 1
            if addr == 0x401020 then error("disasm fail") end
            return "mov [rax],edx"
        end
        _G.__dbvm_batches = {
            {{RIP = 0x401000, RAX = 1, R8 = 0x88, R15 = 0x15}},
            {{RIP = 0x401000, RAX = 2, R8 = 0x89, R15 = 0x16}, {RIP = 0x401020, RAX = 3, R9 = 0x99}},
        }
        _G.__dbvm_idx = 0
        _G.dbvm_watch_retrievelog = function()
            _G.__dbvm_idx = _G.__dbvm_idx + 1
            return _G.__dbvm_batches[_G.__dbvm_idx] or {}
        end
        _G.dbvm_watch_disable = function() return true end
    ''')
    json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "start_dbvm_watch",
        "params": {"address": "0x402000", "mode": "w", "max_entries": 9999999}, "id": 1
    })))
    check("start_dbvm_watch clamps max_entries to 100000",
          rt_db.globals()["__start_max_entries"] == 100000, rt_db.globals()["__start_max_entries"])
    json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "poll_dbvm_watch",
        "params": {"address": "0x402000", "clear": False}, "id": 2
    })))
    r_stop = json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "stop_dbvm_watch",
        "params": {"address": "0x402000"}, "id": 3
    })))["result"]
    check("stop_dbvm_watch merges buffered_logs with final drain",
          r_stop.get("success") is True and r_stop.get("hit_count") == 3, r_stop)
    check("stop_dbvm_watch caches disassemble per unique RIP (1 call per unique RIP)",
          rt_db.globals()["__disasm_calls"] == 2 and
          r_stop["hits"][0]["instruction"] == "mov [rax],edx" and
          r_stop["hits"][1]["instruction"] == "mov [rax],edx" and
          r_stop["hits"][2]["instruction"] == "???",
          (rt_db.globals()["__disasm_calls"], r_stop))
    check("stop_dbvm_watch includes R8..R15 in registers",
          r_stop["hits"][0]["registers"].get("R8") == "0x00000088" and
          r_stop["hits"][0]["registers"].get("R15") == "0x00000015" and
          r_stop["hits"][2]["registers"].get("R9") == "0x00000099", r_stop["hits"])

    # Poll compaction O(N) test (> 10,000 entries)
    rt_db.execute('''
        _G.__big_batch = {}
        for i = 1, 6000 do _G.__big_batch[i] = {RIP = 0x401000, RAX = i} end
        _G.__big_batch2 = {}
        for i = 1, 6000 do _G.__big_batch2[i] = {RIP = 0x401000, RAX = 6000 + i} end
        _G.__dbvm_batches = {_G.__big_batch, _G.__big_batch2}
        _G.__dbvm_idx = 0
    ''')
    json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "start_dbvm_watch",
        "params": {"address": "0x402100", "mode": "w"}, "id": 4
    })))
    json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "poll_dbvm_watch",
        "params": {"address": "0x402100", "clear": False, "max_results": 1}, "id": 5
    })))
    r_comp = json.loads(execute_db(json.dumps({
        "jsonrpc": "2.0", "method": "poll_dbvm_watch",
        "params": {"address": "0x402100", "clear": False, "max_results": 1}, "id": 6
    })))["result"]
    check("poll_dbvm_watch compacts buffer cleanly at 10,000 cap retaining newest entries",
          r_comp.get("buffered_total") == 10000 and r_comp.get("hits", [{}])[0].get("RAX") == "0x000007D1",
          (r_comp.get("buffered_total"), r_comp.get("hits")))

    section("[hardening] PipeWorker writeBytes/writeString verification")
    execute_pw, rt_pw = build_runtime()
    rt_pw.execute('''
        _G.__pw_logs = {}
        _G.log = nil
        local orig_print = _G.print
        _G.print = function(s) table.insert(_G.__pw_logs, tostring(s)) end
        _G.__pw_worker_fn = nil
        _G.createThread = function(fn)
            _G.__pw_worker_fn = fn
            return { Terminated = false, terminate = function() end, destroy = function() end }
        end
        _G.__pw_write_mode = "short_header"
        _G.__pw_write_string_calls = 0
        _G.__pw_disconnects = 0
        _G.createPipe = function()
            local req = '{"jsonrpc":"2.0","method":"ping","id":1}'
            local n = #req
            local sent = false
            local p
            p = {
                Connected = true,
                acceptConnection = function() end,
                readBytes = function()
                    if sent then p.Connected = false; return nil end
                    sent = true
                    return {n % 256, math.floor(n/256) % 256, math.floor(n/65536) % 256, 0}
                end,
                readString = function() return req end,
                writeBytes = function()
                    if _G.__pw_write_mode == "short_header" then return 2 end
                    if _G.__pw_write_mode == "header_nil" then return nil end
                    return 4
                end,
                writeString = function(s)
                    _G.__pw_write_string_calls = _G.__pw_write_string_calls + 1
                    if _G.__pw_write_mode == "body_false" then return false end
                    if _G.__pw_write_mode == "body_nil" then return nil end
                    if _G.__pw_write_mode == "ok" then return #s end
                    return 0
                end,
                disconnect = function() _G.__pw_disconnects = _G.__pw_disconnects + 1 end,
                destroy = function() end,
            }
            return p
        end
    ''')
    st_pw = rt_pw.globals()["__CE_MCP_BRIDGE_STATE"]
    st_pw["workerThread"] = None
    st_pw["workerDone"] = True
    rt_pw.globals()["StartMCPBridge"](True)
    fake_thread = rt_pw.eval('''(function()
        local calls = 0
        local t = {
            Terminated = false,
            synchronize = function(cb) cb() end,
        }
        return t
    end)()''')
    # Run one iteration by terminating inside sleep()
    rt_pw.execute('''
        _G.sleep = function() _G.__pw_thread_obj.Terminated = true end
        _G.__pw_thread_obj = ...
    ''', fake_thread)
    rt_pw.globals()["__pw_worker_fn"](fake_thread)
    logs_1 = list(rt_pw.globals()["__pw_logs"].values())
    check("PipeWorker detects short writeBytes header (< 4)",
          any("writeBytes failed" in s for s in logs_1) and st_pw["workerWriting"] is False, logs_1)

    rt_pw.execute('_G.__pw_logs = {}; _G.__pw_write_string_calls = 0; _G.__pw_write_mode = "header_nil"')
    fake_thread_hn = rt_pw.eval('{ Terminated = false, synchronize = function(cb) cb() end }')
    rt_pw.execute('_G.__pw_thread_obj = ...', fake_thread_hn)
    rt_pw.globals()["__pw_worker_fn"](fake_thread_hn)
    logs_hn = list(rt_pw.globals()["__pw_logs"].values())
    check("PipeWorker detects nil writeBytes header and skips writeString",
          any("writeBytes failed (nil)" in s for s in logs_hn) and
          st_pw["workerWriting"] is False and
          rt_pw.globals()["__pw_write_string_calls"] == 0,
          (logs_hn, rt_pw.globals()["__pw_write_string_calls"]))

    rt_pw.execute('_G.__pw_logs = {}; _G.__pw_write_string_calls = 0; _G.__pw_write_mode = "body_false"')
    fake_thread2 = rt_pw.eval('{ Terminated = false, synchronize = function(cb) cb() end }')
    rt_pw.execute('_G.__pw_thread_obj = ...', fake_thread2)
    rt_pw.globals()["__pw_worker_fn"](fake_thread2)
    logs_2 = list(rt_pw.globals()["__pw_logs"].values())
    check("PipeWorker detects writeString returning false",
          any("writeString failed" in s for s in logs_2) and st_pw["workerWriting"] is False, logs_2)

    rt_pw.execute('_G.__pw_logs = {}; _G.__pw_write_string_calls = 0; _G.__pw_write_mode = "body_nil"')
    fake_thread_bn = rt_pw.eval('{ Terminated = false, synchronize = function(cb) cb() end }')
    rt_pw.execute('_G.__pw_thread_obj = ...', fake_thread_bn)
    rt_pw.globals()["__pw_worker_fn"](fake_thread_bn)
    logs_bn = list(rt_pw.globals()["__pw_logs"].values())
    check("PipeWorker detects writeString returning nil",
          any("writeString failed (nil)" in s for s in logs_bn) and st_pw["workerWriting"] is False, logs_bn)

    rt_pw.execute('_G.__pw_logs = {}; _G.__pw_write_string_calls = 0; _G.__pw_write_mode = "ok"')
    fake_thread_ok = rt_pw.eval('{ Terminated = false, synchronize = function(cb) cb() end }')
    rt_pw.execute('_G.__pw_thread_obj = ...', fake_thread_ok)
    rt_pw.globals()["__pw_worker_fn"](fake_thread_ok)
    logs_ok = list(rt_pw.globals()["__pw_logs"].values())
    check("PipeWorker succeeds when writeBytes=4 and writeString=#response",
          not any("writeBytes failed" in s or "writeString failed" in s for s in logs_ok) and
          st_pw["workerWriting"] is False and
          rt_pw.globals()["__pw_write_string_calls"] == 1,
          (logs_ok, rt_pw.globals()["__pw_write_string_calls"]))

    section("[hardening] Codex review fixes: writeBytes count, auth token, call cursor, null offsets")
    execute_cx, rt_cx = build_runtime()
    cx_id = [0]

    def call_cx(method, params=None, auth_token=None):
        cx_id[0] += 1
        req = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": cx_id[0]}
        if auth_token is not None:
            req["auth_token"] = auth_token
        return json.loads(execute_cx(json.dumps(req)))

    # 1. writeBytes native byte-count checks (0, partial, nil, false, exact)
    rt_cx.execute('_G.__wb_ret = 0; _G.writeBytes = function() return _G.__wb_ret end')
    r_wb0 = call_cx("write_memory", {"address": "0x401000", "bytes": [0x90, 0x90, 0xC3]})["result"]
    check("write_memory fails when writeBytes returns 0",
          r_wb0.get("success") is False and r_wb0.get("bytes_written") == 0 and r_wb0.get("bytes_requested") == 3, r_wb0)

    rt_cx.globals()["__wb_ret"] = 2
    r_wbp = call_cx("write_memory", {"address": "0x401000", "bytes": [0x90, 0x90, 0xC3]})["result"]
    check("write_memory fails on partial writeBytes count (2 of 3)",
          r_wbp.get("success") is False and r_wbp.get("bytes_written") == 2 and r_wbp.get("bytes_requested") == 3, r_wbp)

    rt_cx.globals()["__wb_ret"] = None
    r_wbn = call_cx("write_memory", {"address": "0x401000", "bytes": [0x90]})["result"]
    check("write_memory fails when writeBytes returns nil", r_wbn.get("success") is False, r_wbn)

    rt_cx.globals()["__wb_ret"] = 3
    r_wbok = call_cx("write_memory", {"address": "0x401000", "bytes": [0x90, 0x90, 0xC3]})["result"]
    check("write_memory succeeds when writeBytes returns exact count",
          r_wbok.get("success") is True and r_wbok.get("bytes_written") == 3, r_wbok)

    # 2. find_call_references limit cursor resumes at first unexamined byte and finds 2nd caller
    rt_cx.execute('''
        local baseA = 0x400000
        local target = 0x400100
        local call1 = baseA + 0x20
        local call2 = baseA + 0x30
        local function encodeCall(mem, callSite)
            mem[callSite] = 0xE8
            local rel = target - (callSite + 5)
            if rel < 0 then rel = rel + 0x100000000 end
            for b = 0, 3 do
                mem[callSite + 1 + b] = math.floor(rel / (2 ^ (b * 8))) % 256
            end
        end
        local mem = {}
        encodeCall(mem, call1)
        encodeCall(mem, call2)
        _G.readBytes = function(addr, size, asTable)
            local out = {}
            for i = 0, size - 1 do out[i + 1] = mem[addr + i] or 0 end
            return out
        end
    ''')
    r_c1 = call_cx("find_call_references", {
        "address": "0x400100", "start_address": "0x400000", "size": 0x100, "limit": 1,
    })["result"]
    r_c2 = call_cx("find_call_references", {
        "address": "0x400100", "start_address": r_c1.get("next_start_address"), "size": 0x100, "limit": 1,
    })["result"]
    check("find_call_references limit=1 cursor resumes and finds second caller in same window",
          r_c1.get("count") == 1 and r_c1["callers"][0]["caller_address"] == "0x00400020" and
          r_c1.get("next_start_address") == "0x00400021" and
          r_c2.get("count") == 1 and r_c2["callers"][0]["caller_address"] == "0x00400030",
          (r_c1, r_c2))

    # 3. Pointer offset arrays with JSON null holes are rejected instead of truncated
    rt_cx.execute('_G.readPointer = function(addr) return addr + 0x100 end')
    for method in ("read_pointer", "read_pointer_chain"):
        for raw_offsets in ("[16, null, 32]", "[16, null]", "[null]"):
            payload_str = (
                '{"jsonrpc":"2.0","method":"' + method + '","params":{"base":"0x401000","address":"0x401000","offsets":'
                + raw_offsets + '},"id":99}'
            )
            res = json.loads(execute_cx(payload_str))["result"]
            check(f"{method} rejects null hole offsets {raw_offsets}",
                  res.get("success") is False and "null" in res.get("error", "").lower(), res)

    # 4. Optional CE_MCP_AUTH_TOKEN authentication
    rt_cx.globals()["CE_MCP_AUTH_TOKEN"] = "s3cr3t-token"
    env_no_tok = call_cx("ping")
    env_bad_tok = call_cx("ping", auth_token="wrong-token")
    env_ok_tok = call_cx("ping", auth_token="s3cr3t-token")
    env_status = call_cx("status", auth_token="s3cr3t-token")
    check("CE_MCP_AUTH_TOKEN rejects missing token with -32001",
          env_no_tok.get("error", {}).get("code") == -32001, env_no_tok)
    check("CE_MCP_AUTH_TOKEN rejects wrong token with -32001",
          env_bad_tok.get("error", {}).get("code") == -32001, env_bad_tok)
    check("CE_MCP_AUTH_TOKEN accepts matching token",
          env_ok_tok.get("result", {}).get("success") is True, env_ok_tok)
    check("status reports auth_required=True without leaking token",
          env_status.get("result", {}).get("auth_required") is True and "s3cr3t-token" not in json.dumps(env_status),
          env_status)
    rt_cx.globals()["CE_MCP_AUTH_TOKEN"] = None


def main():
    print("=" * 70)
    print("CE MCP Bridge - offline regression tests (no Cheat Engine required)")
    print("=" * 70)

    test_json()
    test_debugger_preflight()
    test_dispatcher()
    test_idle_watchdog()
    test_optimizations_and_edge_fixes()
    test_bridge_hardening_regressions()

    print("\n" + "=" * 70)
    print("%d checks, %d failed" % (CHECKS, len(FAILURES)))
    for name in FAILURES:
        print("  FAILED: " + name)
    print("=" * 70)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
