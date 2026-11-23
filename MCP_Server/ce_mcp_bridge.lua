-- ============================================================================
-- CHEATENGINE MCP BRIDGE v11.6.3 - FORTIFIED EDITION
-- ============================================================================
-- Combines timer-based pipe communication (v10) with complete command set (v8)
-- This is the PRODUCTION version with all tools for AI-powered reverse engineering
-- v11.6.0: Safe breakpoint sampling with conditions, one-shot/max-hit limits,
--          trigger caps, auto-retirement, and protected debugger continuation.
-- v11.6.1: Added version-aware restart (removed in v11.6.2: synchronous restart can
--          deadlock CE when the connected worker is waiting on the main thread).
-- v11.6.2: Hot-swap the command dispatcher without stopping the pipe worker.
-- v11.6.3: Refuse implicit debugger startup from synchronous MCP dispatch.
-- v11.4.5: Make auto-start idempotent; re-executing this file becomes a no-op
--          while a worker is already alive, avoiding CE freezes from stop/restart.
-- v11.4.4: Abort restart if the old worker does not confirm exit, and tag workers
--          with a generation so stale threads cannot clobber the current pipe state.
-- v11.4.3: Persist server state across re-executions + force-disconnect on restart.
--          Re-running the script now finds and force-stops the previous worker thread,
--          disconnects its client, and waits for it to exit before recreating the pipe.
--          Fixes "all pipe instances busy" / zombie-worker lockups on script reload.
-- v11.4.2: Generic bounded AOB scans and broad-pattern guard
-- v11.4.0: Added robust cleanup on start/stop to prevent zombie breakpoints/watches
--          Ensures clean state on script reload even if resources are active
-- v11.3.1: Universal 32/64-bit handling, improved breakpoint capture, robust analysis
--          Fixed analyze_function, readPointer for pointer chains
-- ============================================================================

-- Pipe name can be overridden before executing this script:
--   _G.CE_MCP_PIPE_NAME = "CE_MCP_Bridge_alt"
-- so a second CE instance can be paired with `mcp_cheatengine.py --pipe CE_MCP_Bridge_alt`.
local PIPE_NAME = _G.CE_MCP_PIPE_NAME or "CE_MCP_Bridge_v99"
local VERSION = "11.6.3"
local TRANSPORT_VERSION = 1
local MAX_SCAN_BUDGET = 200000
-- Hardware breakpoints on a hot instruction produce hits faster than any client can
-- drain them. Keep a bounded ring so CE cannot be OOM'd and responses stay sendable.
local MAX_BP_HITS = 500
local MAX_BP_RESULTS = 100
-- The worker serves one pipe client at a time. Drop a client that has sent nothing
-- for this long so a stale MCP process (an AI session that never disconnected, an
-- old mcp_cheatengine.py without idle release) cannot lock everyone else out.
-- Override before executing this script; 0 disables the kick.
-- Optional shared-secret token for authenticating local pipe clients on shared
-- Windows hosts (Cheat Engine's createPipe grants access to local users).
-- Set `_G.CE_MCP_AUTH_TOKEN = "your-secret"` before executing or hot-reloading,
-- and configure the same CE_MCP_AUTH_TOKEN on mcp_cheatengine.py / check_pipe.py.
local function getAuthToken()
    local tok = rawget(_G, "CE_MCP_AUTH_TOKEN")
    if type(tok) == "string" and tok ~= "" then
        return tok
    end
    return nil
end

local function tokensEqual(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = diff | (a:byte(i) ~ b:byte(i))
    end
    return diff == 0
end

local IDLE_KICK_MS = tonumber(_G.CE_MCP_IDLE_KICK_MS) or 60000

-- Global State
-- IMPORTANT: persist across script re-executions. CE keeps the Lua VM alive between
-- "Execute Script" calls, so a `local` table here would be recreated on every run and the
-- previous run's worker thread + pipe instance would be orphaned (the root cause of
-- "all pipe instances busy" / zombie lockups, and why the v11.4.0 reload-cleanup never fired).
-- Bind to a uniquely-named persistent global so a re-execution can see the old worker.
-- Auto-start is intentionally idempotent: use RestartMCPBridge() for an explicit restart.
_G.__CE_MCP_BRIDGE_STATE = _G.__CE_MCP_BRIDGE_STATE or {
    running = false,
    timer = nil,
    pipe = nil,
    connected = false,
    scan_memscan = nil,
    scan_foundlist = nil,
    breakpoints = {},
    breakpoint_hits = {},
    breakpoint_results = {},
    breakpoint_generation = 0,
    breakpoint_process_id = 0,
    hw_bp_slots = {},      -- Hardware breakpoint slots (max 4)
    active_watches = {},   -- DBVM watch IDs for hypervisor-level tracing
    workerThread = nil,    -- live worker thread object (persisted so reload can stop it)
    workerPipe = nil,      -- live pipe instance (persisted so reload can destroy it)
    workerDone = true,     -- worker-exit handshake flag for bounded shutdown wait
    workerGeneration = 0,  -- monotonically increasing worker instance id
    workerVersion = nil,   -- version actually running in worker closures
    workerTransportVersion = nil,
    workerPipeName = nil,
    workerHotReload = false,
    dispatcherVersion = nil,
    dispatchInProgress = false,
    shutdownRequested = false
}
local serverState = _G.__CE_MCP_BRIDGE_STATE
local previousDispatcherVersion = serverState.dispatcherVersion

-- Fields added after a state table may already exist in a live CE session.
-- Without this, reloading the script onto an older state table leaves them nil.
serverState.breakpoints = serverState.breakpoints or {}
serverState.breakpoint_hits = serverState.breakpoint_hits or {}
serverState.breakpoint_results = serverState.breakpoint_results or {}
serverState.breakpoint_generation = serverState.breakpoint_generation or 0
serverState.dispatchInProgress = serverState.dispatchInProgress == true
if serverState.breakpoint_process_id == nil then
    local currentPid = 0
    local ok = pcall(function() currentPid = getOpenedProcessID() or 0 end)
    serverState.breakpoint_process_id = ok and currentPid or -1
end
serverState.hw_bp_slots = serverState.hw_bp_slots or {}
serverState.active_watches = serverState.active_watches or {}
serverState.aa_scripts = serverState.aa_scripts or {}   -- id -> {script, disableInfo}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

local function toHex(num)
    if not num then return "nil" end
    -- Handle both 32-bit and 64-bit addresses correctly
    if num < 0 then
        -- High-bit-set 64-bit addresses (e.g. kernel space 0xFFFF...) are signed negative in Lua 5.3+
        if num < -0xFFFFFFFF then
            return string.format("0x%016X", num)
        end
        return string.format("-0x%X", -num)
    elseif num > 0xFFFFFFFF then
        -- 64-bit address: use proper formatting
        local high = math.floor(num / 0x100000000)
        local low = num % 0x100000000
        return string.format("0x%X%08X", high, low)
    else
        -- 32-bit address
        return string.format("0x%08X", num)
    end
end

local function log(msg)
    print("[MCP v" .. VERSION .. "] " .. msg)
end

local function tickDiffMs(now, last)
    if now >= last then return now - last end
    return (0x100000000 - last) + now
end

local HEX_BYTE = {}
for i = 0, 255 do
    HEX_BYTE[i] = string.format("%02X", i)
end

local function parseIntegerValue(value)
    if type(value) == "number" then
        if value ~= value or value == math.huge or value == -math.huge or value % 1 ~= 0 then
            return nil
        end
        return math.floor(value)
    end
    if type(value) ~= "string" then return nil end
    local text = value:match("^%s*(.-)%s*$")
    if text == "" then return nil end
    local sign, hex = text:match("^([+-]?)0[xX](%x+)$")
    if hex then
        local n = tonumber(hex, 16)
        if not n then return nil end
        return (sign == "-") and -n or n
    end
    local n = tonumber(text)
    if not n or n ~= n or n == math.huge or n == -math.huge or n % 1 ~= 0 then
        return nil
    end
    return math.floor(n)
end

-- Make a byte string safe to put in JSON without destroying it.
-- Valid UTF-8 sequences pass through unchanged (game strings are often non-ASCII);
-- only control bytes and invalid sequences are escaped as \xNN. The previous
-- implementation escaped every byte >= 127, so any non-English string came back
-- as unreadable hex, and it built the result with O(n^2) string concatenation.
local function sanitizeForJson(str)
    if not str or str == "" then return "", false end
    if not str:find("[^\32-\126]") then return str, false end

    local out = {}
    local i, len = 1, #str
    local spanStart = 1
    local escaped = false

    while i <= len do
        local b = str:byte(i)
        if b >= 32 and b <= 126 then
            i = i + 1
        elseif b == 9 or b == 10 or b == 13 then
            if spanStart < i then
                out[#out + 1] = str:sub(spanStart, i - 1)
            end
            out[#out + 1] = " "
            i = i + 1
            spanStart = i
        elseif b < 32 or b == 127 then
            if spanStart < i then
                out[#out + 1] = str:sub(spanStart, i - 1)
            end
            out[#out + 1] = "\\x" .. (HEX_BYTE[b] or string.format("%02X", b))
            escaped = true
            i = i + 1
            spanStart = i
        else
            local seqLen = 0
            if b >= 0xF0 and b <= 0xF4 then seqLen = 4
            elseif b >= 0xE0 and b <= 0xEF then seqLen = 3
            elseif b >= 0xC2 and b <= 0xDF then seqLen = 2 end

            local valid = false
            if seqLen > 0 and (i + seqLen - 1) <= len then
                local c1 = str:byte(i + 1)
                if c1 >= 0x80 and c1 <= 0xBF then
                    valid = true
                    if b == 0xE0 and c1 < 0xA0 then valid = false
                    elseif b == 0xED and c1 > 0x9F then valid = false
                    elseif b == 0xF0 and c1 < 0x90 then valid = false
                    elseif b == 0xF4 and c1 > 0x8F then valid = false end

                    if valid then
                        for j = 2, seqLen - 1 do
                            local cb = str:byte(i + j)
                            if cb < 0x80 or cb > 0xBF then
                                valid = false
                                break
                            end
                        end
                    end
                end
            end

            if valid then
                i = i + seqLen
            else
                if spanStart < i then
                    out[#out + 1] = str:sub(spanStart, i - 1)
                end
                out[#out + 1] = "\\x" .. (HEX_BYTE[b] or string.format("%02X", b))
                escaped = true
                i = i + 1
                spanStart = i
            end
        end
    end

    if spanStart <= len then
        if #out == 0 then
            return str, escaped
        end
        out[#out + 1] = str:sub(spanStart, len)
    end

    return table.concat(out), escaped
end

-- Map CE's numeric variable types back to their names so structure output is
-- readable ("vtDword") instead of a bare enum value. Resolved from CE's own
-- globals rather than hardcoded, since the numbering is a CE implementation detail.
local VARTYPE_NAMES = nil
local function vartypeName(v)
    if type(v) ~= "number" then return nil end

    if not VARTYPE_NAMES then
        VARTYPE_NAMES = {}
        local names = {
            "vtByte", "vtWord", "vtDword", "vtQword", "vtSingle", "vtDouble",
            "vtString", "vtUnicodeString", "vtByteArray", "vtBinary",
            "vtAutoAssembler", "vtPointer", "vtCustom", "vtGrouped", "vtAll"
        }
        for _, name in ipairs(names) do
            local value = rawget(_G, name)
            if type(value) == "number" and VARTYPE_NAMES[value] == nil then
                VARTYPE_NAMES[value] = name
            end
        end
    end

    return VARTYPE_NAMES[v]
end

-- Universal 32/64-bit architecture helper
-- Returns pointer size, whether target is 64-bit, and current stack/instruction pointers
local function getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
        is64bit = is64,
        ptrSize = ptrSize,
        stackPtr = stackPtr,
        instPtr = instPtr
    }
end

-- Universal register capture - works for both 32-bit and 64-bit targets
local function captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and toHex(RAX) or nil,
            RBX = RBX and toHex(RBX) or nil,
            RCX = RCX and toHex(RCX) or nil,
            RDX = RDX and toHex(RDX) or nil,
            RSI = RSI and toHex(RSI) or nil,
            RDI = RDI and toHex(RDI) or nil,
            RBP = RBP and toHex(RBP) or nil,
            RSP = RSP and toHex(RSP) or nil,
            RIP = RIP and toHex(RIP) or nil,
            R8 = R8 and toHex(R8) or nil,
            R9 = R9 and toHex(R9) or nil,
            R10 = R10 and toHex(R10) or nil,
            R11 = R11 and toHex(R11) or nil,
            R12 = R12 and toHex(R12) or nil,
            R13 = R13 and toHex(R13) or nil,
            R14 = R14 and toHex(R14) or nil,
            R15 = R15 and toHex(R15) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x64"
        }
    else
        return {
            EAX = EAX and toHex(EAX) or nil,
            EBX = EBX and toHex(EBX) or nil,
            ECX = ECX and toHex(ECX) or nil,
            EDX = EDX and toHex(EDX) or nil,
            ESI = ESI and toHex(ESI) or nil,
            EDI = EDI and toHex(EDI) or nil,
            EBP = EBP and toHex(EBP) or nil,
            ESP = ESP and toHex(ESP) or nil,
            EIP = EIP and toHex(EIP) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x86"
        }
    end
end

-- Sentinel serialized by json.encode as JSON null (via type_func_map["function"])
-- so unreadable stack slots preserve exact 0-based [RSP + i*ptrSize] offsets.
local JSON_NULL = function() end

-- Universal stack capture - reads stack with correct pointer size
local function captureStack(depth)
    local arch = getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    depth = math.floor(tonumber(depth) or 0)
    if not stackPtr or depth <= 0 then return stack end

    local ptrSize = arch.ptrSize
    local anyReadable = false
    local filledSlots = 0
    local ok, bytes = pcall(readBytes, stackPtr, depth * ptrSize, true)
    if ok and type(bytes) == "table" and #bytes >= ptrSize then
        filledSlots = math.min(depth, math.floor(#bytes / ptrSize))
        for i = 0, filledSlots - 1 do
            local off = i * ptrSize
            local complete = true
            for b = 1, ptrSize do
                if bytes[off + b] == nil then
                    complete = false
                    break
                end
            end
            if complete then
                local val
                if ptrSize == 8 then
                    val = bytes[off + 1]
                        | (bytes[off + 2] << 8)
                        | (bytes[off + 3] << 16)
                        | (bytes[off + 4] << 24)
                        | (bytes[off + 5] << 32)
                        | (bytes[off + 6] << 40)
                        | (bytes[off + 7] << 48)
                        | (bytes[off + 8] << 56)
                else
                    val = bytes[off + 1]
                        + bytes[off + 2] * 0x100
                        + bytes[off + 3] * 0x10000
                        + bytes[off + 4] * 0x1000000
                end
                stack[i + 1] = toHex(val)
                anyReadable = true
            end
        end
        if anyReadable and filledSlots == depth then
            local allPresent = true
            for idx = 1, depth do
                if stack[idx] == nil then
                    allPresent = false
                    break
                end
            end
            if allPresent then
                return stack
            end
        end
    end

    local reader = arch.is64bit and readQword or readInteger
    local hasReader = type(reader) == "function"
    for i = 0, depth - 1 do
        local idx = i + 1
        if stack[idx] == nil then
            local val = nil
            if hasReader then
                local okRead, readVal = pcall(reader, stackPtr + i * ptrSize)
                if okRead and readVal ~= nil then
                    val = readVal
                end
            end
            if val ~= nil then
                stack[idx] = toHex(val)
                anyReadable = true
            else
                stack[idx] = JSON_NULL
            end
        end
    end

    if not anyReadable then
        return {}
    end
    return stack
end

-- Destroy scan objects safely to avoid leaking memscan/foundlist across runs.
local function cleanupScanObjects()
    local cleaned = { memscan = 0, foundlist = 0 }

    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
        cleaned.foundlist = 1
    end

    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
        cleaned.memscan = 1
    end

    return cleaned
end

local function breakpointAddressFromEntry(value)
    if type(value) == "number" then return value end
    if type(value) == "string" then
        local hex = value:match("^0[xX](%x+)$")
        return hex and tonumber(hex, 16) or tonumber(value)
    end
    if type(value) == "table" then
        return breakpointAddressFromEntry(value.address or value.Address or value[1])
    end
    return nil
end

-- CE's debug_setBreakpoint has no documented success return. Verify changes
-- against CE's actual breakpoint list instead of trusting pcall alone.
local function isCeBreakpointInstalled(addr)
    if type(debug_getBreakpointList) ~= "function" then
        return nil, "debug_getBreakpointList is unavailable"
    end

    local ok, list = pcall(debug_getBreakpointList)
    if not ok then
        return nil, "debug_getBreakpointList failed: " .. tostring(list)
    end
    -- CE returns nil rather than an empty table when no breakpoints exist.
    if list == nil then return false end
    if type(list) ~= "table" then
        return nil, "debug_getBreakpointList returned " .. type(list)
    end

    for key, value in pairs(list) do
        local entryAddress = breakpointAddressFromEntry(value) or breakpointAddressFromEntry(key)
        if entryAddress == addr then return true end
    end
    return false
end

local function removeCeBreakpointVerified(addr)
    local installed, listErr = isCeBreakpointInstalled(addr)
    if installed == nil then return false, listErr end
    if not installed then return true end

    local ok, removeResult = pcall(debug_removeBreakpoint, addr)
    if not ok then
        return false, "debug_removeBreakpoint raised: " .. tostring(removeResult)
    end

    local stillInstalled, verifyErr = isCeBreakpointInstalled(addr)
    if stillInstalled == nil then return false, verifyErr end
    if stillInstalled then
        return false, "debug_removeBreakpoint did not remove " .. toHex(addr)
    end
    return true
end

-- Remove tracked breakpoint state by id and optionally detach CE breakpoint.
local function clearTrackedBreakpointById(bpId, removeCeBreakpoint)
    if not bpId then return false end

    local bp = serverState.breakpoints[bpId]
    local existed = bp ~= nil or serverState.breakpoint_results[bpId] ~= nil or serverState.breakpoint_hits[bpId] ~= nil

    if bp and removeCeBreakpoint and bp.address then
        local removed, removeErr = removeCeBreakpointVerified(bp.address)
        if not removed then
            bp.remove_error = removeErr
            return false, removeErr
        end
    end

    if bp and bp.slot then
        serverState.hw_bp_slots[bp.slot] = nil
    end

    serverState.breakpoints[bpId] = nil
    serverState.breakpoint_hits[bpId] = nil
    serverState.breakpoint_results[bpId] = nil
    return existed
end

-- Append a hit for a breakpoint.
-- Must never assume the per-id bucket still exists: get_breakpoint_hits(clear=true)
-- used to replace the whole breakpoint_hits table, after which the next hit ran
-- table.insert(nil, ...) inside the debugger callback. That error aborted the
-- callback before debug_continueFromBreakpoint, leaving the target thread frozen.
local function recordBreakpointHit(bpId, hitData)
    local bucket = serverState.breakpoint_hits[bpId]
    if not bucket then
        bucket = {}
        serverState.breakpoint_hits[bpId] = bucket
    end

    if #bucket >= MAX_BP_HITS then
        table.remove(bucket, 1)
        hitData.dropped_older_hits = true
    end

    table.insert(bucket, hitData)
end

-- Auto-retire a breakpoint without discarding its buffered hits. This is used by
-- one-shot and bounded sampling so callers can retrieve the final hit after the
-- hardware slot has already been released.
local function retireTrackedBreakpointById(bpId, reason)
    local bp = serverState.breakpoints[bpId]
    if not bp then return false end

    if bp.address then
        local removed, removeErr = removeCeBreakpointVerified(bp.address)
        if not removed then
            bp.retire_error = removeErr
            return false, removeErr
        end
    end

    if bp.slot then
        serverState.hw_bp_slots[bp.slot] = nil
    end

    bp.active = false
    bp.slot = nil
    bp.retired_reason = reason or "completed"
    bp.retired_at = os.time()
    serverState.breakpoint_results[bpId] = bp
    serverState.breakpoints[bpId] = nil

    local resultCount, oldestId, oldestTime = 0, nil, math.huge
    for id, result in pairs(serverState.breakpoint_results) do
        resultCount = resultCount + 1
        local retiredAt = tonumber(result.retired_at) or 0
        if retiredAt < oldestTime then
            oldestId, oldestTime = id, retiredAt
        end
    end
    if resultCount > MAX_BP_RESULTS and oldestId then
        serverState.breakpoint_results[oldestId] = nil
        serverState.breakpoint_hits[oldestId] = nil
    end
    return true
end

-- Remove all tracked breakpoints that point to the same address.
local function clearTrackedBreakpointsByAddress(addr, removeCeBreakpoint)
    if not addr then return 0, {} end

    local ids = {}
    for id, bp in pairs(serverState.breakpoints) do
        if bp.address == addr then
            table.insert(ids, id)
        end
    end

    local removed = 0
    local failures = {}
    for _, id in ipairs(ids) do
        local ok, err = clearTrackedBreakpointById(id, removeCeBreakpoint)
        if ok then
            removed = removed + 1
        else
            table.insert(failures, { id = id, error = err or "remove failed" })
        end
    end

    return removed, failures
end

local function ensureBreakpointProcessContext()
    local ok, pid = pcall(getOpenedProcessID)
    if not ok then
        return nil, "getOpenedProcessID failed: " .. tostring(pid)
    end
    pid = pid or 0

    local previousPid = serverState.breakpoint_process_id
    if previousPid == -1 then
        -- Migration from an older state whose PID could not be queried during load.
        serverState.breakpoint_process_id = pid
        return pid
    end
    previousPid = previousPid or 0
    if previousPid ~= pid then
        -- CE drops debugger state when changing targets. Never try to remove an old
        -- virtual address from the newly attached process.
        serverState.breakpoints = {}
        serverState.breakpoint_hits = {}
        serverState.breakpoint_results = {}
        serverState.hw_bp_slots = {}
        serverState.aa_scripts = {}
        serverState.breakpoint_generation = (serverState.breakpoint_generation or 0) + 1
        serverState.breakpoint_process_id = pid
    end
    return pid
end

-- ============================================================================
-- CLEANUP & SAFETY ROUTINES (CRITICAL FOR ROBUSTNESS)
-- ============================================================================
-- Prevents "zombie" breakpoints and DBVM watches when script is reloaded

local function cleanupZombieState()
    log("Cleaning up zombie resources...")
    local cleaned = { breakpoints = 0, breakpoint_errors = {}, dbvm_watches = 0, scans = 0 }
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then
        table.insert(cleaned.breakpoint_errors, {
            id = "*",
            error = contextErr
        })
    end
    
    -- 1. Remove all Hardware Breakpoints managed by us
    if serverState.breakpoints and not contextErr then
        local ids = {}
        for id in pairs(serverState.breakpoints) do table.insert(ids, id) end
        for _, id in ipairs(ids) do
            local ok, err = clearTrackedBreakpointById(id, true)
            if ok then
                cleaned.breakpoints = cleaned.breakpoints + 1
            else
                table.insert(cleaned.breakpoint_errors, {
                    id = id,
                    error = err or "remove failed"
                })
            end
        end
    end
    
    -- 2. Stop all DBVM Watches
    if serverState.active_watches then
        for key, watch in pairs(serverState.active_watches) do
            if watch.id then
                local ok = pcall(function() dbvm_watch_disable(watch.id) end)
                if ok then cleaned.dbvm_watches = cleaned.dbvm_watches + 1 end
            end
        end
    end

    -- 3. Cleanup Scan memory objects
    local scanCleaned = cleanupScanObjects()
    cleaned.scans = scanCleaned.memscan + scanCleaned.foundlist

    -- Completed samples can be discarded. Failed active removals stay tracked so
    -- a later cleanup can retry instead of creating invisible zombie breakpoints.
    serverState.breakpoint_results = {}
    for id in pairs(serverState.breakpoint_hits) do
        if not serverState.breakpoints[id] then
            serverState.breakpoint_hits[id] = nil
        end
    end
    serverState.active_watches = {}
    
    if cleaned.breakpoints > 0 or cleaned.dbvm_watches > 0 or cleaned.scans > 0 then
        log(string.format("Cleaned: %d breakpoints, %d DBVM watches, %d scans", 
            cleaned.breakpoints, cleaned.dbvm_watches, cleaned.scans))
    end
    
    return cleaned
end

-- ============================================================================
-- JSON LIBRARY (Pure Lua - Complete Implementation)
-- ============================================================================
local json = {}
local encode

local escape_char_map = { [ "\\" ] = "\\", [ "\"" ] = "\"", [ "\b" ] = "b", [ "\f" ] = "f", [ "\n" ] = "n", [ "\r" ] = "r", [ "\t" ] = "t" }
local escape_char_map_inv = { [ "/" ] = "/" }
for k, v in pairs(escape_char_map) do escape_char_map_inv[v] = k end
local function escape_char(c) return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte())) end
local function encode_nil(val) return "null" end
local function encode_table(val, stack)
  local res, stack = {}, stack or {}
  if stack[val] then error("circular reference") end
  stack[val] = true

  local isArray = true
  local count = 0
  local maxIdx = 0
  for k, _ in pairs(val) do
    count = count + 1
    if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then
      isArray = false
      break
    end
    if k > maxIdx then maxIdx = k end
  end

  if isArray and (count == 0 or maxIdx == count) then
    for i = 1, count do res[i] = encode(val[i], stack) end
    stack[val] = nil
    return "[" .. table.concat(res, ",") .. "]"
  else
    for k, v in pairs(val) do
      if type(k) ~= "string" then k = tostring(k) end
      res[#res + 1] = encode(k, stack) .. ":" .. encode(v, stack)
    end
    stack[val] = nil
    return "{" .. table.concat(res, ",") .. "}"
  end
end
local function encode_string(val) return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"' end
-- Numbers must round-trip exactly. "%.14g" silently mangles 64-bit addresses
-- (0x7FF6A0001000 = 140694538166272 needs 15 digits) into scientific notation,
-- so every raw `value` field for an x64 pointer came back wrong on the Python side.
local function encode_number(val)
  if val ~= val or val <= -math.huge or val >= math.huge then return "null" end
  if math.type and math.type(val) == "integer" then
    return string.format("%d", val)
  end
  if val == math.floor(val) and math.abs(val) < 9.2233720368547758e18 then
    return string.format("%.0f", val)
  end
  local short = string.format("%.14g", val)
  if tonumber(short) == val then return short end
  return string.format("%.17g", val)
end
local type_func_map = { ["nil"] = encode_nil, ["table"] = encode_table, ["string"] = encode_string, ["number"] = encode_number, ["boolean"] = tostring, ["function"] = function() return "null" end, ["userdata"] = function() return "null" end }
encode = function(val, stack) local t = type(val) local f = type_func_map[t] if f then return f(val, stack) end error("unexpected type '" .. t .. "'") end
json.encode = encode

local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
local decode

-- \uXXXX must become UTF-8. The old decoder called string.char(codepoint), which
-- raises "value out of range" for anything above U+00FF, so any request carrying
-- non-ASCII text (Chinese paths, comments in a Lua/AA file, strings to write)
-- failed to parse. Python's json.dumps escapes those by default.
local function codepointToUtf8(n)
  if n < 0x80 then
    return string.char(n)
  elseif n < 0x800 then
    return string.char(0xC0 + math.floor(n / 0x40), 0x80 + n % 0x40)
  elseif n < 0x10000 then
    return string.char(0xE0 + math.floor(n / 0x1000),
                       0x80 + math.floor(n / 0x40) % 0x40,
                       0x80 + n % 0x40)
  else
    return string.char(0xF0 + math.floor(n / 0x40000),
                       0x80 + math.floor(n / 0x1000) % 0x40,
                       0x80 + math.floor(n / 0x40) % 0x40,
                       0x80 + n % 0x40)
  end
end

-- Single pass so "\\u0041" (escaped backslash then literal u) is not mistaken
-- for an escape, which the previous two-gsub approach got wrong.
local function unescapeJsonString(s)
  local out = {}
  local i, len = 1, #s
  while i <= len do
    local nextEsc = s:find("\\", i, true)
    if not nextEsc then
      out[#out + 1] = s:sub(i)
      break
    end
    if nextEsc > i then out[#out + 1] = s:sub(i, nextEsc - 1) end
    if nextEsc == len then return nil, "trailing backslash" end
    local e = s:sub(nextEsc + 1, nextEsc + 1)
    if e == "u" then
      local hex = s:sub(nextEsc + 2, nextEsc + 5)
      if not hex:match("^%x%x%x%x$") then return nil, "invalid \\u escape" end
      local cp = tonumber(hex, 16)
      i = nextEsc + 6
      if cp >= 0xD800 and cp <= 0xDBFF and s:sub(i, i + 1) == "\\u" then
        local lowHex = s:sub(i + 2, i + 5)
        if not lowHex:match("^%x%x%x%x$") then return nil, "invalid \\u escape" end
        local low = tonumber(lowHex, 16)
        if low >= 0xDC00 and low <= 0xDFFF then
          cp = 0x10000 + (cp - 0xD800) * 0x400 + (low - 0xDC00)
          i = i + 6
        end
      end
      out[#out + 1] = codepointToUtf8(cp)
    else
      out[#out + 1] = escape_char_map_inv[e] or e
      i = nextEsc + 2
    end
  end
  return table.concat(out)
end

local function decode_string(str, pos)
  local startpos = pos + 1
  local endpos = pos
  while true do
    endpos = str:find('["\\]', endpos + 1)
    if not endpos then return nil, "expected closing quote" end
    if str:sub(endpos, endpos) == '"' then break end
    endpos = endpos + 1
  end
  local s, err = unescapeJsonString(str:sub(startpos, endpos - 1))
  if not s then return nil, err end
  return s, endpos + 1
end
local function decode_number(str, pos)
  local numstr = str:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
  local val = tonumber(numstr)
  if not val then return nil, "invalid number" end
  return val, pos + #numstr
end
local function decode_literal(str, pos)
  local word = str:match("^%a+", pos)
  if word == "true" then return true, pos + 4 end
  if word == "false" then return false, pos + 5 end
  if word == "null" then return nil, pos + 4 end
  return nil, "invalid literal"
end
local decode_value
local function decode_array(str, pos)
  pos = pos + 1
  local arr, n = {}, 0
  local hasNull = false
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "]" then return arr, pos + 1 end
  while true do
    local val
    val, pos = decode_value(str, pos)
    if type(pos) ~= "number" then return nil, pos or "invalid array value" end
    n = n + 1
    if val == nil then
      hasNull = true
    else
      arr[n] = val
    end
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "]" then
      if hasNull then setmetatable(arr, { __json_array_len = n }) end
      return arr, pos + 1
    end
    if c ~= "," then return nil, "expected ']' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local function decode_object(str, pos)
  pos = pos + 1
  local obj = {}
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "}" then return obj, pos + 1 end
  while true do
    if str:sub(pos, pos) ~= '"' then return nil, "expected string key" end
    local key
    key, pos = decode_string(str, pos)
    if not key then return nil, pos or "expected string key" end
    pos = decode_scanwhite(str, pos)
    if str:sub(pos, pos) ~= ":" then return nil, "expected ':'" end
    pos = decode_scanwhite(str, pos + 1)
    local val
    val, pos = decode_value(str, pos)
    if type(pos) ~= "number" then return nil, pos or "invalid object value" end
    obj[key] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "}" then return obj, pos + 1 end
    if c ~= "," then return nil, "expected '}' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local char_func_map = { ['"'] = decode_string, ["{"] = decode_object, ["["] = decode_array }
setmetatable(char_func_map, { __index = function(t, c) if c:match("%d") or c == "-" then return decode_number end return decode_literal end })
decode_value = function(str, pos)
  pos = decode_scanwhite(str, pos or 1)
  if pos > #str then return nil, "unexpected end of input" end
  local c = str:sub(pos, pos)
  return char_func_map[c](str, pos)
end
decode = function(str, pos)
  if type(str) ~= "string" then return nil, "expected string" end
  if pos ~= nil then
    return decode_value(str, pos)
  end
  local val, nextPos = decode_value(str, 1)
  if type(nextPos) ~= "number" then
    return nil, nextPos
  end
  if decode_scanwhite(str, nextPos) <= #str then
    return nil, "trailing data"
  end
  return val, nextPos
end
json.decode = decode

-- ============================================================================
-- COMMAND HANDLERS - PROCESS & MODULES
-- ============================================================================

local function cmd_get_process_info(params)
    -- Only reinitialize symbol handler when explicitly requested; doing this on
    -- every query reloads PDBs/exports and stalls CE's main thread.
    if params.refresh_symbols == true then
        pcall(reinitializeSymbolhandler)
    end
    
    local pid = getOpenedProcessID()
    if pid and pid > 0 then
        -- Get modules using CE's native enumeration only. Do not fall back to global MZ scans.
        local modules = enumModules(pid)
        if not modules or #modules == 0 then
            modules = enumModules()
        end
        
        -- Build module list
        local moduleList = {}
        local mainModuleName = nil
        local moduleFallbackSkipped = false
        
        if modules and #modules > 0 then
            for i = 1, math.min(#modules, 50) do
                local m = modules[i]
                if m then
                    table.insert(moduleList, {
                        name = m.Name or "???",
                        address = toHex(m.Address or 0),
                        size = m.Size or 0
                    })
                    if i == 1 then mainModuleName = m.Name end
                end
            end
        end
        
        if #moduleList == 0 then
            moduleFallbackSkipped = true
        end
        
        -- `process` is CE's global holding the attached process name. It can be nil or
        -- empty when anti-cheat hides the process; fall back to the first enumerated
        -- module (CE lists the main image first) instead of a hardcoded game name.
        local name = nil
        if type(process) == "string" and process ~= "" then
            name = process
        elseif mainModuleName and mainModuleName ~= "" then
            name = mainModuleName
        end

        local is64 = false
        pcall(function() is64 = targetIs64Bit() end)

        return {
            success = true,
            process_id = pid,
            process_name = name or "unknown",
            process_name_resolved = name ~= nil,
            architecture = is64 and "x64" or "x86",
            is_64bit = is64,
            pointer_size = is64 and 8 or 4,
            module_count = #moduleList,
            total_modules = modules and #modules or 0,
            modules_truncated = (modules and #modules or 0) > #moduleList,
            modules = moduleList,
            module_fallback_skipped = moduleFallbackSkipped,
            module_fallback_reason = moduleFallbackSkipped and "global MZ AOB scan disabled by 200000 scan budget" or nil
        }
    end
    return { success = false, error = "No process attached" }
end

local function cmd_enum_modules(params)
    local pid = getOpenedProcessID()
    local modules = enumModules(pid)  -- Try with PID first
    
    -- If that fails, try without PID
    if not modules or #modules == 0 then
        modules = enumModules()
    end
    
    local result = {}
    if modules and #modules > 0 then
        for i, m in ipairs(modules) do
            if m then
                table.insert(result, {
                    name = m.Name or "???",
                    address = toHex(m.Address or 0),
                    size = m.Size or 0,
                    is_64bit = m.Is64Bit or false,
                    path = m.PathToFile or ""
                })
            end
        end
    end
    
    if #result == 0 then
        return {
            success = true,
            modules = {},
            count = 0,
            fallback_skipped = true,
            fallback_reason = "global MZ AOB scan disabled by 200000 scan budget"
        }
    end
    
    return { success = true, modules = result, count = #result, fallback_used = false }
end

local function cmd_get_symbol_address(params)
    local symbol = params.symbol or params.name
    if not symbol then return { success = false, error = "No symbol name" } end
    
    local addr = getAddressSafe(symbol)
    if addr then
        return { success = true, symbol = symbol, address = toHex(addr), value = addr }
    end
    return { success = false, error = "Symbol not found: " .. symbol }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY READ
-- ============================================================================

local function cmd_read_memory(params)
    local addr = params.address
    local size = math.min(math.max(math.floor(tonumber(params.size) or 256), 1), 65536)
    local includeBytes = params.include_bytes ~= false
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local bytes = readBytes(addr, size, true)
    if not bytes then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    local hex = {}
    for i = 1, #bytes do
        local b = bytes[i]
        hex[i] = HEX_BYTE[b] or string.format("%02X", b)
    end
    
    local resp = { 
        success = true, 
        address = toHex(addr), 
        size = #bytes, 
        data = table.concat(hex, " "),
    }
    if includeBytes then
        resp.bytes = bytes
    end
    return resp
end

local function cmd_read_integer(params)
    local addr = params.address
    local itype = params.type or "dword"
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local val
    if itype == "byte" then
        local b = readBytes(addr, 1, true)
        if b and #b > 0 then val = b[1] end
    elseif itype == "word" then val = readSmallInteger(addr)
    elseif itype == "dword" then val = readInteger(addr)
    elseif itype == "qword" then val = readQword(addr)
    elseif itype == "float" then val = readFloat(addr)
    elseif itype == "double" then val = readDouble(addr)
    else return { success = false, error = "Unknown type: " .. tostring(itype) } end
    
    if val == nil then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    return { success = true, address = toHex(addr), value = val, type = itype, hex = toHex(val) }
end

local function cmd_read_string(params)
    local addr = params.address
    local maxlen = math.min(math.max(math.floor(tonumber(params.max_length) or 256), 1), 65536)
    local wide = params.wide or false
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local okRead, str = pcall(readString, addr, maxlen, wide)
    if not okRead or str == nil then
        return { success = false, address = toHex(addr), error = "Failed to read string at " .. toHex(addr) }
    end

    local sanitized, escaped = sanitizeForJson(str)

    return {
        success = true,
        address = toHex(addr),
        value = sanitized,
        wide = wide,
        length = #str,                    -- bytes returned by CE
        display_length = #sanitized,       -- length after escaping
        contains_escaped_bytes = escaped,
        truncated = (#str >= maxlen)
    }
end

local function parsePointerOffsets(offsets)
    if offsets == nil then return {} end
    if type(offsets) ~= "table" then
        return nil, "Invalid offsets: expected array"
    end
    local mt = getmetatable(offsets)
    local expectedLen = (mt and mt.__json_array_len) or #offsets
    local count = 0
    local maxIdx = 0
    for k, _ in pairs(offsets) do
        if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then
            return nil, "Invalid offsets: expected dense array"
        end
        count = count + 1
        if k > maxIdx then maxIdx = k end
    end
    if count ~= expectedLen or maxIdx ~= expectedLen then
        return nil, "Invalid offsets: array must not contain null or missing elements"
    end
    local parsedOffsets = {}
    for i = 1, expectedLen do
        local rawOffset = offsets[i]
        local offset = parseIntegerValue(rawOffset)
        if offset == nil then
            return nil, "Invalid offset at index " .. i .. ": " .. tostring(rawOffset)
        end
        parsedOffsets[i] = offset
    end
    return parsedOffsets
end

local function cmd_read_pointer(params)
    local base = params.base or params.address
    local parsedOffsets, offsetsErr = parsePointerOffsets(params.offsets)
    if not parsedOffsets then
        return { success = false, error = offsetsErr }
    end

    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end

    local currentAddr = base
    local path = { toHex(base) }

    for i, offset in ipairs(parsedOffsets) do
        -- Use readPointer for 32/64-bit compatibility (readInteger on 32-bit, readQword on 64-bit)
        local ptr = readPointer(currentAddr)
        if not ptr then
            return { success = false, error = "Failed to read pointer at " .. toHex(currentAddr), path = path }
        end
        currentAddr = ptr + offset
        table.insert(path, toHex(currentAddr))
    end

    -- Read final value using readPointer for 32/64-bit compatibility
    local finalValue = readPointer(currentAddr)
    return { 
        success = true, 
        base = toHex(base), 
        final_address = toHex(currentAddr), 
        value = finalValue, 
        path = path 
    }
end

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

local function parseAobPattern(pattern)
    local tokens = {}
    local fixed = 0
    local wildcards = 0

    for rawToken in tostring(pattern):gmatch("%S+") do
        local token = rawToken:upper()
        local wildcard = token == "?" or token == "??" or token == "*" or token == "**"
        local value = nil

        if wildcard then
            wildcards = wildcards + 1
        else
            value = tonumber(token, 16)
            if not value or value < 0 or value > 0xFF then
                return nil, "Invalid AOB token: " .. rawToken
            end
            fixed = fixed + 1
        end

        table.insert(tokens, { wildcard = wildcard, value = value })
    end

    if #tokens == 0 then
        return nil, "Empty AOB pattern"
    end

    return {
        tokens = tokens,
        length = #tokens,
        fixed = fixed,
        wildcards = wildcards,
    }, nil
end

local function classifyUnsafeGlobalAob(stats)
    local wildcardRatio = stats.wildcards / stats.length

    if stats.fixed == 0 then
        return true, "pattern has no fixed bytes"
    end

    if stats.length <= 8 and stats.fixed <= 2 then
        return true, "short pattern has too few fixed bytes"
    end

    if wildcardRatio >= 0.70 and stats.fixed <= 4 then
        return true, "pattern wildcard ratio is too high"
    end

    return false, nil
end

local COMMON_ANCHOR_BYTES = {
    [0x00] = true, [0x90] = true, [0xCC] = true, [0xFF] = true,
}

local function compilePatternMatcher(stats)
    local fixedOffs = {}
    local fixedVals = {}
    local anchorIdx = nil

    for j = 1, stats.length do
        local token = stats.tokens[j]
        if not token.wildcard then
            local k = #fixedOffs + 1
            fixedOffs[k] = j - 1
            fixedVals[k] = token.value
            if not anchorIdx or (COMMON_ANCHOR_BYTES[fixedVals[anchorIdx]] and not COMMON_ANCHOR_BYTES[token.value]) then
                anchorIdx = k
            end
        end
    end

    if not anchorIdx then
        return {
            length = stats.length,
            anchorOff = 0,
            anchorVal = nil,
            fixedCount = 0,
            fixedOffs = fixedOffs,
            fixedVals = fixedVals,
            relOffs = {},
        }
    end

    local anchorOff = fixedOffs[anchorIdx]
    -- Move remaining fixed bytes into compact arrays excluding the anchor so the
    -- inner verification loop skips re-checking the anchor byte.
    local remOffs, remVals, relOffs = {}, {}, {}
    for k = 1, #fixedOffs do
        if k ~= anchorIdx then
            remOffs[#remOffs + 1] = fixedOffs[k]
            remVals[#remVals + 1] = fixedVals[k]
            relOffs[#relOffs + 1] = fixedOffs[k] - anchorOff
        end
    end

    return {
        length = stats.length,
        anchorOff = anchorOff,
        anchorVal = fixedVals[anchorIdx],
        fixedCount = #remOffs,
        fixedOffs = remOffs,
        fixedVals = remVals,
        relOffs = relOffs,
    }
end

local function scanAobRange(startAddr, scanSize, stats, limit, timeBudgetMs)
    local addresses = {}
    local chunkSize = 0x20000
    local patLen = stats.length
    local overlap = math.max(patLen - 1, 0)
    local scanned = 0
    local truncated = false
    local started = getTickCount()

    local matcher = stats._compiled
    if not matcher then
        matcher = compilePatternMatcher(stats)
        stats._compiled = matcher
    end

    local anchorOff = matcher.anchorOff
    local anchorVal = matcher.anchorVal
    local fixedCount = matcher.fixedCount
    local fixedVals = matcher.fixedVals
    local relOffs = matcher.relOffs

    while scanned < scanSize and #addresses < limit do
        if tickDiffMs(getTickCount(), started) > timeBudgetMs then
            truncated = true
            break
        end

        local chunkAddr = startAddr + scanned
        local remaining = scanSize - scanned
        local readSize = math.min(chunkSize + overlap, remaining)
        local ok, bytes = pcall(readBytes, chunkAddr, readSize, true)

        if ok and bytes then
            local maxIndex = #bytes - patLen + 1
            if maxIndex > chunkSize then maxIndex = chunkSize end

            if anchorVal == nil then
                for i = 1, maxIndex do
                    local addr = chunkAddr + i - 1
                    addresses[#addresses + 1] = {
                        address = toHex(addr),
                        value = addr,
                    }
                    if #addresses >= limit then break end
                end
            elseif fixedCount == 0 then
                local aStart = 1 + anchorOff
                local aEnd = maxIndex + anchorOff
                local addrBase = chunkAddr - anchorOff - 1
                for a = aStart, aEnd do
                    if bytes[a] == anchorVal then
                        local addr = addrBase + a
                        addresses[#addresses + 1] = {
                            address = toHex(addr),
                            value = addr,
                        }
                        if #addresses >= limit then break end
                    end
                end
            else
                local rel1 = relOffs[1]
                local val1 = fixedVals[1]
                local aStart = 1 + anchorOff
                local aEnd = maxIndex + anchorOff
                local addrBase = chunkAddr - anchorOff - 1
                for a = aStart, aEnd do
                    if bytes[a] == anchorVal and bytes[a + rel1] == val1 then
                        local matched = true
                        for k = 2, fixedCount do
                            if bytes[a + relOffs[k]] ~= fixedVals[k] then
                                matched = false
                                break
                            end
                        end
                        if matched then
                            local addr = addrBase + a
                            addresses[#addresses + 1] = {
                                address = toHex(addr),
                                value = addr,
                            }
                            if #addresses >= limit then break end
                        end
                    end
                end
            end
        end

        scanned = scanned + chunkSize
        if processMessages then pcall(processMessages) end
    end

    return addresses, math.min(scanned, scanSize), truncated
end

local function hasFlag(value, flag)
    value = tonumber(value) or 0
    return math.floor(value / flag) % 2 == 1
end

local function clampScanBudget(value)
    local n = tonumber(value) or MAX_SCAN_BUDGET
    n = math.floor(n)
    if n < 1 then n = 1 end
    if n > MAX_SCAN_BUDGET then n = MAX_SCAN_BUDGET end
    return n
end

local function parseAddressValue(value)
    if type(value) == "number" then return value end
    if type(value) ~= "string" or value == "" then return nil end
    local ok, addr = pcall(getAddressSafe, value)
    if ok and addr then return addr end
    local hex = value:match("^0[xX](%x+)$")
    if hex then return tonumber(hex, 16) end
    return tonumber(value)
end

local function isReadableCommittedRegion(region)
    local state = tonumber(region.State or 0) or 0
    local protect = tonumber(region.Protect or 0) or 0
    if state ~= 0x1000 then return false end
    if hasFlag(protect, 0x01) or hasFlag(protect, 0x100) then return false end
    return hasFlag(protect, 0x02)
        or hasFlag(protect, 0x04)
        or hasFlag(protect, 0x08)
        or hasFlag(protect, 0x20)
        or hasFlag(protect, 0x40)
        or hasFlag(protect, 0x80)
end

local function regionHasWrite(region)
    local protect = tonumber(region.Protect or 0) or 0
    return hasFlag(protect, 0x04) or hasFlag(protect, 0x08) or hasFlag(protect, 0x40) or hasFlag(protect, 0x80)
end

local function regionHasExecute(region)
    local protect = tonumber(region.Protect or 0) or 0
    return hasFlag(protect, 0x10) or hasFlag(protect, 0x20) or hasFlag(protect, 0x40) or hasFlag(protect, 0x80)
end

local function regionMatchesProtection(region, protection)
    local p = tostring(protection or "")
    if p:find("%+R") and not isReadableCommittedRegion(region) then return false end
    if p:find("%+W") and not regionHasWrite(region) then return false end
    if p:find("%+X") and not regionHasExecute(region) then return false end
    if p:find("%-W") and regionHasWrite(region) then return false end
    if p:find("%-X") and regionHasExecute(region) then return false end
    return true
end

-- enumMemoryRegions is expensive (hundreds of thousands of regions on a real x64
-- process). Cache both the full sorted list and the committed-readable subset,
-- and stamp the cache AFTER enumeration so slow VirtualQueryEx calls do not
-- immediately expire their own cache entry.
local REGION_CACHE_TTL_MS = 15000
local regionCache = { regions = nil, readable = nil, pid = nil, at = 0 }

local function getSortedMemoryRegions(forceRefresh, readableOnly)
    local pid = getOpenedProcessID() or 0
    local now = getTickCount()
    local age = tickDiffMs(now, regionCache.at)

    if (not forceRefresh) and regionCache.regions and regionCache.pid == pid
       and age < REGION_CACHE_TTL_MS then
        return readableOnly and regionCache.readable or regionCache.regions
    end

    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return nil, "enumMemoryRegions failed"
    end

    local sorted = true
    local prevBase = -math.huge
    for i = 1, #regions do
        local base = regions[i].BaseAddress or 0
        if base < prevBase then
            sorted = false
            break
        end
        prevBase = base
    end
    if not sorted then
        table.sort(regions, function(a, b)
            return (a.BaseAddress or 0) < (b.BaseAddress or 0)
        end)
    end

    local readable = {}
    for i = 1, #regions do
        local r = regions[i]
        if isReadableCommittedRegion(r) then
            readable[#readable + 1] = r
        end
    end

    regionCache.regions = regions
    regionCache.readable = readable
    regionCache.pid = pid
    regionCache.at = getTickCount()
    return readableOnly and readable or regions
end

local function findFirstRegionIndexForCursor(regions, cursor)
    local lo, hi = 1, #regions
    local ans = hi + 1
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        local r = regions[mid]
        local base = tonumber(r.BaseAddress or 0) or 0
        local regionSize = tonumber(r.RegionSize or 0) or 0
        if base + regionSize > cursor then
            ans = mid
            hi = mid - 1
        else
            lo = mid + 1
        end
    end
    return ans
end

local function chooseScanWindow(params)
    local explicitStart = nil
    if params.start_address ~= nil and params.start_address ~= "" then
        explicitStart = parseAddressValue(params.start_address)
        if not explicitStart then
            return nil, "Invalid start_address: " .. tostring(params.start_address)
        end
    end
    local requestedSize = tonumber(params.size or params.scan_size)
    local budget = clampScanBudget(params.max_scan or requestedSize or MAX_SCAN_BUDGET)

    if explicitStart and requestedSize and requestedSize > 0 then
        local actualSize = clampScanBudget(requestedSize)
        return {
            start = explicitStart,
            size = actualSize,
            explicit = true,
            truncated = requestedSize > actualSize,
            next_start = explicitStart + actualSize,
        }
    end

    local cursor = explicitStart or parseAddressValue(params.cursor) or 0
    local regions, regionErr = getSortedMemoryRegions(params.refresh == true, true)
    if not regions then
        return nil, regionErr or "enumMemoryRegions failed"
    end

    local startIdx = params.region_index_hint
    if not startIdx or startIdx < 1 then
        startIdx = findFirstRegionIndexForCursor(regions, cursor)
    end

    for idx = startIdx, #regions do
        local region = regions[idx]
        local base = tonumber(region.BaseAddress or 0) or 0
        local regionSize = tonumber(region.RegionSize or 0) or 0
        local regionEnd = base + regionSize
        if regionSize > 0 and regionEnd > cursor and regionMatchesProtection(region, params.protection) then
            local startAddr = math.max(base, cursor)
            local available = regionEnd - startAddr
            if available > 0 then
                local actualSize = math.min(budget, available)
                local nextStart = startAddr + actualSize
                return {
                    start = startAddr,
                    size = actualSize,
                    explicit = false,
                    truncated = available > actualSize,
                    next_start = nextStart,
                    next_region_index = (nextStart >= regionEnd) and (idx + 1) or idx,
                    region_base = base,
                    region_size = regionSize,
                }
            end
        end
    end

    return nil, "No readable committed memory region found at or after the requested cursor"
end

-- Scan one or more auto-chosen windows under a single shared time budget.
-- Every scan used to stop after one 200k-address window and hand `next_start_address`
-- back to the caller, so covering a real process took dozens of round trips.
-- max_windows lets a single call walk forward until the limit, the window count,
-- or the time budget runs out - whichever comes first.
local function runPatternScan(params, stats, limit, timeBudgetMs)
    local maxWindows = math.floor(tonumber(params.max_windows) or 1)
    if maxWindows < 1 then maxWindows = 1 end
    if maxWindows > 64 then maxWindows = 64 end

    local results = {}
    local scannedTotal = 0
    local windowsScanned = 0
    local firstStart, nextStart = nil, nil
    local truncated = false
    local explicit = false
    local stoppedForGoodReason = false   -- reached the limit, or the caller's own window
    local startedAt = nil
    local cursorParams = params

    for _ = 1, maxWindows do
        local window, windowErr = chooseScanWindow(cursorParams)
        if not window then
            -- Ran out of regions: the scan really did reach the end of memory.
            if windowsScanned == 0 then return nil, windowErr end
            stoppedForGoodReason = true
            break
        end

        -- Start the scan budget clock after the initial region lookup so slow
        -- enumMemoryRegions() on huge x64 processes does not abort with 0 bytes scanned.
        if startedAt == nil then startedAt = getTickCount() end

        if firstStart == nil then firstStart = window.start end
        explicit = window.explicit
        nextStart = window.next_start

        local remainingBudget = timeBudgetMs - tickDiffMs(getTickCount(), startedAt)
        if remainingBudget <= 0 then
            truncated = true
            nextStart = window.start
            break
        end

        local found, scanned, windowTruncated =
            scanAobRange(window.start, window.size, stats, limit - #results, remainingBudget)

        for _, item in ipairs(found) do
            results[#results + 1] = item
        end

        scannedTotal = scannedTotal + scanned
        windowsScanned = windowsScanned + 1
        truncated = truncated or windowTruncated or window.truncated

        if #results >= limit or window.explicit or windowTruncated then
            stoppedForGoodReason = true
            break
        end
        if tickDiffMs(getTickCount(), startedAt) >= timeBudgetMs then
            truncated = true
            break
        end

        -- Continue from the end of this window on the next pass.
        cursorParams = {
            cursor = window.next_start,
            region_index_hint = window.next_region_index,
            protection = params.protection,
            max_scan = params.max_scan,
        }
    end

    -- Using up the window allowance is not the same as finishing: more memory may
    -- follow, so report it as truncated and let the caller continue from next_start.
    if not stoppedForGoodReason and windowsScanned >= maxWindows then
        truncated = true
    end

    return {
        results = results,
        scanned_bytes = scannedTotal,
        windows_scanned = windowsScanned,
        start_address = firstStart,
        next_start_address = nextStart,
        truncated = truncated,
        explicit = explicit,
    }
end

local function cmd_aob_scan(params)
    local pattern = params.pattern
    -- Write the default back into params: chooseScanWindow reads params.protection,
    -- so a local-only default meant an omitted protection scanned every readable
    -- region instead of executable ones.
    local protection = params.protection or "+X"
    params.protection = protection
    local limit = tonumber(params.limit) or 100
    local startAddr = params.start_address
    local scanSize = params.size or params.scan_size
    local timeBudgetMs = tonumber(params.time_budget_ms) or 1500
    local maxBoundedSize = MAX_SCAN_BUDGET

    if not pattern then return { success = false, error = "No pattern provided" } end

    local stats, parseErr = parseAobPattern(pattern)
    if not stats then return { success = false, error = parseErr } end

    if startAddr == "" then
        startAddr = nil
        params.start_address = nil
    elseif startAddr ~= nil then
        local resolved = parseAddressValue(startAddr)
        if not resolved then
            return { success = false, error = "Invalid start_address: " .. tostring(startAddr), pattern = pattern }
        end
        startAddr = resolved
        params.start_address = resolved
    end
    if scanSize == "" then scanSize = nil end
    if type(scanSize) == "string" then scanSize = tonumber(scanSize) end

    limit = math.min(math.max(limit, 1), 1000)
    timeBudgetMs = math.min(math.max(timeBudgetMs, 100), 10000)

    if scanSize then
        scanSize = math.min(scanSize, maxBoundedSize)
        params.size = scanSize
    end

    -- Enforce the broad-pattern guard. classifyUnsafeGlobalAob existed but was never
    -- called, so `allow_unsafe_global` on the Python side did nothing: a pattern like
    -- "?? ?? ?? ??" would happily match every byte of the process.
    local bounded = (startAddr ~= nil) and (scanSize ~= nil) and (scanSize > 0)
    if not bounded then
        local unsafe, unsafeReason = classifyUnsafeGlobalAob(stats)
        if unsafe and not params.allow_unsafe_global then
            return {
                success = false,
                error = "Refusing unbounded scan for a low-entropy pattern: " .. unsafeReason,
                pattern = pattern,
                fixed_bytes = stats.fixed,
                wildcard_bytes = stats.wildcards,
                hint = "Add fixed bytes, pass start_address+size to bound the scan, or set allow_unsafe_global=true",
            }
        end
    end

    local scan, scanErr = runPatternScan(params, stats, limit, timeBudgetMs)
    if not scan then
        return { success = false, error = scanErr, pattern = pattern }
    end

    return {
        success = true,
        count = #scan.results,
        pattern = pattern,
        addresses = scan.results,
        bounded = scan.explicit,
        auto_window = not scan.explicit,
        start_address = toHex(scan.start_address),
        scanned_bytes = scan.scanned_bytes,
        windows_scanned = scan.windows_scanned,
        max_scan_budget = MAX_SCAN_BUDGET,
        truncated = scan.truncated,
        next_start_address = toHex(scan.next_start_address),
    }
end
local function cmd_scan_all(params)
    local value = params.value
    local vtype = params.type or "dword"
    local varType

    if vtype == "byte" then varType = vtByte
    elseif vtype == "word" then varType = vtWord
    elseif vtype == "dword" then varType = vtDword
    elseif vtype == "qword" then varType = vtQword
    elseif vtype == "float" then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString
    else
        return { success = false, error = "Unknown scan type: " .. tostring(vtype) }
    end

    if value == nil then
        return { success = false, error = "No value provided" }
    end

    local window, windowErr = chooseScanWindow(params)
    if not window then
        return { success = false, error = windowErr }
    end

    -- Ensure old scans are released before creating a new one.
    cleanupScanObjects()

    local okCreate, ms = pcall(createMemScan)
    if not okCreate or not ms then
        return { success = false, error = "Failed to create MemScan: " .. tostring(ms) }
    end

    local scanOpt = soExactValue
    -- Use specific protection flags if provided (defaults to +W-C from Python).
    -- Keep every scan call inside one capped window; callers can continue with next_start_address.
    local protect = params.protection or "+W-C"
    local fl = nil
    local count = 0

    local okScan, scanErr = pcall(function()
        ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil, window.start, window.start + window.size - 1, protect, fsmNotAligned, "1", false, false, false, false)
        ms.waitTillDone()
        fl = createFoundList(ms)
        if not fl then error("createFoundList returned nil") end
        fl.initialize()
        count = fl.getCount()
    end)

    if not okScan then
        if fl then pcall(function() fl.destroy() end) end
        pcall(function() ms.destroy() end)
        return { success = false, error = "scan_all failed: " .. tostring(scanErr) }
    end

    serverState.scan_memscan = ms
    serverState.scan_foundlist = fl

    return {
        success = true,
        count = count,
        start_address = toHex(window.start),
        scanned_addresses = window.size,
        max_scan_budget = MAX_SCAN_BUDGET,
        auto_window = not window.explicit,
        truncated = window.truncated,
        next_start_address = toHex(window.next_start),
    }
end

local function cmd_get_scan_results(params)
    local max = math.min(math.max(math.floor(tonumber(params.max) or 100), 1), 10000)
    
    if not serverState.scan_foundlist then 
        return { success = false, error = "No scan results. Run scan_all first." } 
    end
    
    local fl = serverState.scan_foundlist
    local results = {}
    local count = math.min(fl.getCount(), max)
    
    for i = 0, count - 1 do
        -- IMPORTANT: Ensure address has 0x prefix for consistency with all other commands
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0x") and not addrStr:match("^0X") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, { 
            address = addrStr, 
            value = fl.getValue(i) 
        })
    end
    
    return { success = true, results = results, total = fl.getCount(), returned = count }
end

-- ============================================================================
-- COMMAND HANDLERS - NEXT SCAN & WRITE MEMORY (Added by MCP Enhancement)
-- ============================================================================

local function cmd_next_scan(params)
    local value = params.value
    local scanType = params.scan_type or "exact"

    if not serverState.scan_memscan then
        return { success = false, error = "No previous scan. Run scan_all first." }
    end

    local scanOpt
    local needsValue = false
    if scanType == "exact" then scanOpt = soExactValue; needsValue = true
    elseif scanType == "increased" then scanOpt = soIncreasedValue
    elseif scanType == "decreased" then scanOpt = soDecreasedValue
    elseif scanType == "changed" then scanOpt = soChanged
    elseif scanType == "unchanged" then scanOpt = soUnchanged
    elseif scanType == "bigger" then scanOpt = soBiggerThan; needsValue = true
    elseif scanType == "smaller" then scanOpt = soSmallerThan; needsValue = true
    else
        return { success = false, error = "Unknown scan_type: " .. tostring(scanType) }
    end

    if needsValue and value == nil then
        return { success = false, error = "scan_type '" .. scanType .. "' requires a value" }
    end

    local ms = serverState.scan_memscan
    local okScan, scanErr = pcall(function()
        ms.nextScan(scanOpt, rtRounded, needsValue and tostring(value) or nil, nil, false, false, false, false, false)
        ms.waitTillDone()
    end)
    if not okScan then
        return { success = false, error = "next_scan failed: " .. tostring(scanErr) }
    end

    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end

    local fl = nil
    local count = 0
    local okFl, flErr = pcall(function()
        fl = createFoundList(ms)
        if not fl then error("createFoundList returned nil") end
        fl.initialize()
        count = fl.getCount()
    end)
    if not okFl then
        if fl then pcall(function() fl.destroy() end) end
        return { success = false, error = "next_scan foundlist failed: " .. tostring(flErr) }
    end

    serverState.scan_foundlist = fl

    return { success = true, count = count }
end

local function cmd_write_integer(params)
    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if value == nil then return { success = false, error = "No value provided", address = toHex(addr) } end

    local ok, writeOk
    if vtype == "byte" then
        ok, writeOk = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, writeOk = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, writeOk = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, writeOk = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, writeOk = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, writeOk = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype) }
    end

    if not ok then
        return { success = false, error = "Write failed: " .. tostring(writeOk), address = toHex(addr) }
    end
    if writeOk == false then
        return { success = false, error = "Write failed at " .. toHex(addr), address = toHex(addr) }
    end

    return { success = true, address = toHex(addr), value = value, type = vtype }
end

local function cmd_write_memory(params)
    local addr = params.address
    local bytes = params.bytes

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if type(bytes) ~= "table" then return { success = false, error = "bytes must be an array" } end
    local count = #bytes
    if count < 1 or count > 65536 then
        return { success = false, error = "bytes length must be between 1 and 65536" }
    end
    for i = 1, count do
        local b = bytes[i]
        if type(b) ~= "number" or b < 0 or b > 255 or b % 1 ~= 0 then
            return { success = false, error = "Invalid byte at index " .. i .. ": expected integer 0..255" }
        end
    end

    local ok, writeResult = pcall(writeBytes, addr, bytes)
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(writeResult), address = toHex(addr), bytes_written = 0, bytes_requested = count }
    end
    if writeResult == false or writeResult == nil then
        return { success = false, error = "Write failed at " .. toHex(addr), address = toHex(addr), bytes_written = 0, bytes_requested = count }
    end
    if type(writeResult) == "number" then
        if writeResult < count then
            return {
                success = false,
                error = string.format("Partial or failed write at %s: wrote %d of %d bytes", toHex(addr), writeResult, count),
                address = toHex(addr),
                bytes_written = writeResult,
                bytes_requested = count
            }
        end
    elseif writeResult ~= true then
        return { success = false, error = "Write returned unexpected status: " .. tostring(writeResult), address = toHex(addr), bytes_written = 0, bytes_requested = count }
    end

    return { success = true, address = toHex(addr), bytes_written = count }
end

local function cmd_write_string(params)
    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if type(str) ~= "string" then
        if str == nil then return { success = false, error = "No string provided" } end
        str = tostring(str)
    end

    local ok, writeOk = pcall(writeString, addr, str, wide)
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(writeOk), address = toHex(addr) }
    end
    if writeOk == false then
        return { success = false, error = "Write failed at " .. toHex(addr), address = toHex(addr) }
    end

    return { success = true, address = toHex(addr), length = #str, wide = wide }
end


-- ============================================================================
-- COMMAND HANDLERS - DISASSEMBLY & ANALYSIS
-- ============================================================================

local function cmd_disassemble(params)
    local addr = params.address
    local count = math.min(math.max(math.floor(tonumber(params.count) or 20), 1), 1000)
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- Pre-read instruction bytes in one bulk call (max 15 bytes per x86/x64 instruction)
    -- instead of calling readBytes() separately for every instruction.
    local okBulk, bulkBytes = pcall(readBytes, addr, count * 15, true)
    if not okBulk then bulkBytes = nil end

    local instructions = {}
    local currentAddr = addr
    
    for i = 1, count do
        local ok, disasm = pcall(disassemble, currentAddr)
        if not ok or not disasm then break end
        
        local instSize = getInstructionSize(currentAddr) or 1
        local relOff = currentAddr - addr
        local bytesHex = {}
        if bulkBytes and (relOff + instSize) <= #bulkBytes then
            for bIdx = 1, instSize do
                local b = bulkBytes[relOff + bIdx]
                bytesHex[bIdx] = HEX_BYTE[b] or string.format("%02X", b)
            end
        else
            local instBytes = readBytes(currentAddr, instSize, true) or {}
            for bIdx = 1, #instBytes do
                local b = instBytes[bIdx]
                bytesHex[bIdx] = HEX_BYTE[b] or string.format("%02X", b)
            end
        end
        
        instructions[#instructions + 1] = {
            address = toHex(currentAddr),
            offset = relOff,
            size = instSize,
            bytes = table.concat(bytesHex, " "),
            instruction = disasm
        }
        
        currentAddr = currentAddr + instSize
    end
    
    return { success = true, start_address = toHex(addr), count = #instructions, instructions = instructions }
end

local function cmd_get_instruction_info(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local ok, disasm = pcall(disassemble, addr)
    if not ok or not disasm then
        return { success = false, error = "Failed to disassemble at " .. toHex(addr) }
    end
    local size = getInstructionSize(addr)
    local bytes = readBytes(addr, size or 1, true) or {}
    local bytesHex = {}
    for _, b in ipairs(bytes) do
        bytesHex[#bytesHex + 1] = HEX_BYTE[b] or string.format("%02X", b)
    end
    
    local prevAddr = getPreviousOpcode(addr)
    
    return {
        success = true,
        address = toHex(addr),
        instruction = disasm,
        size = size,
        bytes = table.concat(bytesHex, " "),
        previous_instruction = prevAddr and toHex(prevAddr) or nil
    }
end

-- Walk backwards from `addr` looking for a function prologue.
-- Reads the search window in 4 KB blocks instead of issuing four single-byte
-- readBytes calls per candidate offset (the old loop cost up to ~16k
-- cross-process reads per request, which is what made these tools feel hung).
local function findFunctionStart(addr, maxSearch)
    maxSearch = math.min(math.max(math.floor(tonumber(maxSearch) or 4096), 0), 1048576)

    local is64 = targetIs64Bit()
    local chunkSize = 0x1000
    local top = addr                 -- highest candidate address, inclusive
    local remaining = maxSearch + 1  -- number of candidate addresses
    local readAnything = false

    while remaining > 0 do
        local thisCount = math.min(chunkSize, remaining)
        local chunkStart = top - thisCount + 1
        if chunkStart < 0 then break end

        -- +3 tail bytes so a pattern starting at the top of the chunk still matches.
        local okBlock, block = pcall(readBytes, chunkStart, thisCount + 3, true)
        if not okBlock or not block then
            -- Hit an unreadable page: a function body cannot span it, so stop here.
            break
        end
        readAnything = true

        for i = thisCount, 1, -1 do
            local b1, b2, b3, b4 = block[i], block[i + 1], block[i + 2], block[i + 3]

            -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
            if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
                return chunkStart + i - 1, "x86_standard"
            end
            -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
            if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
                return chunkStart + i - 1, "x64_standard"
            end
            -- 64-bit leaf: sub rsp, imm8 (48 83 EC xx)
            if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
                return chunkStart + i - 1, "x64_leaf"
            end
        end

        remaining = remaining - thisCount
        top = chunkStart - 1
    end

    if not readAnything then
        return nil, nil, "Could not read memory around " .. toHex(addr)
    end
    return nil, nil, nil
end

-- Find the terminating RET by walking instructions, not raw bytes: a bare byte
-- scan stops on the first 0xC3 that happens to be part of an operand.
local function findFunctionEnd(funcStart, maxSearch)
    maxSearch = math.min(math.max(math.floor(tonumber(maxSearch) or 4096), 0), 1048576)
    if maxSearch <= 0 then return nil end
    local okBlock, block = pcall(readBytes, funcStart, maxSearch, true)
    if not okBlock or not block then return nil end

    local offset = 0
    while offset < #block do
        local b = block[offset + 1]
        if b == 0xC3 or b == 0xC2 then
            return funcStart + offset
        end
        local size = getInstructionSize(funcStart + offset)
        if not size or size == 0 then return nil end
        offset = offset + size
    end
    return nil
end

local function cmd_find_function_boundaries(params)
    local addr = params.address
    local maxSearch = params.max_search or 4096

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()
    local funcStart, prologueType, startErr = findFunctionStart(addr, maxSearch)

    if startErr then
        return { success = false, error = startErr, query_address = toHex(addr) }
    end

    local funcEnd = funcStart and findFunctionEnd(funcStart, maxSearch) or nil
    local found = funcStart ~= nil

    return {
        success = true,
        found = found,
        query_address = toHex(addr),
        function_start = funcStart and toHex(funcStart) or nil,
        function_end = funcEnd and toHex(funcEnd) or nil,
        function_size = (funcStart and funcEnd) and (funcEnd - funcStart + 1) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

local function cmd_analyze_function(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()
    local maxInstructions = math.min(math.max(tonumber(params.max_instructions) or 2000, 1), 20000)
    local bodyLimit = math.min(math.max(tonumber(params.max_bytes) or 0x2000, 0x100), 0x10000)

    -- Find function start using architecture-aware prologue detection
    local funcStart, prologueType, startErr = findFunctionStart(addr, params.max_search or 4096)

    if not funcStart then
        return {
            success = false,
            error = startErr or "Could not find function start",
            arch = is64 and "x64" or "x86",
            query_address = toHex(addr)
        }
    end

    -- Read the whole body once; the old loop did a separate 1-byte cross-process
    -- read for every instruction (and another for every 0xFF ModR/M byte).
    local okBody, body = pcall(readBytes, funcStart, bodyLimit, true)
    if not okBody or not body then
        return {
            success = false,
            error = "Could not read function body at " .. toHex(funcStart),
            arch = is64 and "x64" or "x86",
            function_start = toHex(funcStart)
        }
    end

    local function readS32LE(bytes, index)
        if not bytes[index] or not bytes[index + 3] then return nil end
        local v = bytes[index] + bytes[index + 1] * 0x100 + bytes[index + 2] * 0x10000 + bytes[index + 3] * 0x1000000
        if v >= 0x80000000 then v = v - 0x100000000 end
        return v
    end

    -- Analyze calls within function
    local calls = {}
    local funcEnd = nil
    local offset = 0
    local instructionCount = 0
    local truncated = false

    while offset < #body do
        if instructionCount >= maxInstructions then
            truncated = true
            break
        end
        instructionCount = instructionCount + 1

        local currentAddr = funcStart + offset
        local instSize = getInstructionSize(currentAddr)
        if not instSize or instSize == 0 then break end

        local b1 = body[offset + 1]
        if b1 == 0xC3 or b1 == 0xC2 then
            funcEnd = currentAddr
            break
        end

        -- E8 rel32 = relative CALL (most common)
        if b1 == 0xE8 then
            local relOffset = readS32LE(body, offset + 2)
            if relOffset then
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    target = toHex(currentAddr + 5 + relOffset),
                    type = "relative"
                })
            end
        end

        -- FF /2 = indirect CALL (CALL r/m32 or CALL r/m64)
        if b1 == 0xFF then
            local b2 = body[offset + 2]
            if b2 and (b2 >= 0x10 and b2 <= 0x1F) then  -- ModR/M for /2
                local okDis, disasm = pcall(disassemble, currentAddr)
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    instruction = (okDis and disasm) or "???",
                    type = "indirect"
                })
            end
        end

        offset = offset + instSize
    end

    return {
        success = true,
        function_start = toHex(funcStart),
        function_end = funcEnd and toHex(funcEnd) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        instructions_analyzed = instructionCount,
        bytes_analyzed = offset,
        truncated = truncated or (funcEnd == nil),
        call_count = #calls,
        calls = calls
    }
end

-- ============================================================================
-- COMMAND HANDLERS - REFERENCE FINDING
-- ============================================================================

local function cmd_find_references(params)
    local targetAddr = params.address
    local limit = math.min(math.max(math.floor(tonumber(params.limit) or 50), 1), 1000)
    local timeBudgetMs = math.min(math.max(math.floor(tonumber(params.time_budget_ms) or 1500), 100), 10000)

    if type(targetAddr) == "string" then targetAddr = getAddressSafe(targetAddr) end
    if not targetAddr then return { success = false, error = "Invalid address" } end
    if math.type and math.type(targetAddr) ~= "integer" then
        targetAddr = math.floor(targetAddr)
    end

    local is64 = targetIs64Bit()
    local pattern

    -- Convert address to AOB pattern (little-endian)
    if is64 and (targetAddr > 0xFFFFFFFF or targetAddr < 0) then
        -- 64-bit address: 8 bytes little-endian (handles high-bit negative Lua integers)
        local bytes = {}
        for i = 1, 8 do
            local b = (targetAddr >> ((i - 1) * 8)) & 0xFF
            bytes[i] = HEX_BYTE[b] or string.format("%02X", b)
        end
        pattern = table.concat(bytes, " ")
    else
        -- 32-bit address: 4 bytes little-endian
        local b1 = targetAddr & 0xFF
        local b2 = (targetAddr >> 8) & 0xFF
        local b3 = (targetAddr >> 16) & 0xFF
        local b4 = (targetAddr >> 24) & 0xFF
        pattern = (HEX_BYTE[b1] or string.format("%02X", b1)) .. " " ..
                  (HEX_BYTE[b2] or string.format("%02X", b2)) .. " " ..
                  (HEX_BYTE[b3] or string.format("%02X", b3)) .. " " ..
                  (HEX_BYTE[b4] or string.format("%02X", b4))
    end

    params.protection = params.protection or "+X"
    local stats, parseErr = parseAobPattern(pattern)
    if not stats then return { success = false, error = parseErr } end

    local scan, scanErr = runPatternScan(params, stats, limit, timeBudgetMs)
    if not scan then
        return { success = false, error = scanErr, target = toHex(targetAddr), references = {} }
    end

    local refs = {}
    for _, result in ipairs(scan.results) do
        local refAddr = result.value
        local okDis, disasm = pcall(disassemble, refAddr)
        table.insert(refs, {
            address = toHex(refAddr),
            instruction = (okDis and disasm) or "???"
        })
    end

    return {
        success = true,
        target = toHex(targetAddr),
        count = #refs,
        references = refs,
        arch = is64 and "x64" or "x86",
        start_address = toHex(scan.start_address),
        scanned_bytes = scan.scanned_bytes,
        windows_scanned = scan.windows_scanned,
        max_scan_budget = MAX_SCAN_BUDGET,
        auto_window = not scan.explicit,
        truncated = scan.truncated,
        next_start_address = toHex(scan.next_start_address),
    }
end

local function cmd_find_call_references(params)
    local funcAddr = params.address or params.function_address
    local limit = math.min(math.max(tonumber(params.limit) or 20, 1), 50)
    local startAddr = params.start_address
    local scanSize = params.size or params.scan_size
    local timeBudgetMs = math.min(math.max(tonumber(params.time_budget_ms) or 1500, 100), 10000)
    local maxWindows = math.min(math.max(math.floor(tonumber(params.max_windows) or 1), 1), 64)

    if type(funcAddr) == "string" then funcAddr = getAddressSafe(funcAddr) end
    if not funcAddr then return { success = false, error = "Invalid function address" } end

    if startAddr == "" then
        startAddr = nil
        params.start_address = nil
    elseif startAddr ~= nil then
        local resolved = parseAddressValue(startAddr)
        if not resolved then
            return { success = false, error = "Invalid start_address: " .. tostring(startAddr), function_address = toHex(funcAddr), callers = {} }
        end
        startAddr = resolved
        params.start_address = resolved
    end
    if type(scanSize) == "string" then
        scanSize = tonumber(scanSize)
        params.size = scanSize
    end

    params.protection = params.protection or "+X"

    local callers = {}
    local scannedTotal = 0
    local windowsScanned = 0
    local firstStart, nextStart = nil, nil
    local truncated = false
    local explicit = false
    local stoppedForGoodReason = false
    local chunkSize = 0x20000
    -- getTickCount is wall clock. os.clock() measures CPU time, so the budget never
    -- expired while the scan sat blocked on cross-process reads - the opposite of
    -- what a time budget is for, and inconsistent with every other scan here.
    local startedAt = nil
    local cursorParams = params

    for _ = 1, maxWindows do
        local window, windowErr = chooseScanWindow(cursorParams)
        if not window then
            if windowsScanned == 0 then
                return { success = false, error = windowErr, function_address = toHex(funcAddr), callers = {} }
            end
            stoppedForGoodReason = true
            break
        end

        if startedAt == nil then startedAt = getTickCount() end

        if firstStart == nil then firstStart = window.start end
        explicit = window.explicit
        nextStart = window.next_start

        if tickDiffMs(getTickCount(), startedAt) >= timeBudgetMs then
            truncated = true
            nextStart = window.start
            break
        end

        local winStart = window.start
        local winSize = window.size
        local scanned = 0
        local windowTruncated = false
        local resumeAddr = nil

        while scanned < winSize do
            if tickDiffMs(getTickCount(), startedAt) > timeBudgetMs then
                resumeAddr = winStart + scanned
                windowTruncated = true
                break
            end

            local remaining = winSize - scanned
            if remaining < 5 then break end
            local thisSize = math.min(chunkSize, remaining)
            local chunkAddr = winStart + scanned
            local ok, bytes = pcall(readBytes, chunkAddr, thisSize, true)

            if ok and bytes and #bytes >= 5 then
                for i = 1, #bytes - 4 do
                    if bytes[i] == 0xE8 then
                        local relOffset = bytes[i + 1] + bytes[i + 2] * 0x100 + bytes[i + 3] * 0x10000 + bytes[i + 4] * 0x1000000
                        if relOffset >= 0x80000000 then relOffset = relOffset - 0x100000000 end
                        local callAddr = chunkAddr + i - 1
                        local target = callAddr + 5 + relOffset
                        if target == funcAddr then
                            local okDis, disasm = pcall(disassemble, callAddr)
                            callers[#callers + 1] = {
                                caller_address = toHex(callAddr),
                                instruction = (okDis and disasm) or "???"
                            }
                            if #callers >= limit then
                                -- Resume at the very next unexamined candidate byte
                                -- (preserving overlap for 5-byte relative calls).
                                resumeAddr = callAddr + 1
                                scanned = math.min(winSize, resumeAddr - winStart)
                                windowTruncated = true
                                break
                            end
                        end
                    end
                end
            end

            if windowTruncated then break end
            if remaining <= chunkSize then
                scanned = winSize
                break
            end
            scanned = scanned + (thisSize - 4)
            if processMessages then pcall(processMessages) end
        end

        if resumeAddr ~= nil then
            nextStart = resumeAddr
        end

        scannedTotal = scannedTotal + scanned
        windowsScanned = windowsScanned + 1
        truncated = truncated or windowTruncated or window.truncated

        if #callers >= limit or window.explicit or windowTruncated then
            stoppedForGoodReason = true
            break
        end
        if tickDiffMs(getTickCount(), startedAt) >= timeBudgetMs then
            truncated = true
            break
        end

        cursorParams = {
            cursor = window.next_start,
            region_index_hint = window.next_region_index,
            protection = params.protection,
            max_scan = params.max_scan,
        }
    end

    if not stoppedForGoodReason and windowsScanned >= maxWindows then
        truncated = true
    end

    return {
        success = true,
        function_address = toHex(funcAddr),
        start_address = toHex(firstStart),
        scanned_bytes = scannedTotal,
        windows_scanned = windowsScanned,
        max_scan_budget = MAX_SCAN_BUDGET,
        auto_window = not explicit,
        truncated = truncated,
        next_start_address = toHex(nextStart),
        count = #callers,
        callers = callers
    }
end

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

local BREAKPOINT_REGISTER_NAMES = {
    RAX = true, RBX = true, RCX = true, RDX = true,
    RSI = true, RDI = true, RBP = true, RSP = true, RIP = true,
    R8 = true, R9 = true, R10 = true, R11 = true,
    R12 = true, R13 = true, R14 = true, R15 = true,
    EAX = true, EBX = true, ECX = true, EDX = true,
    ESI = true, EDI = true, EBP = true, ESP = true, EIP = true
}

local BREAKPOINT_CONDITION_OPERATORS = {
    eq = true, ne = true, lt = true, le = true,
    gt = true, ge = true, ["in"] = true, mask_eq = true
}

local function parseBreakpointInteger(value)
    if type(value) == "number" then return value end
    if type(value) ~= "string" then return nil end
    local text = value:match("^%s*(.-)%s*$")
    local hex = text:match("^0[xX](%x+)$")
    if hex then return tonumber(hex, 16) end
    return tonumber(text)
end

local function normalizeBreakpointRegister(value)
    if type(value) ~= "string" then return nil end
    local name = value:upper()
    if BREAKPOINT_REGISTER_NAMES[name] then return name end
    return nil
end

-- Conditions are ANDed. Supported forms:
--   {kind="register", register="R8", operator="in", values={42, 123, 387}}
--   {kind="memory", base_register="RDX", offset=0, size=1, operator="eq", value=1}
-- A direct `address` may replace `base_register` for memory conditions.
local function normalizeBreakpointConditions(rawConditions)
    if rawConditions == nil then return {} end
    if type(rawConditions) ~= "table" then
        return nil, "conditions must be an array"
    end

    if rawConditions.kind ~= nil then
        rawConditions = { rawConditions }
    elseif next(rawConditions) ~= nil and rawConditions[1] == nil then
        return nil, "conditions must be an array of condition objects"
    end

    local conditions = {}
    for index, raw in ipairs(rawConditions) do
        if type(raw) ~= "table" then
            return nil, "condition #" .. index .. " must be an object"
        end

        local condition = {}
        condition.kind = tostring(raw.kind or "register"):lower()
        condition.operator = tostring(raw.operator or "eq"):lower()
        if not BREAKPOINT_CONDITION_OPERATORS[condition.operator] then
            return nil, "condition #" .. index .. " has unsupported operator: " .. condition.operator
        end

        if condition.kind == "register" then
            condition.register = normalizeBreakpointRegister(raw.register)
            if not condition.register then
                return nil, "condition #" .. index .. " has an invalid register"
            end
        elseif condition.kind == "memory" then
            condition.base_register = normalizeBreakpointRegister(raw.base_register or raw.register)
            condition.address = parseAddressValue(raw.address)
            if not condition.base_register and not condition.address then
                return nil, "condition #" .. index .. " needs base_register or address"
            end

            condition.offset = parseBreakpointInteger(raw.offset) or 0
            condition.size = math.floor(parseBreakpointInteger(raw.size) or 1)
            if condition.size ~= 1 and condition.size ~= 2 and condition.size ~= 4 and condition.size ~= 8 then
                return nil, "condition #" .. index .. " size must be 1, 2, 4, or 8"
            end
        else
            return nil, "condition #" .. index .. " has unsupported kind: " .. condition.kind
        end

        if condition.operator == "in" then
            if type(raw.values) ~= "table" or #raw.values == 0 then
                return nil, "condition #" .. index .. " operator 'in' needs values"
            end
            condition.values = {}
            for valueIndex, rawValue in ipairs(raw.values) do
                local value = parseBreakpointInteger(rawValue)
                if value == nil then
                    return nil, "condition #" .. index .. " has invalid values[" .. valueIndex .. "]"
                end
                table.insert(condition.values, value)
            end
        else
            condition.value = parseBreakpointInteger(raw.value ~= nil and raw.value or raw.equals)
            if condition.value == nil then
                return nil, "condition #" .. index .. " needs a numeric value"
            end
        end

        if condition.operator == "mask_eq" then
            condition.mask = parseBreakpointInteger(raw.mask)
            if condition.mask == nil then
                return nil, "condition #" .. index .. " operator 'mask_eq' needs mask"
            end
        end

        table.insert(conditions, condition)
    end

    return conditions
end

local function readBreakpointRegister(registerName)
    local value = _G[registerName]
    if value == nil then
        return nil, "register " .. tostring(registerName) .. " is unavailable"
    end
    value = tonumber(value)
    if value == nil then
        return nil, "register " .. tostring(registerName) .. " is not numeric"
    end
    return value
end

local function readBreakpointUnsigned(address, size)
    local ok, bytes = pcall(readBytes, address, size, true)
    if not ok or type(bytes) ~= "table" or #bytes < size then
        return nil, "failed to read " .. size .. " byte(s) at " .. toHex(address)
    end

    local value = 0
    for index = size, 1, -1 do
        value = value * 0x100 + (tonumber(bytes[index]) or 0)
    end
    return value
end

local function compareBreakpointValue(actual, condition)
    local operator = condition.operator
    if operator == "eq" then return actual == condition.value end
    if operator == "ne" then return actual ~= condition.value end
    if operator == "lt" then return actual < condition.value end
    if operator == "le" then return actual <= condition.value end
    if operator == "gt" then return actual > condition.value end
    if operator == "ge" then return actual >= condition.value end
    if operator == "mask_eq" then
        return (actual & condition.mask) == (condition.value & condition.mask)
    end
    if operator == "in" then
        for _, value in ipairs(condition.values) do
            if actual == value then return true end
        end
        return false
    end
    return false
end

local function evaluateBreakpointConditions(conditions)
    local observations = {}
    for index, condition in ipairs(conditions) do
        local actual, readErr
        if condition.kind == "register" then
            actual, readErr = readBreakpointRegister(condition.register)
        else
            local address = condition.address
            if condition.base_register then
                local base
                base, readErr = readBreakpointRegister(condition.base_register)
                if base then address = base + condition.offset end
            else
                address = address + condition.offset
            end
            if not readErr then
                actual, readErr = readBreakpointUnsigned(address, condition.size)
            end
        end

        if readErr then return false, readErr, observations end
        table.insert(observations, {
            index = index,
            kind = condition.kind,
            actual = toHex(actual)
        })
        if not compareBreakpointValue(actual, condition) then
            return false, nil, observations
        end
    end
    return true, nil, observations
end

local function clampBreakpointInteger(value, defaultValue, maximum)
    local result = math.floor(tonumber(value) or defaultValue)
    if result < 0 then result = 0 end
    if maximum and result > maximum then result = maximum end
    return result
end

local function buildBreakpointOptions(params)
    local conditions, conditionErr = normalizeBreakpointConditions(params.conditions)
    if not conditions then return nil, conditionErr end

    local oneShot = params.one_shot ~= false
    local defaultMaxHits = oneShot and 1 or 0
    local options = {
        capture_registers = params.capture_registers ~= false,
        capture_stack = params.capture_stack == true,
        stack_depth = clampBreakpointInteger(params.stack_depth, 16, 64),
        one_shot = oneShot,
        max_hits = clampBreakpointInteger(params.max_hits, defaultMaxHits, MAX_BP_HITS),
        max_triggers = clampBreakpointInteger(params.max_triggers, 256, 1000000),
        conditions = conditions
    }
    if options.stack_depth < 1 then options.stack_depth = 1 end
    if options.one_shot then options.max_hits = 1 end
    return options
end

local function continueDebuggerSafely()
    local ok, err = pcall(debug_continueFromBreakpoint, co_run)
    if ok then return true end
    return false, tostring(err)
end

-- Debugger callbacks always resume the target, even if condition evaluation or
-- capture fails. Expensive register/stack capture only runs after all conditions
-- match, keeping filtered hot-path events as small as possible.
local function runBreakpointCallback(bpId, expectedAddress, expectedGeneration, buildHit)
    local retireReason = nil
    local okBody, bodyErr = pcall(function()
        local bp = serverState.breakpoints[bpId]
        if not bp or bp.address ~= expectedAddress or bp.generation ~= expectedGeneration then
            return
        end

        bp.trigger_count = (bp.trigger_count or 0) + 1
        local matched, conditionErr, observations = evaluateBreakpointConditions(bp.conditions or {})
        if conditionErr then
            bp.callback_errors = (bp.callback_errors or 0) + 1
            recordBreakpointHit(bpId, {
                id = bpId,
                address = toHex(bp.address),
                timestamp = os.time(),
                breakpoint_type = "condition_error",
                error = conditionErr,
                trigger_count = bp.trigger_count
            })
            retireReason = "condition_error"
            return
        end

        if matched then
            bp.matched_count = (bp.matched_count or 0) + 1
            local hit = buildHit(bp, observations)
            hit.trigger_count = bp.trigger_count
            hit.matched_count = bp.matched_count
            hit.condition_observations = observations
            recordBreakpointHit(bpId, hit)

            if bp.one_shot or (bp.max_hits > 0 and bp.matched_count >= bp.max_hits) then
                retireReason = bp.one_shot and "one_shot_complete" or "max_hits_reached"
            end
        end

        if not retireReason and bp.max_triggers > 0 and bp.trigger_count >= bp.max_triggers then
            retireReason = "max_triggers_reached"
        end
    end)

    if not okBody then
        local bp = serverState.breakpoints[bpId]
        if bp then
            bp.callback_errors = (bp.callback_errors or 0) + 1
            recordBreakpointHit(bpId, {
                id = bpId,
                address = toHex(bp.address),
                timestamp = os.time(),
                breakpoint_type = "callback_error",
                error = tostring(bodyErr),
                trigger_count = bp.trigger_count or 0
            })
            retireReason = "callback_error"
        end
    end

    if retireReason then
        local retired, retireErr = retireTrackedBreakpointById(bpId, retireReason)
        if not retired then
            local bp = serverState.breakpoints[bpId]
            if bp then
                bp.retire_error = retireErr or "auto-retirement failed"
                bp.retirement_pending = true
            end
            -- Do not resume into another hit when the bounded breakpoint could
            -- not be removed. Returning 0 hands the paused state back to CE.
            return 0
        end
    end

    local continued, continueErr = continueDebuggerSafely()
    if not continued then
        local bp = serverState.breakpoints[bpId] or serverState.breakpoint_results[bpId]
        if bp then bp.continue_error = continueErr end
        -- Returning 0 lets CE retain control and show the paused debugger state.
        return 0
    end
    return 1
end

local function getDebuggerState()
    if type(debug_isDebugging) ~= "function" then
        return nil, "debug_isDebugging is unavailable"
    end
    local ok, started = pcall(debug_isDebugging)
    if not ok or type(started) ~= "boolean" then
        return nil, "Cannot query debugger state: " .. tostring(started)
    end
    return started
end

local function prepareBreakpointInstallation(addr, bpId)
    local pid, contextErr = ensureBreakpointProcessContext()
    if not pid then return nil, contextErr end
    if pid <= 0 then return nil, "No process attached" end
    -- debug_setBreakpoint calls StartDebuggerIfNeeded internally. Starting a
    -- debugger here can wait for attachment/UI while the pipe worker is waiting
    -- for this main-thread dispatch. pcall cannot time out that native wait.
    -- Check before removing/replacing anything or reserving a hardware slot.
    local started, debuggerErr = getDebuggerState()
    if started ~= true then
        return nil, debuggerErr or "Debugger is not started. Start debugging in CE first (debugProcess() in CE's Lua console), finish attachment, then retry. MCP does not auto-start the debugger."
    end
    local _, addressFailures = clearTrackedBreakpointsByAddress(addr, true)
    if #addressFailures > 0 then
        return nil, "Failed to remove existing breakpoint at address: " .. tostring(addressFailures[1].error)
    end

    if serverState.breakpoints[bpId] then
        local removed, removeErr = clearTrackedBreakpointById(bpId, true)
        if not removed then
            return nil, "Failed to replace breakpoint id '" .. bpId .. "': " .. tostring(removeErr)
        end
    elseif serverState.breakpoint_results[bpId] or serverState.breakpoint_hits[bpId] then
        clearTrackedBreakpointById(bpId, false)
    end

    local alreadyInstalled, listErr = isCeBreakpointInstalled(addr)
    if alreadyInstalled == nil then
        return nil, "Cannot verify CE breakpoint list: " .. tostring(listErr)
    end
    if alreadyInstalled then
        return nil, "An unmanaged CE breakpoint already exists at " .. toHex(addr)
    end
    return pid
end

local function verifyBreakpointInstallation(bpId, addr, callOk, callResult)
    -- A callback can complete a one-shot before debug_setBreakpoint returns.
    if not serverState.breakpoints[bpId] and serverState.breakpoint_results[bpId] then
        return true
    end

    local installed, verifyErr = isCeBreakpointInstalled(addr)
    if installed == true then
        if not callOk or callResult == false then
            return true, "CE breakpoint list confirms installation despite API return: " .. tostring(callResult)
        end
        return true
    end

    if installed == false then
        clearTrackedBreakpointById(bpId, false)
        local callError = not callOk and tostring(callResult) or nil
        return false, callError or "CE breakpoint list does not contain " .. toHex(addr), false
    end

    local bp = serverState.breakpoints[bpId]
    if bp then bp.install_verification_error = verifyErr end
    -- Keep the slot/state reserved because the side effect is uncertain.
    return false, "Could not verify breakpoint installation: " .. tostring(verifyErr), true
end

local function cmd_set_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    bpId = bpId or tostring(addr)
    local options, optionErr = buildBreakpointOptions(params)
    if not options then return { success = false, error = optionErr } end

    local processId, prepareErr = prepareBreakpointInstallation(addr, bpId)
    if not processId then return { success = false, error = prepareErr } end
    
    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end
    
    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end
    
    serverState.breakpoint_hits[bpId] = {}
    serverState.breakpoint_results[bpId] = nil
    serverState.breakpoint_generation = serverState.breakpoint_generation + 1
    local generation = serverState.breakpoint_generation

    -- Register state before calling CE: on a very hot address the callback may
    -- run immediately after installation, before debug_setBreakpoint returns.
    local bp = {
        address = addr,
        slot = slot,
        type = "execute",
        active = true,
        process_id = processId,
        generation = generation,
        created_at = os.time(),
        trigger_count = 0,
        matched_count = 0,
        callback_errors = 0,
        capture_registers = options.capture_registers,
        capture_stack = options.capture_stack,
        stack_depth = options.stack_depth,
        one_shot = options.one_shot,
        max_hits = options.max_hits,
        max_triggers = options.max_triggers,
        conditions = options.conditions
    }
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = bp

    -- Use bpmDebugRegister so target instruction bytes are not modified.
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    local okSet, setResult = pcall(debug_setBreakpoint, addr, 1, bptExecute, bpmDebugRegister, function()
        return runBreakpointCallback(bpId, addr, generation, function(activeBp, observations)
            local hitData = {
                id = bpId,
                address = toHex(addr),
                timestamp = os.time(),
                breakpoint_type = "hardware_execute"
            }

            if activeBp.capture_registers then
                hitData.registers = captureRegisters()
            end

            if activeBp.capture_stack then
                hitData.stack = captureStack(activeBp.stack_depth)
            end

            return hitData
        end)
    end)

    local installed, installErr, stateRetained = verifyBreakpointInstallation(bpId, addr, okSet, setResult)
    if not installed then
        return {
            success = false,
            address = toHex(addr),
            error = installErr,
            state_retained = stateRetained == true
        }
    end

    local active = serverState.breakpoints[bpId] ~= nil
    local result = serverState.breakpoint_results[bpId]
    return {
        success = true,
        id = bpId,
        address = toHex(addr),
        slot = active and slot or nil,
        active = active,
        method = "hardware_debug_register",
        one_shot = options.one_shot,
        max_hits = options.max_hits,
        max_triggers = options.max_triggers,
        condition_count = #options.conditions,
        retired_reason = result and result.retired_reason or nil,
        install_warning = installErr,
        max_buffered_hits = MAX_BP_HITS
    }
end

local function cmd_set_data_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local accessType = tostring(params.access_type or "w"):lower()  -- r, w, rw
    local size = math.floor(tonumber(params.size) or 4)
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if accessType ~= "r" and accessType ~= "w" and accessType ~= "rw" then
        return { success = false, error = "access_type must be 'r', 'w', or 'rw'" }
    end
    if size ~= 1 and size ~= 2 and size ~= 4 and size ~= 8 then
        return { success = false, error = "Hardware data breakpoint size must be 1, 2, 4, or 8" }
    end
    if size == 8 and not targetIs64Bit() then
        return { success = false, error = "8-byte hardware data breakpoints require a 64-bit target" }
    end
    if addr % size ~= 0 then
        return { success = false, error = "Hardware data breakpoint address must be naturally aligned to size" }
    end
    
    bpId = bpId or tostring(addr)
    local options, optionErr = buildBreakpointOptions(params)
    if not options then return { success = false, error = optionErr } end

    local processId, prepareErr = prepareBreakpointInstallation(addr, bpId)
    if not processId then return { success = false, error = prepareErr } end
    
    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end
    
    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end
    
    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end
    
    serverState.breakpoint_hits[bpId] = {}
    serverState.breakpoint_results[bpId] = nil
    serverState.breakpoint_generation = serverState.breakpoint_generation + 1
    local generation = serverState.breakpoint_generation

    local bp = {
        address = addr,
        slot = slot,
        type = "data",
        access_type = accessType,
        watch_size = size,
        active = true,
        process_id = processId,
        generation = generation,
        created_at = os.time(),
        trigger_count = 0,
        matched_count = 0,
        callback_errors = 0,
        capture_registers = options.capture_registers,
        capture_stack = options.capture_stack,
        stack_depth = options.stack_depth,
        one_shot = options.one_shot,
        max_hits = options.max_hits,
        max_triggers = options.max_triggers,
        conditions = options.conditions
    }
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = bp

    local okSet, setResult = pcall(debug_setBreakpoint, addr, size, bpType, bpmDebugRegister, function()
        return runBreakpointCallback(bpId, addr, generation, function(activeBp, observations)
            local arch = getArchInfo()
            local instPtr = arch.instPtr
            local instruction = "???"
            if instPtr then
                pcall(function() instruction = disassemble(instPtr) end)
            end
            local value, valueErr = readBreakpointUnsigned(addr, size)
            local hitData = {
                id = bpId,
                type = "data_" .. accessType,
                address = toHex(addr),
                timestamp = os.time(),
                breakpoint_type = "hardware_data",
                value = value and toHex(value) or nil,
                value_error = valueErr,
                instruction = instruction,
                arch = arch.is64bit and "x64" or "x86"
            }
            if activeBp.capture_registers then
                hitData.registers = captureRegisters()
            end
            if activeBp.capture_stack then
                hitData.stack = captureStack(activeBp.stack_depth)
            end
            return hitData
        end)
    end)

    local installed, installErr, stateRetained = verifyBreakpointInstallation(bpId, addr, okSet, setResult)
    if not installed then
        return {
            success = false,
            address = toHex(addr),
            error = installErr,
            state_retained = stateRetained == true
        }
    end

    local active = serverState.breakpoints[bpId] ~= nil
    local result = serverState.breakpoint_results[bpId]
    return {
        success = true,
        id = bpId,
        address = toHex(addr),
        slot = active and slot or nil,
        active = active,
        access_type = accessType,
        method = "hardware_debug_register",
        one_shot = options.one_shot,
        max_hits = options.max_hits,
        max_triggers = options.max_triggers,
        condition_count = #options.conditions,
        retired_reason = result and result.retired_reason or nil,
        install_warning = installErr,
        max_buffered_hits = MAX_BP_HITS,
        -- x86 debug registers have no read-only condition; "r" is served by RW.
        note = (accessType == "r") and "Hardware debug registers cannot trap reads only; this also fires on writes" or nil
    }
end

local function cmd_remove_breakpoint(params)
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then return { success = false, error = contextErr } end
    local bpId = params.id
    
    if bpId and (serverState.breakpoints[bpId] or serverState.breakpoint_results[bpId] or serverState.breakpoint_hits[bpId]) then
        local wasActive = serverState.breakpoints[bpId] ~= nil
        local removed, removeErr = clearTrackedBreakpointById(bpId, true)
        if not removed then
            return {
                success = false,
                id = bpId,
                error = removeErr or "Failed to remove breakpoint",
                state_retained = true
            }
        end
        return { success = true, id = bpId, was_active = wasActive }
    end
    
    return { success = false, error = "Breakpoint not found: " .. tostring(bpId) }
end

local function cmd_get_breakpoint_hits(params)
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then return { success = false, error = contextErr } end
    local bpId = params.id
    local clear = params.clear ~= false
    
    local hits
    if bpId then
        hits = serverState.breakpoint_hits[bpId] or {}
        if clear then serverState.breakpoint_hits[bpId] = {} end
    else
        -- Get all hits
        hits = {}
        for id, hitsForBp in pairs(serverState.breakpoint_hits) do
            for _, hit in ipairs(hitsForBp) do
                table.insert(hits, hit)
            end
            -- Empty each bucket in place. Replacing the parent table (the old behaviour)
            -- left live debugger callbacks holding a reference to a bucket that no
            -- longer belonged to anyone.
            if clear then serverState.breakpoint_hits[id] = {} end
        end
    end

    local activeBp = bpId and serverState.breakpoints[bpId] or nil
    local completedBp = bpId and serverState.breakpoint_results[bpId] or nil
    local bpState = activeBp or completedBp
    return {
        success = true,
        count = #hits,
        hits = hits,
        active = activeBp ~= nil,
        retired_reason = completedBp and completedBp.retired_reason or nil,
        process_id = bpState and bpState.process_id or nil,
        generation = bpState and bpState.generation or nil,
        trigger_count = bpState and (bpState.trigger_count or 0) or nil,
        matched_count = bpState and (bpState.matched_count or 0) or nil,
        callback_errors = bpState and (bpState.callback_errors or 0) or nil,
        remove_error = bpState and bpState.remove_error or nil,
        retire_error = bpState and bpState.retire_error or nil,
        retirement_pending = bpState and bpState.retirement_pending or nil,
        continue_error = bpState and bpState.continue_error or nil,
        max_buffered_hits = MAX_BP_HITS
    }
end

local function cmd_list_breakpoints(params)
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then return { success = false, error = contextErr } end
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        table.insert(list, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot,
            active = true,
            process_id = bp.process_id,
            generation = bp.generation,
            one_shot = bp.one_shot,
            max_hits = bp.max_hits,
            max_triggers = bp.max_triggers,
            trigger_count = bp.trigger_count or 0,
            matched_count = bp.matched_count or 0,
            condition_count = #(bp.conditions or {}),
            buffered_hits = #(serverState.breakpoint_hits[id] or {}),
            remove_error = bp.remove_error,
            retire_error = bp.retire_error,
            retirement_pending = bp.retirement_pending,
            continue_error = bp.continue_error,
            install_verification_error = bp.install_verification_error
        })
    end
    return { success = true, count = #list, breakpoints = list }
end

local function cmd_clear_all_breakpoints(params)
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then return { success = false, error = contextErr } end
    local ids = {}
    for id, _ in pairs(serverState.breakpoints) do
        table.insert(ids, id)
    end

    local count = 0
    local failures = {}
    for _, id in ipairs(ids) do
        local removed, removeErr = clearTrackedBreakpointById(id, true)
        if removed then
            count = count + 1
        else
            table.insert(failures, { id = id, error = removeErr or "remove failed" })
        end
    end

    -- Discard completed samples, but retain state for any active removal failure.
    serverState.breakpoint_results = {}
    for id in pairs(serverState.breakpoint_hits) do
        if not serverState.breakpoints[id] then
            serverState.breakpoint_hits[id] = nil
        end
    end

    return {
        success = #failures == 0,
        removed = count,
        failures = failures,
        remaining_active = #failures
    }
end

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

local function cmd_evaluate_lua(params)
    local code = params.code
    local serializeResult = params.serialize_result or false
    if not code then return { success = false, error = "No code provided" } end
    
    local fn, err = loadstring(code)
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end
    
    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end
    
    local resultType = type(result)
    if serializeResult then
        return {
            success = true,
            result = result,
            result_type = resultType,
            serialized = true
        }
    end

    return {
        success = true,
        result = result ~= nil and tostring(result) or nil,
        result_type = resultType,
        serialized = false
    }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

-- Committed, readable regions only - the useful subset for picking a scan window.
-- The old implementation probed nine hardcoded 32-bit base addresses
-- (0x00400000, 0x10000000, ...) which are meaningless for an x64 target and
-- missed everything else even on x86.
local function cmd_get_memory_regions(params)
    local maxRegions = math.min(math.max(tonumber(params.max) or 100, 1), 5000)
    local protection = params.protection

    local readableRegions, regionErr = getSortedMemoryRegions(params.refresh == true, true)
    if not readableRegions then
        return { success = false, error = regionErr or "enumMemoryRegions failed" }
    end

    local regions = {}
    local matched = 0

    for _, r in ipairs(readableRegions) do
        if not protection or regionMatchesProtection(r, protection) then
            matched = matched + 1
            if #regions < maxRegions then
                local writable = regionHasWrite(r)
                local executable = regionHasExecute(r)
                local protStr = "R"
                if writable then protStr = protStr .. "W" end
                if executable then protStr = protStr .. "X" end

                regions[#regions + 1] = {
                    base = toHex(r.BaseAddress or 0),
                    size = r.RegionSize or 0,
                    protection = protStr,
                    protect_flags = r.Protect or 0,
                    readable = true,
                    writable = writable,
                    executable = executable
                }
            end
        end
    end

    return {
        success = true,
        count = #regions,
        total_matching = matched,
        truncated = matched > #regions,
        filter = protection,
        regions = regions
    }
end

-- ============================================================================
-- COMMAND HANDLERS - UTILITY
-- ============================================================================

local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

-- Full bridge state in one call. Troubleshooting used to require guessing from
-- ping plus whatever CE printed to its own console.
local function cmd_status(params)
    local _, contextErr = ensureBreakpointProcessContext()
    if contextErr then
        return {
            success = false,
            version = VERSION,
            pipe_name = PIPE_NAME,
            error = contextErr
        }
    end
    local breakpoints = {}
    for id, bp in pairs(serverState.breakpoints) do
        table.insert(breakpoints, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execute",
            slot = bp.slot,
            active = true,
            process_id = bp.process_id,
            generation = bp.generation,
            one_shot = bp.one_shot,
            max_hits = bp.max_hits,
            max_triggers = bp.max_triggers,
            trigger_count = bp.trigger_count or 0,
            matched_count = bp.matched_count or 0,
            condition_count = #(bp.conditions or {}),
            buffered_hits = #(serverState.breakpoint_hits[id] or {}),
            remove_error = bp.remove_error,
            retire_error = bp.retire_error,
            retirement_pending = bp.retirement_pending,
            continue_error = bp.continue_error,
            install_verification_error = bp.install_verification_error
        })
    end

    local completedBreakpoints = {}
    for id, bp in pairs(serverState.breakpoint_results) do
        table.insert(completedBreakpoints, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execute",
            active = false,
            process_id = bp.process_id,
            generation = bp.generation,
            retired_reason = bp.retired_reason,
            trigger_count = bp.trigger_count or 0,
            matched_count = bp.matched_count or 0,
            callback_errors = bp.callback_errors or 0,
            buffered_hits = #(serverState.breakpoint_hits[id] or {}),
            continue_error = bp.continue_error
        })
    end

    local slotsUsed = 0
    for i = 1, 4 do
        if serverState.hw_bp_slots[i] then slotsUsed = slotsUsed + 1 end
    end

    local watches = {}
    for key, w in pairs(serverState.active_watches) do
        table.insert(watches, {
            virtual_address = key,
            watch_id = w.id,
            mode = w.mode,
            uptime_seconds = os.time() - (w.start_time or os.time())
        })
    end

    local aaScripts = {}
    for id in pairs(serverState.aa_scripts) do table.insert(aaScripts, id) end

    local pid = getOpenedProcessID() or 0
    local is64, dbkLoaded, dbvmActive = false, false, false
    pcall(function() is64 = targetIs64Bit() end)
    pcall(function() dbkLoaded = dbk_initialized() == true end)
    pcall(function() dbvmActive = dbvm_initialized() == true end)
    local debuggerStarted, debuggerStateError = getDebuggerState()
    local debuggerInterface = nil
    if debuggerStarted then
        pcall(function() debuggerInterface = debug_getCurrentDebuggerInterface() end)
    end

    return {
        success = true,
        version = VERSION,
        pipe_name = PIPE_NAME,
        auth_required = getAuthToken() ~= nil,
        client_connected = serverState.connected == true,
        idle_kick_ms = IDLE_KICK_MS,
        client_idle_ms = (serverState.connected == true and serverState.lastActivityTick)
            and tickDiffMs(getTickCount(), serverState.lastActivityTick) or nil,
        worker_running = serverState.workerDone ~= true,
        worker_generation = serverState.workerGeneration or 0,
        worker_version = serverState.workerVersion,
        worker_transport_version = serverState.workerTransportVersion,
        worker_pipe_name = serverState.workerPipeName,
        worker_hot_reload = serverState.workerHotReload == true,
        dispatcher_version = serverState.dispatcherVersion,
        dispatch_in_progress = serverState.dispatchInProgress == true,
        process_id = pid,
        process_attached = pid > 0,
        debugger_started = debuggerStarted,
        debugger_state_error = debuggerStateError,
        debugger_interface = debuggerInterface,
        breakpoint_requires_started_debugger = true,
        breakpoint_process_id = serverState.breakpoint_process_id,
        architecture = is64 and "x64" or "x86",
        dbk_loaded = dbkLoaded,
        dbvm_active = dbvmActive,
        hw_breakpoint_slots_used = slotsUsed,
        hw_breakpoint_slots_total = 4,
        breakpoints = breakpoints,
        completed_breakpoints = completedBreakpoints,
        dbvm_watches = watches,
        auto_assemble_scripts = aaScripts,
        scan_results_available = serverState.scan_foundlist ~= nil,
        max_scan_budget = MAX_SCAN_BUDGET,
        max_buffered_hits = MAX_BP_HITS,
        max_completed_breakpoints = MAX_BP_RESULTS
    }
end

-- Release breakpoints, DBVM watches and scan objects without reloading the script.
local function cmd_cleanup(params)
    local cleaned = cleanupZombieState()
    return {
        success = #cleaned.breakpoint_errors == 0,
        removed_breakpoints = cleaned.breakpoints,
        breakpoint_cleanup_errors = cleaned.breakpoint_errors,
        remaining_active_breakpoints = #cleaned.breakpoint_errors,
        stopped_dbvm_watches = cleaned.dbvm_watches,
        released_scan_objects = cleaned.scans,
        note = "AutoAssembler scripts are left untouched; disable them explicitly with auto_assemble(disable=true)"
    }
end

local function cmd_search_string(params)
    local searchStr = params.string or params.pattern
    local wide = params.wide or false
    local limit = math.min(math.max(math.floor(tonumber(params.limit) or 100), 1), 1000)
    local timeBudgetMs = math.min(math.max(math.floor(tonumber(params.time_budget_ms) or 1500), 100), 10000)
    
    if not searchStr then return { success = false, error = "No search string" } end
    
    -- Convert string to AOB pattern
    local parts = {}
    for i = 1, #searchStr do
        local b = searchStr:byte(i)
        parts[#parts + 1] = HEX_BYTE[b] or string.format("%02X", b)
        if wide then parts[#parts + 1] = "00" end
    end
    local pattern = table.concat(parts, " ")

    local stats, parseErr = parseAobPattern(pattern)
    if not stats then return { success = false, error = parseErr } end

    local scan, scanErr = runPatternScan(params, stats, limit, timeBudgetMs)
    if not scan then
        return { success = false, error = scanErr, addresses = {} }
    end

    local addresses = {}
    for _, result in ipairs(scan.results) do
        local addr = result.value
        local okPreview, preview = pcall(readString, addr, 50, wide)
        table.insert(addresses, {
            address = toHex(addr),
            preview = sanitizeForJson(okPreview and preview or "")
        })
    end

    return {
        success = true,
        count = #addresses,
        addresses = addresses,
        start_address = toHex(scan.start_address),
        scanned_bytes = scan.scanned_bytes,
        windows_scanned = scan.windows_scanned,
        max_scan_budget = MAX_SCAN_BUDGET,
        auto_window = not scan.explicit,
        truncated = scan.truncated,
        next_start_address = toHex(scan.next_start_address),
    }
end

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
local function cmd_dissect_structure(params)
    local address = params.address
    local size = math.min(math.max(math.floor(tonumber(params.size) or 256), 1), 65536)

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end

    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure" }
    end

    local elements = {}
    -- CE class methods take dot notation (see CE_LUA_Documentation.md and every other
    -- call in this file: ms.firstScan, fl.getCount, list.destroy). The previous colon
    -- form passed the structure itself as the first argument, so autoGuess received
    -- (struct, address, 0) instead of (address, 0, size) - it failed inside its pcall
    -- and the tool silently reported zero elements for every address.
    local okBody, bodyErr = pcall(function()
        struct.autoGuess(address, 0, size)

        local count = struct.Count or 0
        for i = 0, count - 1 do
            local elem = struct.Element[i]
            if elem then
                local val = nil
                pcall(function() val = elem.getValue(address) end)
                local offsetVal = elem.Offset or 0

                table.insert(elements, {
                    offset = offsetVal,
                    hex_offset = string.format("+0x%X", offsetVal),
                    name = elem.Name or "",
                    vartype = elem.Vartype,
                    vartype_name = vartypeName(elem.Vartype),
                    bytesize = elem.Bytesize,
                    current_value = type(val) == "string" and sanitizeForJson(val) or val
                })
            end
        end
    end)

    -- createStructure does not add to the global list, so just free it.
    pcall(function() struct.destroy() end)

    if not okBody then
        return {
            success = false,
            base_address = toHex(address),
            error = "dissect_structure failed: " .. tostring(bodyErr)
        }
    end

    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
local function cmd_get_thread_list(params)
    local okCreate, list = pcall(createStringlist)
    if not okCreate or not list then
        return { success = false, error = "Failed to create string list: " .. tostring(list) }
    end

    local threads = {}
    local okBody, bodyErr = pcall(function()
        getThreadlist(list)
        local count = list.Count or 0
        for i = 0, count - 1 do
            local idHex = list[i]
            table.insert(threads, {
                id_hex = idHex,
                id_int = tonumber(idHex, 16)
            })
        end
    end)

    pcall(function() list.destroy() end)

    if not okBody then
        return { success = false, error = "get_thread_list failed: " .. tostring(bodyErr) }
    end

    return {
        success = true,
        count = #threads,
        threads = threads
    }
end

-- AutoAssemble: Execute an AutoAssembler script.
-- The [ENABLE] run returns a disableInfo table that CE needs to run the matching
-- [DISABLE] section later. That table used to be discarded, so injected code,
-- hooks and allocations could never be cleanly reverted through this bridge.
-- It is now kept under `id` (defaults to "last") for a follow-up disable=true call.
local function cmd_auto_assemble(params)
    local script = params.script or params.code
    local disable = params.disable or false
    local scriptId = params.id or "last"

    if disable then
        local saved = serverState.aa_scripts[scriptId]
        if not saved then
            local known = {}
            for id in pairs(serverState.aa_scripts) do table.insert(known, id) end
            return {
                success = false,
                error = "No enabled script stored under id '" .. tostring(scriptId) .. "'",
                known_ids = known
            }
        end

        -- Passing the stored disableInfo makes CE execute the [DISABLE] section.
        local okDisable, disableOk, disableErr = pcall(autoAssemble, saved.script, saved.disableInfo)
        if not okDisable then
            return {
                success = false,
                id = scriptId,
                error = "AutoAssemble disable crashed: " .. tostring(disableOk)
            }
        end
        if disableOk == false then
            return {
                success = false,
                id = scriptId,
                error = "AutoAssemble disable failed: " .. tostring(disableErr or "unknown error")
            }
        end

        serverState.aa_scripts[scriptId] = nil
        return { success = true, id = scriptId, disabled = true }
    end

    if not script then return { success = false, error = "No script provided" } end

    local okRun, success, disableInfo, warnings = pcall(autoAssemble, script)
    if not okRun then
        return { success = false, error = "AutoAssemble crashed: " .. tostring(success) }
    end

    if not success then
        return { success = false, error = "AutoAssemble failed: " .. tostring(disableInfo) }
    end

    local result = {
        success = true,
        executed = true,
        id = scriptId,
        warnings = warnings and tostring(warnings) or nil
    }

    if type(disableInfo) == "table" then
        serverState.aa_scripts[scriptId] = { script = script, disableInfo = disableInfo }
        result.disable_available = true
        result.disable_hint = "Call auto_assemble with disable=true and id='" .. tostring(scriptId) .. "' to run the [DISABLE] section"

        local okSymbols = pcall(function()
            if disableInfo.symbols then
                result.symbols = {}
                for name, addr in pairs(disableInfo.symbols) do
                    if type(addr) == "number" then result.symbols[name] = toHex(addr) end
                end
            end
        end)
        if not okSymbols then result.symbols = nil end

        pcall(function()
            if disableInfo.allocs then
                result.allocations = {}
                for name, info in pairs(disableInfo.allocs) do
                    table.insert(result.allocations, {
                        name = tostring(name),
                        address = type(info) == "table" and info.address and toHex(info.address) or nil,
                        size = type(info) == "table" and info.size or nil
                    })
                end
            end
        end)
    else
        result.disable_available = false
    end

    return result
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
local function cmd_enum_memory_regions_full(params)
    local maxRegions = math.min(math.max(math.floor(tonumber(params.max) or 500), 1), 5000)

    local regions, regionErr = getSortedMemoryRegions(params.refresh == true, false)
    if not regions then
        return { success = false, error = regionErr or "enumMemoryRegions failed" }
    end

    local result = {}
    for i, r in ipairs(regions) do
        if i > maxRegions then break end

        -- Determine protection string
        local prot = tonumber(r.Protect or 0) or 0
        local state = tonumber(r.State or 0) or 0
        local baseProt = prot & 0xFF
        local protStr = ""

        -- PAGE_EXECUTE / base protection flags
        if baseProt == 0x10 then protStr = "X"
        elseif baseProt == 0x20 then protStr = "RX"
        elseif baseProt == 0x40 then protStr = "RWX"
        elseif baseProt == 0x80 then protStr = "WX"
        elseif baseProt == 0x02 then protStr = "R"
        elseif baseProt == 0x04 then protStr = "RW"
        elseif baseProt == 0x08 then protStr = "W"
        elseif baseProt == 0x01 then protStr = "NOACCESS"
        else protStr = string.format("0x%X", baseProt)
        end

        if (prot & 0x100) ~= 0 then protStr = protStr .. "+GUARD" end
        if (prot & 0x200) ~= 0 then protStr = protStr .. "+NOCACHE" end
        if (prot & 0x400) ~= 0 then protStr = protStr .. "+WRITECOMBINE" end

        table.insert(result, {
            base = toHex(r.BaseAddress or 0),
            allocation_base = toHex(r.AllocationBase or 0),
            size = r.RegionSize or 0,
            state = state,
            protect = prot,
            protect_string = protStr,
            type = r.Type or 0,
            -- State decoded
            is_committed = state == 0x1000,
            is_reserved = state == 0x2000,
            is_free = state == 0x10000
        })
    end

    return {
        success = true,
        count = #result,
        total_regions = #regions,
        truncated = #regions > #result,
        regions = result
    }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
local function cmd_read_pointer_chain(params)
    local base = params.base
    local parsedOffsets, offsetsErr = parsePointerOffsets(params.offsets)
    if not parsedOffsets then
        return { success = false, error = offsetsErr }
    end

    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end

    local currentAddr = base
    local chain = { { step = 0, address = toHex(currentAddr), description = "base" } }

    for i, offset in ipairs(parsedOffsets) do
        -- Read pointer at current address
        local ptr = readPointer(currentAddr)
        if not ptr then
            return {
                success = false,
                error = "Failed to read pointer at step " .. i,
                partial_chain = chain,
                failed_at_address = toHex(currentAddr)
            }
        end

        -- Apply offset
        currentAddr = ptr + offset
        local hexOffset = (offset >= 0) and string.format("+0x%X", offset) or string.format("-0x%X", -offset)
        table.insert(chain, {
            step = i,
            address = toHex(currentAddr),
            offset = offset,
            hex_offset = hexOffset,
            pointer_value = toHex(ptr)
        })
    end

    -- Try to read a value at the final address (using readPointer for 32/64-bit compatibility)
    local finalValue = nil
    pcall(function()
        finalValue = readPointer(currentAddr)
    end)

    return {
        success = true,
        base = toHex(base),
        offsets = parsedOffsets,
        final_address = toHex(currentAddr),
        final_value = finalValue,
        chain = chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
local function cmd_get_rtti_classname(params)
    local address = params.address
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local className = getRTTIClassName(address)
    
    if className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
local function cmd_get_address_info(params)
    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
local function cmd_checksum_memory(params)
    local address = params.address
    local size = math.min(math.max(math.floor(tonumber(params.size) or 256), 1), 16777216)
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local ok, hash = pcall(md5memory, address, size)
    
    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash)
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
local function cmd_generate_signature(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)
    
    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature)
        }
    end
    
    if not signature or signature == "" then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature - pattern not unique enough"
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

-- ============================================================================
-- DBVM HYPERVISOR TOOLS (Safe Dynamic Tracing - Ring -1)
-- ============================================================================
-- These tools use DBVM (Debuggable Virtual Machine) for hypervisor-level tracing.
-- They are 100% invisible to anti-cheat: no game memory modification, no debug registers.
-- DBVM works at the hypervisor level, beneath the OS, making it undetectable.
-- ============================================================================

-- Get Physical Address: Converts virtual address to physical RAM address
-- Required for DBVM operations which work on physical memory
local function cmd_get_physical_address(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- Check if DBK (kernel driver) is available
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    
    if not ok then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings."
        }
    end
    
    if not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page may not be present in RAM."
        }
    end
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        physical_int = phys
    }
end

-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
local function cmd_start_dbvm_watch(params)
    local addr = params.address
    local mode = params.mode or "w"  -- "w" = write, "r" = read, "rw" = both, "x" = execute
    local maxEntries = math.min(math.max(math.floor(tonumber(params.max_entries) or 1000), 1), 100000)  -- Internal buffer size
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- 0. Safety Checks
    if not dbk_initialized() then
        return { success = false, error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode" }
    end
    
    if not dbvm_initialized() then
        -- Try to initialize if possible
        pcall(dbvm_initialize)
        if not dbvm_initialized() then
            return { success = false, error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM" }
        end
    end

    -- 1. Get Physical Address (DBVM works on physical RAM)
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    if not ok or not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page might be paged out or invalid."
        }
    end
    
    -- 2. Check if already watching this address
    local watchKey = toHex(addr)
    if serverState.active_watches[watchKey] then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Already watching this address. Call stop_dbvm_watch first."
        }
    end
    
    -- 3. Configure watch options
    -- Bit 0: Log multiple times (1 = yes)
    -- Bit 1: Ignore size / log whole page (2)
    -- Bit 2: Log FPU registers (4)
    -- Bit 3: Log Stack (8)
    local options = 1 + 2 + 8  -- Multiple logging + whole page + stack context
    
    -- 4. Start the appropriate watch based on mode
    local watch_id
    local okWatch, result
    
    log(string.format("Starting DBVM watch on Phys: 0x%X (Mode: %s)", phys, mode))

    if mode == "x" then
        if not dbvm_watch_executes then
            return { success = false, error = "dbvm_watch_executes function missing from CE Lua engine" }
        end
        okWatch, result = pcall(dbvm_watch_executes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    elseif mode == "r" or mode == "rw" then
        okWatch, result = pcall(dbvm_watch_reads, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    else  -- default: write
        okWatch, result = pcall(dbvm_watch_writes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    end
    
    if not okWatch then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch CRASHED/FAILED: " .. tostring(result)
        }
    end
    
    if not watch_id then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch returned nil (check CE console for details)"
        }
    end
    
    -- 5. Store watch for later retrieval
    serverState.active_watches[watchKey] = {
        id = watch_id,
        physical = phys,
        mode = mode,
        start_time = os.time()
    }
    
    return {
        success = true,
        status = "monitoring",
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        watch_id = watch_id,
        mode = mode,
        note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end"
    }
end

-- Poll DBVM Watch: Retrieve logged accesses WITHOUT stopping the watch
-- This is CRITICAL for continuous packet monitoring - logs can be polled repeatedly
local function cmd_poll_dbvm_watch(params)
    local addr = params.address
    local clear = params.clear ~= false  -- Default true; explicit false is respected
    local max_results = math.min(math.max(math.floor(tonumber(params.max_results) or 1000), 1), 10000)
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address. Call start_dbvm_watch first."
        }
    end
    
    local watch_id = watchInfo.id
    watchInfo.buffered_logs = watchInfo.buffered_logs or {}
    local buffer = watchInfo.buffered_logs

    -- Retrieve newly logged entries from DBVM (retrievelog drains the driver ring).
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    if okLog and log and #log > 0 then
        local logLen = #log
        if logLen >= 10000 then
            local trimmed = {}
            local startIdx = logLen - 10000 + 1
            for i = startIdx, logLen do
                trimmed[#trimmed + 1] = log[i]
            end
            buffer = trimmed
            watchInfo.buffered_logs = buffer
        else
            for i = 1, logLen do
                buffer[#buffer + 1] = log[i]
            end
            if #buffer > 10000 then
                local excess = #buffer - 10000
                local trimmed = {}
                for i = excess + 1, #buffer do
                    trimmed[#trimmed + 1] = buffer[i]
                end
                buffer = trimmed
                watchInfo.buffered_logs = buffer
            end
        end
    end

    local results = {}
    local count = math.min(#buffer, max_results)
    for i = 1, count do
        local entry = buffer[i]
        -- For packet capture, we need the stack pointer to read [ESP+4]
        local hitData = {
            hit_number = i,
            ESP = entry.RSP and (entry.RSP % 0x100000000) or nil,
            RSP = entry.RSP and toHex(entry.RSP) or nil,
            EIP = entry.RIP and (entry.RIP % 0x100000000) or nil,
            RIP = entry.RIP and toHex(entry.RIP) or nil,
            EAX = entry.RAX and (entry.RAX % 0x100000000) or nil,
            ECX = entry.RCX and (entry.RCX % 0x100000000) or nil,
            EDX = entry.RDX and (entry.RDX % 0x100000000) or nil,
            EBX = entry.RBX and (entry.RBX % 0x100000000) or nil,
            ESI = entry.RSI and (entry.RSI % 0x100000000) or nil,
            EDI = entry.RDI and (entry.RDI % 0x100000000) or nil,
            RAX = entry.RAX and toHex(entry.RAX) or nil,
            RBX = entry.RBX and toHex(entry.RBX) or nil,
            RCX = entry.RCX and toHex(entry.RCX) or nil,
            RDX = entry.RDX and toHex(entry.RDX) or nil,
            RSI = entry.RSI and toHex(entry.RSI) or nil,
            RDI = entry.RDI and toHex(entry.RDI) or nil,
            RBP = entry.RBP and toHex(entry.RBP) or nil,
            R8  = entry.R8  and toHex(entry.R8)  or nil,
            R9  = entry.R9  and toHex(entry.R9)  or nil,
            R10 = entry.R10 and toHex(entry.R10) or nil,
            R11 = entry.R11 and toHex(entry.R11) or nil,
            R12 = entry.R12 and toHex(entry.R12) or nil,
            R13 = entry.R13 and toHex(entry.R13) or nil,
            R14 = entry.R14 and toHex(entry.R14) or nil,
            R15 = entry.R15 and toHex(entry.R15) or nil,
        }
        results[#results + 1] = hitData
    end

    if clear then
        watchInfo.buffered_logs = {}
    end
    
    local uptime = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        status = "active",
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        clear_requested = clear,
        uptime_seconds = uptime,
        hit_count = #results,
        buffered_total = clear and 0 or #buffer,
        hits = results,
        note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end."
    }
end

-- Stop DBVM Watch: Retrieve logged accesses and disable monitoring
-- Returns all instructions that touched the monitored memory
local function cmd_stop_dbvm_watch(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address"
        }
    end
    
    local watch_id = watchInfo.id
    local allEntries = {}
    if watchInfo.buffered_logs then
        for i = 1, #watchInfo.buffered_logs do
            allEntries[#allEntries + 1] = watchInfo.buffered_logs[i]
        end
    end

    -- 1. Retrieve remaining logged accesses from DBVM
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    if okLog and log then
        for i = 1, #log do
            allEntries[#allEntries + 1] = log[i]
        end
    end

    local results = {}
    local disasmCache = {}
    -- Parse each log entry (contains CPU context at time of access)
    for i, entry in ipairs(allEntries) do
        local instr = "???"
        if entry.RIP then
            local cached = disasmCache[entry.RIP]
            if cached == nil then
                local okDis, disasm = pcall(disassemble, entry.RIP)
                cached = (okDis and disasm) or "???"
                disasmCache[entry.RIP] = cached
            end
            instr = cached
        end

        local hitData = {
            hit_number = i,
            instruction_address = entry.RIP and toHex(entry.RIP) or nil,
            instruction = instr,
            -- CPU registers at time of access
            registers = {
                RAX = entry.RAX and toHex(entry.RAX) or nil,
                RBX = entry.RBX and toHex(entry.RBX) or nil,
                RCX = entry.RCX and toHex(entry.RCX) or nil,
                RDX = entry.RDX and toHex(entry.RDX) or nil,
                RSI = entry.RSI and toHex(entry.RSI) or nil,
                RDI = entry.RDI and toHex(entry.RDI) or nil,
                RBP = entry.RBP and toHex(entry.RBP) or nil,
                RSP = entry.RSP and toHex(entry.RSP) or nil,
                RIP = entry.RIP and toHex(entry.RIP) or nil,
                R8  = entry.R8  and toHex(entry.R8)  or nil,
                R9  = entry.R9  and toHex(entry.R9)  or nil,
                R10 = entry.R10 and toHex(entry.R10) or nil,
                R11 = entry.R11 and toHex(entry.R11) or nil,
                R12 = entry.R12 and toHex(entry.R12) or nil,
                R13 = entry.R13 and toHex(entry.R13) or nil,
                R14 = entry.R14 and toHex(entry.R14) or nil,
                R15 = entry.R15 and toHex(entry.R15) or nil,
            }
        }
        table.insert(results, hitData)
    end
    
    -- 2. Disable the watch
    pcall(dbvm_watch_disable, watch_id)
    
    -- 3. Clean up
    serverState.active_watches[watchKey] = nil
    
    local duration = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        hit_count = #results,
        duration_seconds = duration,
        hits = results,
        note = #results > 0 and "Found instructions that accessed the memory" or "No accesses detected during monitoring"
    }
end

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,
    
    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- More accurate, uses native API
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,
    status = cmd_status,
    get_status = cmd_status,  -- Alias
    cleanup = cmd_cleanup,
}

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================

-- Encoding can fail (circular table from evaluate_lua with serialize_result,
-- unsupported value, deep nesting). Previously that error escaped executeCommand,
-- no response was ever written, and the Python client blocked until its timeout.
-- Every path out of here must produce a valid JSON-RPC envelope.
local function encodeResponse(payload, id)
    local ok, encoded = pcall(json.encode, payload)
    if ok and encoded then return encoded end

    local fallback = {
        jsonrpc = "2.0",
        error = {
            code = -32603,
            message = "Response serialization failed: " .. tostring(encoded),
        },
        id = id,
    }
    local ok2, encoded2 = pcall(json.encode, fallback)
    if ok2 and encoded2 then return encoded2 end
    return '{"jsonrpc":"2.0","error":{"code":-32603,"message":"Response serialization failed"},"id":null}'
end

local function dispatchRequest(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or type(request) ~= "table" then
        return encodeResponse({ jsonrpc = "2.0", error = { code = -32700, message = "Parse error" }, id = nil }, nil)
    end

    local method = request.method
    local params = request.params or {}
    local id = request.id

    local authToken = getAuthToken()
    if authToken ~= nil and not tokensEqual(request.auth_token, authToken) then
        return encodeResponse({ jsonrpc = "2.0", error = { code = -32001, message = "Unauthorized: missing or invalid auth_token" }, id = id }, id)
    end

    if type(params) ~= "table" then
        return encodeResponse({ jsonrpc = "2.0", error = { code = -32602, message = "params must be an object" }, id = id }, id)
    end

    local handler = commandHandlers[method]
    if not handler then
        return encodeResponse({ jsonrpc = "2.0", error = { code = -32601, message = "Method not found: " .. tostring(method) }, id = id }, id)
    end

    local ok2, result = pcall(handler, params)
    if not ok2 then
        return encodeResponse({ jsonrpc = "2.0", error = { code = -32603, message = "Internal error: " .. tostring(result) }, id = id }, id)
    end

    return encodeResponse({ jsonrpc = "2.0", result = result, id = id }, id)
end

-- Runs on the main thread for every request; the idle watchdog reads the stamps.
local function executeCommand(jsonRequest)
    serverState.lastActivityTick = getTickCount()
    local response = dispatchRequest(jsonRequest)
    serverState.lastActivityTick = getTickCount()
    return response
end

-- The pipe worker resolves this global for every request. Re-executing the script
-- can therefore replace all command handlers without stopping a connected worker.
_G.__CE_MCP_BRIDGE_DISPATCHER = executeCommand
serverState.dispatcherVersion = VERSION

-- ============================================================================
-- THREAD-BASED PIPE SERVER (NON-BLOCKING GUI)
-- ============================================================================
-- Replaces v10 Timer architecture to prevent GUI Freezes.
-- I/O happens in Worker Thread. Execution happens in Main Thread.

local function PipeWorker(thread)
    local generation = serverState.workerGeneration or 0
    log("Worker Thread Started #" .. tostring(generation) .. " - Waiting for connection...")
    
    while not thread.Terminated and serverState.workerGeneration == generation do
        -- Create Pipe Instance per connection attempt
        -- Increased buffer size to 64KB for better throughput
        local pipe = createPipe(PIPE_NAME, 65536, 65536)
        if not pipe then
            log("Fatal: Failed to create pipe")
            if serverState.workerGeneration == generation then
                serverState.workerDone = true
            end
            return
        end
        
        -- Store reference so we can wake it from main thread (StopMCPBridge) to break blocking calls
        if serverState.workerGeneration == generation then
            serverState.workerPipe = pipe
        end
        
        local okAccept, acceptErr = pcall(function()
            pipe.acceptConnection()
        end)
        if (not okAccept) and (not thread.Terminated) then
            log("Thread: acceptConnection failed: " .. tostring(acceptErr))
        end
        
        if pipe.Connected and not thread.Terminated and serverState.workerGeneration == generation then
            log("Client Connected")
            serverState.connected = true
            
            while not thread.Terminated and pipe.Connected and serverState.workerGeneration == generation do
                local ok, lenBytes = pcall(function() return pipe.readBytes(4) end)
                
                if ok and lenBytes and #lenBytes == 4 then
                    local len = lenBytes[1] + (lenBytes[2] * 256) + (lenBytes[3] * 65536) + (lenBytes[4] * 16777216)
                    
                    -- Sanity check length
                    if len > 0 and len < 100 * 1024 * 1024 then
                        local okPayload, payload = pcall(function() return pipe.readString(len) end)
                        
                        if okPayload and payload and #payload == len then
                            -- CRITICAL: EXECUTE ON MAIN THREAD
                            local response = nil
                            thread.synchronize(function()
                                if serverState.shutdownRequested or serverState.workerGeneration ~= generation then
                                    return
                                end
                                serverState.dispatchInProgress = true
                                local dispatcher = _G.__CE_MCP_BRIDGE_DISPATCHER or executeCommand
                                local okDispatch, dispatchResult = pcall(dispatcher, payload)
                                if okDispatch then
                                    response = dispatchResult
                                else
                                    response = encodeResponse({
                                        jsonrpc = "2.0",
                                        error = {
                                            code = -32603,
                                            message = "Dispatcher failed: " .. tostring(dispatchResult)
                                        },
                                        id = nil
                                    }, nil)
                                end
                                serverState.dispatchInProgress = false
                            end)
                            
                            -- Write response back (Worker Thread)
                            if response and not thread.Terminated and serverState.workerGeneration == generation then
                                local rLen = #response
                                local b1 = rLen % 256
                                local b2 = math.floor(rLen / 256) % 256
                                local b3 = math.floor(rLen / 65536) % 256
                                local b4 = math.floor(rLen / 16777216) % 256

                                serverState.workerWriting = true
                                local okWriteHeader, headerWritten = pcall(function()
                                    return pipe.writeBytes({b1, b2, b3, b4})
                                end)
                                if (not okWriteHeader) or (not pipe.Connected) or type(headerWritten) ~= "number" or headerWritten < 4 then
                                    serverState.workerWriting = false
                                    if not thread.Terminated then
                                        log("Thread: writeBytes failed (" .. tostring(headerWritten) .. "), reconnecting client")
                                    end
                                    break
                                end

                                local okWriteBody, bodyWritten = pcall(function()
                                    return pipe.writeString(response)
                                end)
                                serverState.workerWriting = false
                                if (not okWriteBody) or (not pipe.Connected) or type(bodyWritten) ~= "number" or bodyWritten < rLen then
                                    if not thread.Terminated then
                                        log("Thread: writeString failed (" .. tostring(bodyWritten) .. "), reconnecting client")
                                    end
                                    break
                                end
                            end
                        else
                            if not thread.Terminated then
                                log("Thread: readString failed, reconnecting client")
                            end
                            break
                        end
                    else
                        if not thread.Terminated then
                            log("Thread: invalid payload length (" .. tostring(len) .. "), reconnecting client")
                        end
                        break
                    end
                else
                    if pipe.Connected and not thread.Terminated then
                        log("Thread: readBytes failed while connected, reconnecting client")
                        break
                    end
                end
            end
            
            serverState.connected = false
            log("Client Disconnected")
        end
        
        -- Clean up pipe (never double-destroy a pipe already destroyed by StopMCPBridge)
        if serverState.workerGeneration == generation and serverState.workerPipe == pipe then
            serverState.workerPipe = nil
        end
        local destroyedMap = serverState.destroyedPipes
        if not (destroyedMap and destroyedMap[pipe]) then
            pcall(function() pipe.disconnect() end)
            pcall(function() pipe.destroy() end)
        else
            destroyedMap[pipe] = nil
        end
        
        -- Brief sleep before recreating pipe to accept new connection
        if not thread.Terminated and serverState.workerGeneration == generation then sleep(50) end
    end
    
    if serverState.workerGeneration == generation then
        serverState.workerDone = true
    end
    log("Worker Thread Terminated #" .. tostring(generation))
end

-- ============================================================================
-- IDLE CLIENT WATCHDOG
-- ============================================================================
-- Main-thread timer. Disconnecting the pipe wakes the worker's blocking readBytes,
-- exactly as StopMCPBridge does, and the worker then re-listens for the next client.
-- Needs no worker changes, so it also covers a hot-reloaded, still-running worker.

local function idleWatchdogTick()
    if IDLE_KICK_MS <= 0 then return end
    local pipe = serverState.workerPipe
    if not pipe or serverState.connected ~= true or serverState.dispatchInProgress == true or serverState.workerWriting == true then
        serverState.idleWatchPipe = nil
        return
    end

    local now = getTickCount()
    -- The worker creates a fresh pipe object per client: a new client starts its own clock.
    if serverState.idleWatchPipe ~= pipe then
        serverState.idleWatchPipe = pipe
        serverState.idleWatchSince = now
    end

    local last = serverState.idleWatchSince or now
    local act = serverState.lastActivityTick
    if act and tickDiffMs(now, act) < tickDiffMs(now, last) then
        last = act
    end

    local elapsed = tickDiffMs(now, last)
    if elapsed >= IDLE_KICK_MS then
        log("Disconnecting MCP client idle for " .. tostring(math.floor(elapsed / 1000)) ..
            "s so other clients can connect")
        serverState.idleWatchPipe = nil
        pcall(function() pipe.disconnect() end)
    end
end

local function startIdleWatchdog()
    if serverState.idleTimer then
        pcall(function() serverState.idleTimer.destroy() end)
        serverState.idleTimer = nil
    end
    if IDLE_KICK_MS <= 0 or type(createTimer) ~= "function" then return end
    local ok, timer = pcall(createTimer, nil, false)
    if not ok or not timer then return end
    timer.Interval = 1000
    timer.OnTimer = function() pcall(idleWatchdogTick) end
    timer.Enabled = true
    serverState.idleTimer = timer
end

-- ============================================================================
-- MAIN CONTROL
-- ============================================================================

function StopMCPBridge()
    if serverState.dispatchInProgress == true then
        log("StopMCPBridge refused: an MCP command is executing on the CE main thread.")
        return false
    end

    if serverState.idleTimer then
        pcall(function() serverState.idleTimer.destroy() end)
        serverState.idleTimer = nil
    end

    if serverState.workerThread then
        log("Stopping Server (force-disconnect client + terminate worker)...")
        local t = serverState.workerThread
        serverState.shutdownRequested = true
        serverState.destroyedPipes = serverState.destroyedPipes or {}

        -- Signal the worker loop to stop.
        pcall(function() t.terminate() end)

        -- First disconnect connected clients and pump CheckSynchronize so any
        -- queued thread.synchronize unblocks immediately without double-destroy.
        -- Only destroy the pipe if the worker stays blocked in acceptConnection().
        local waited = 0
        while (serverState.workerDone ~= true) and (waited < 3000) do
            if CheckSynchronize then pcall(CheckSynchronize) end
            local pipe = serverState.workerPipe
            if pipe then
                pcall(function() pipe.disconnect() end)
                if waited >= 150 and serverState.workerPipe == pipe then
                    serverState.destroyedPipes[pipe] = true
                    serverState.workerPipe = nil
                    pcall(function() pipe.destroy() end)
                end
            end
            sleep(50)
            waited = waited + 50
        end
        if serverState.workerDone ~= true then
            log("Warning: worker did not confirm exit within 3s; restart aborted to avoid duplicate pipe workers")
            serverState.running = false
            serverState.connected = false
            local pipe = serverState.workerPipe
            if pipe then
                serverState.destroyedPipes[pipe] = true
                serverState.workerPipe = nil
                pcall(function() pipe.disconnect() end)
                pcall(function() pipe.destroy() end)
            end
            return false
        end

        pcall(function() t.destroy() end)
        serverState.workerThread = nil
        serverState.workerVersion = nil
        serverState.workerTransportVersion = nil
        serverState.workerPipeName = nil
        serverState.workerHotReload = false
        serverState.running = false
        serverState.connected = false
    end

    -- Destroy any stray pipe handle even if the worker reference was already lost.
    if serverState.workerPipe then
        local pipe = serverState.workerPipe
        serverState.workerPipe = nil
        pcall(function() pipe.disconnect() end)
        pcall(function() pipe.destroy() end)
    end

    if serverState.timer then
        pcall(function() serverState.timer.destroy() end)
        serverState.timer = nil
    end

    serverState.workerVersion = nil
    serverState.workerTransportVersion = nil
    serverState.workerPipeName = nil
    serverState.workerHotReload = false
    serverState.workerWriting = false

    -- CRITICAL: Cleanup all zombie resources (breakpoints, DBVM watches, scans)
    cleanupZombieState()

    log("Server Stopped")
    return true
end

function StartMCPBridge(forceRestart)
    forceRestart = (forceRestart == true)
    local workerAlive = serverState.workerThread and serverState.workerDone ~= true
    if (not forceRestart) and workerAlive then
        if serverState.workerHotReload == true and
           serverState.workerTransportVersion == TRANSPORT_VERSION and
           serverState.workerPipeName == PIPE_NAME then
            if previousDispatcherVersion ~= VERSION then
                log("MCP command dispatcher hot-reloaded from " ..
                    tostring(previousDispatcherVersion or "unknown") .. " to " .. VERSION ..
                    "; pipe worker preserved.")
            else
                log("MCP Bridge v" .. VERSION .. " already running; dispatcher refreshed in place.")
            end
            return true
        else
            -- Old workers capture their original local dispatcher. Restarting them
            -- synchronously from script load can deadlock CE, so never do it here.
            log("MCP worker transport or pipe is incompatible with this script; " ..
                "automatic restart skipped to protect CE. Restart CE once.")
            return true
        end
    end

    local stopped = StopMCPBridge()  -- This now also calls cleanupZombieState()
    if stopped == false then
        log("MCP Bridge start skipped: previous worker is still shutting down. Re-run after it exits.")
        return false
    end
    
    -- Update Global State
    log("Starting MCP Bridge v" .. VERSION)
    
    serverState.running = true
    serverState.connected = false
    serverState.shutdownRequested = false
    serverState.workerWriting = false
    serverState.destroyedPipes = {}
    startIdleWatchdog()
    
    -- Create the Worker Thread
    serverState.workerGeneration = (serverState.workerGeneration or 0) + 1
    serverState.workerDone = false
    serverState.workerVersion = VERSION
    serverState.workerTransportVersion = TRANSPORT_VERSION
    serverState.workerPipeName = PIPE_NAME
    serverState.workerHotReload = true
    serverState.dispatchInProgress = false
    serverState.workerThread = createThread(PipeWorker)
    if not serverState.workerThread then
        serverState.running = false
        serverState.workerDone = true
        serverState.workerVersion = nil
        serverState.workerTransportVersion = nil
        serverState.workerPipeName = nil
        serverState.workerHotReload = false
        log("Fatal: failed to create MCP worker thread")
        return false
    end
    
    log("===========================================")
    log("MCP Server Listening on: " .. PIPE_NAME)
    log("Architecture: Threaded I/O + Synchronized Execution")
    log("Cleanup: Zombie Prevention Active")
    log("===========================================")
    return true
end

function RestartMCPBridge()
    return StartMCPBridge(true)
end

-- Auto-start
startIdleWatchdog()
StartMCPBridge(false)
