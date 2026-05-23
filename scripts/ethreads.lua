-- List ETHREADs belonging to a process

local KTHREAD_STATE = {
    [0] = "Initialized",
    [1] = "Ready",
    [2] = "Running",
    [3] = "Standby",
    [4] = "Terminated",
    [5] = "Waiting",
    [6] = "Transition",
    [7] = "DeferredReady",
    [8] = "GateWaitObsolete",
    [9] = "WaitingForProcessInSwap",
}

local WAIT_REASON = {
    [0] = "Executive",
    [1] = "FreePage",
    [2] = "PageIn",
    [3] = "PoolAllocation",
    [4] = "DelayExecution",
    [5] = "Suspended",
    [6] = "UserRequest",
    [7] = "WrExecutive",
    [8] = "WrFreePage",
    [9] = "WrPageIn",
    [10] = "WrPoolAllocation",
    [11] = "WrDelayExecution",
    [12] = "WrSuspended",
    [13] = "WrUserRequest",
    [14] = "WrEventPair",
    [15] = "WrQueue",
    [16] = "WrLpcReceive",
    [17] = "WrLpcReply",
    [18] = "WrVirtualMemory",
    [19] = "WrPageOut",
    [20] = "WrRendezvous",
    [21] = "WrKeyedEvent",
    [22] = "WrTerminated",
    [23] = "WrProcessInSwap",
    [24] = "WrCpuRateControl",
    [25] = "WrCalloutStack",
    [26] = "WrKernel",
    [27] = "WrResource",
    [28] = "WrPushLock",
    [29] = "WrMutex",
    [30] = "WrQuantumEnd",
    [31] = "WrDispatchInt",
    [32] = "WrPreempted",
    [33] = "WrYieldExecution",
    [34] = "WrFastMutex",
    [35] = "WrGuardedMutex",
    [36] = "WrRundown",
    [37] = "WrAlertByThreadId",
    [38] = "WrDeferredPreempt",
}

local function resolve_process(target)
    if target:match("^%d+$") then
        local p = ntos.try_process(target)
        if p then return p.eprocess, ("%s (pid %d)"):format(p.name, p.pid) end
    end

    local value = ntos.try_eval(target)
    if value then return value, tostring(value) end

    local p = ntos.process(target)
    return p.eprocess, ("%s (pid %d)"):format(p.name, p.pid)
end

local function list_threads(eprocess)
    local head_off = ntos.try_offset_of("_EPROCESS", "ThreadListHead")
    if not head_off then
        error("_EPROCESS.ThreadListHead is unavailable in symbols")
    end

    local head = eprocess + head_off
    local cur = ntos.read_qword(head)
    local seen = {}
    local threads = {}

    for _ = 1, 4096 do
        if cur == ntos.addr(0) or cur == head then break end
        local key = tostring(cur)
        if seen[key] then break end
        seen[key] = true
        threads[#threads + 1] = ntos.containing_record(cur, "_ETHREAD", "ThreadListEntry")
        cur = ntos.read_qword(cur)
    end

    return threads
end

local function thread_summary(ethread, layout)
    local kthread = ethread + layout.tcb_off
    local tid = layout.cid_off and ntos.try_read_field_qword("_CLIENT_ID", "UniqueThread", ethread + layout.cid_off)
    local state = ntos.try_read_field_byte("_KTHREAD", "State", kthread)
    local wait_reason = ntos.try_read_field_byte("_KTHREAD", "WaitReason", kthread)
    local start = (layout.start_off and ntos.try_read_qword(ethread + layout.start_off))
        or (layout.win32_off and ntos.try_read_qword(ethread + layout.win32_off))
    return tid, state, wait_reason, start
end

register_command("ethreads",
    "List ETHREADs for a process\n" ..
    "(usage: ethreads <pid|process-name|eprocess-expression>)",
    {"process"},
    function(target)
        if not target then
            ntos.command_usage()
            return
        end

        local eprocess, label = resolve_process(target)
        local threads = list_threads(eprocess)
        local layout = {
            tcb_off = ntos.try_offset_of("_ETHREAD", "Tcb") or 0,
            cid_off = ntos.try_offset_of("_ETHREAD", "Cid"),
            start_off = ntos.try_offset_of("_ETHREAD", "StartAddress"),
            win32_off = ntos.try_offset_of("_ETHREAD", "Win32StartAddress"),
        }

        print(("ethreads for %s @ %s"):format(label, tostring(eprocess)))
        print(("  %-18s %-10s %-18s %-22s %s"):format("ETHREAD", "TID", "State", "WaitReason", "Start"))
        for _, ethread in ipairs(threads) do
            local tid, state, wait_reason, start = thread_summary(ethread, layout)
            local state_s = state and (KTHREAD_STATE[state] or ("0x%x"):format(state)) or "?"
            local wait_s = wait_reason and (WAIT_REASON[wait_reason] or ("0x%x"):format(wait_reason)) or "?"
            local start_s = start and ntos.format_symbol(start) or "?"
            print(("  %-18s %-10s %-18s %-22s %s"):format(
                tostring(ethread), tostring(tid or "?"), state_s, wait_s, start_s))
        end
        if #threads == 0 then
            print("  (none)")
        end
    end)
