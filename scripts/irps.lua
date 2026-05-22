-- Discover IRPs linked from process ETHREADs and device CurrentIrp fields

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

local function list_threads(eprocess)
    local head_off = ntos.try_offset_of("_EPROCESS", "ThreadListHead")
    if not head_off then return {} end

    local head = eprocess + head_off
    local cur = ntos.try_read_qword(head)
    local seen = {}
    local threads = {}

    for _ = 1, 4096 do
        if not cur or cur == ntos.addr(0) or cur == head then break end
        local key = tostring(cur)
        if seen[key] then break end
        seen[key] = true
        threads[#threads + 1] = ntos.containing_record(cur, "_ETHREAD", "ThreadListEntry")
        cur = ntos.try_read_qword(cur)
    end

    return threads
end

local function list_thread_irps(ethread)
    local head_off = ntos.try_offset_of("_ETHREAD", "IrpList")
    if not head_off then return {} end

    local head = ethread + head_off
    local cur = ntos.try_read_qword(head)
    local seen = {}
    local irps = {}

    for _ = 1, 256 do
        if not cur or cur == ntos.addr(0) or cur == head then break end
        local key = tostring(cur)
        if seen[key] then break end
        seen[key] = true
        irps[#irps + 1] = ntos.containing_record(cur, "_IRP", "ThreadListEntry")
        cur = ntos.try_read_qword(cur)
    end

    return irps
end

local function plausible_irp(irp)
    local s = ntos.try_read_struct("_IRP", irp)
    if not s then return nil end
    if s.Type and s.Type ~= 6 then return nil end
    if s.Size and (s.Size < ntos.type_size("_IRP") or s.Size > 0x1000) then return nil end
    return s
end

local function print_irp(source, irp, extra)
    local s = plausible_irp(irp)
    if not s then return false end
    local stack_count = s.StackCount or "?"
    local current = s.CurrentLocation or "?"
    print(("  %-18s %-7s stack=%-2s current=%-2s %s"):format(
        tostring(irp), source, tostring(stack_count), tostring(current), extra or ""))
    return true
end

local function matching_processes(filter)
    if not filter then return ntos.ps() end
    if filter:match("^%d+$") then
        local p = ntos.try_process(filter)
        return p and { p } or {}
    end
    return ntos.ps(filter)
end

local function scan_process(p)
    local hits = 0
    local cid_off = ntos.try_offset_of("_ETHREAD", "Cid")
    local tcb_off = ntos.try_offset_of("_ETHREAD", "Tcb") or 0
    for _, ethread in ipairs(list_threads(p.eprocess)) do
        local kthread = ethread + tcb_off
        local tid = cid_off and ntos.try_read_field_qword("_CLIENT_ID", "UniqueThread", ethread + cid_off)
        local state = ntos.try_read_field_byte("_KTHREAD", "State", kthread)
        local wait = ntos.try_read_field_byte("_KTHREAD", "WaitReason", kthread)
        local state_s = state and (KTHREAD_STATE[state] or ("0x%x"):format(state)) or "?"
        local wait_s = wait and (WAIT_REASON[wait] or ("0x%x"):format(wait)) or "?"
        for _, irp in ipairs(list_thread_irps(ethread)) do
            local extra = ("pid=%d tid=%s ethread=%s state=%s wait=%s"):format(
                p.pid, tostring(tid or "?"), tostring(ethread), state_s, wait_s)
            if print_irp("thread", irp, extra) then hits = hits + 1 end
        end
    end
    return hits
end

local function scan_devices(filter)
    local hits = 0
    for _, driver in ipairs(ntos.driver_objects()) do
        local driver_name = driver.name or "?"
        if not filter or driver_name:lower():find(filter, 1, true) then
            local cur = driver.device_object
            local seen = {}
            for _ = 1, 256 do
                if not cur or cur == ntos.addr(0) then break end
                local key = tostring(cur)
                if seen[key] then break end
                seen[key] = true

                local dev = ntos.try_read_struct("_DEVICE_OBJECT", cur)
                if not dev then break end
                if dev.CurrentIrp and dev.CurrentIrp ~= ntos.addr(0) then
                    local extra = ("driver=%s device=%s"):format(driver_name, tostring(cur))
                    if print_irp("device", dev.CurrentIrp, extra) then hits = hits + 1 end
                end
                cur = dev.NextDevice
            end
        end
    end
    return hits
end

register_command("irps",
    "Discover IRPs from ETHREAD IrpList entries and DEVICE_OBJECT CurrentIrp\n" ..
    "(usage: irps [process-filter|driver-filter])",
    {"process"},
    function(filter)
        local needle = filter and filter:lower() or nil
        local total = 0
        print(("  %-18s %-7s %s"):format("IRP", "Source", "Details"))

        for _, p in ipairs(matching_processes(filter)) do
            total = total + scan_process(p)
        end
        if not filter or not filter:match("^%d+$") then
            total = total + scan_devices(needle)
        end

        if total == 0 then
            if filter then
                print(("  no IRPs found for '%s'"):format(filter))
            else
                print("  no IRPs found")
            end
        end
    end)
