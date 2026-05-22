-- Inspect an ETHREAD/KTHREAD

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

local function print_ptr(label, value)
    if value then print(("  %-14s: %s"):format(label, tostring(value))) end
end

local function print_symbol(label, value)
    if value then print(("  %-14s: %s"):format(label, ntos.format_symbol(value))) end
end

local function thread_irps(ethread)
    local head_off = ntos.try_offset_of("_ETHREAD", "IrpList")
    if not head_off then return nil end

    local head = ethread + head_off
    local cur = ntos.try_read_qword(head)
    if not cur or cur == ntos.addr(0) or cur == head then return {} end

    local seen = {}
    local out = {}
    for _ = 1, 256 do
        if cur == ntos.addr(0) or cur == head then break end
        local key = tostring(cur)
        if seen[key] then break end
        seen[key] = true
        out[#out + 1] = ntos.containing_record(cur, "_IRP", "ThreadListEntry")
        cur = ntos.try_read_qword(cur)
        if not cur then break end
    end
    return out
end

register_command("ethread",
    "Inspect an ETHREAD/KTHREAD\n" ..
    "(usage: ethread <ethread-expression>)",
    {"symbol"},
    function(expr)
        if not expr then
            ntos.command_usage()
            return
        end

        local ethread = ntos.eval(expr)
        local e = ntos.try_read_struct("_ETHREAD", ethread)
        if not e then
            print(("%s is not a readable _ETHREAD"):format(tostring(ethread)))
            return
        end

        local tcb_off = ntos.try_offset_of("_ETHREAD", "Tcb") or 0
        local kthread = ethread + tcb_off
        local k = ntos.try_read_struct("_KTHREAD", kthread)

        print(("ethread %s"):format(tostring(ethread)))
        if tcb_off ~= 0 then print(("  kthread       : %s"):format(tostring(kthread))) end

        local cid_off = ntos.try_offset_of("_ETHREAD", "Cid")
        if cid_off then
            local pid = ntos.try_read_field_qword("_CLIENT_ID", "UniqueProcess", ethread + cid_off)
            local tid = ntos.try_read_field_qword("_CLIENT_ID", "UniqueThread", ethread + cid_off)
            print(("  cid           : pid=%s tid=%s"):format(tostring(pid), tostring(tid)))
        end

        print_ptr("process", e.ThreadsProcess)
        print_symbol("start", e.StartAddress)
        print_symbol("win32 start", e.Win32StartAddress)
        print_ptr("teb", e.Teb)

        local irps = thread_irps(ethread)
        if irps then
            if #irps == 0 then
                print("  irp list      : empty")
            else
                print(("  irp list      : %d pending"):format(#irps))
                for i, irp in ipairs(irps) do
                    print(("    [%d] %s"):format(i, tostring(irp)))
                end
            end
        end

        if k then
            if k.State then print(("  state         : %s (0x%x)"):format(KTHREAD_STATE[k.State] or "?", k.State)) end
            if k.WaitReason then print(("  wait reason   : %s (0x%x)"):format(WAIT_REASON[k.WaitReason] or "?", k.WaitReason)) end
            if k.Priority then print(("  priority      : %d"):format(k.Priority)) end
            if k.BasePriority then print(("  base priority : %d"):format(k.BasePriority)) end
            if k.WaitIrql then print(("  wait irql     : %d"):format(k.WaitIrql)) end
            if k.KernelStackResident then print(("  stack resident: %s"):format(k.KernelStackResident ~= 0 and "yes" or "no")) end
            print_ptr("kernel stack", k.KernelStack)
            print_ptr("stack base", k.StackBase)
            print_ptr("stack limit", k.StackLimit)
            print_ptr("trap frame", k.TrapFrame)
        else
            print("  kthread       : unreadable")
        end
    end)
