-- Inspect an I/O request packet and its current stack location

local IRP_MJ = {
    [0x00] = "CREATE",
    [0x01] = "CREATE_NAMED_PIPE",
    [0x02] = "CLOSE",
    [0x03] = "READ",
    [0x04] = "WRITE",
    [0x05] = "QUERY_INFORMATION",
    [0x06] = "SET_INFORMATION",
    [0x07] = "QUERY_EA",
    [0x08] = "SET_EA",
    [0x09] = "FLUSH_BUFFERS",
    [0x0a] = "QUERY_VOLUME_INFORMATION",
    [0x0b] = "SET_VOLUME_INFORMATION",
    [0x0c] = "DIRECTORY_CONTROL",
    [0x0d] = "FILE_SYSTEM_CONTROL",
    [0x0e] = "DEVICE_CONTROL",
    [0x0f] = "INTERNAL_DEVICE_CONTROL",
    [0x10] = "SHUTDOWN",
    [0x11] = "LOCK_CONTROL",
    [0x12] = "CLEANUP",
    [0x13] = "CREATE_MAILSLOT",
    [0x14] = "QUERY_SECURITY",
    [0x15] = "SET_SECURITY",
    [0x16] = "POWER",
    [0x17] = "SYSTEM_CONTROL",
    [0x18] = "DEVICE_CHANGE",
    [0x19] = "QUERY_QUOTA",
    [0x1a] = "SET_QUOTA",
    [0x1b] = "PNP",
}

local function read_iostack(addr)
    local ios = ntos.try_read_struct("_IO_STACK_LOCATION", addr)
    if not ios then return nil end
    print(("  current stack : %s"):format(tostring(addr)))
    if ios.MajorFunction then
        print(("    major       : IRP_MJ_%s (0x%x)"):format(IRP_MJ[ios.MajorFunction] or "?", ios.MajorFunction))
    end
    if ios.MinorFunction then print(("    minor       : 0x%x"):format(ios.MinorFunction)) end
    if ios.DeviceObject then print(("    device      : %s"):format(tostring(ios.DeviceObject))) end
    if ios.FileObject then print(("    file        : %s"):format(tostring(ios.FileObject))) end
    if ios.CompletionRoutine then print(("    completion  : %s"):format(ntos.format_symbol(ios.CompletionRoutine))) end
    if ios.Context then print(("    context     : %s"):format(tostring(ios.Context))) end
    return ios
end

register_command("irp",
    "Inspect an IRP and its current IO_STACK_LOCATION\n" ..
    "(usage: irp <irp-expression>)",
    {"symbol"},
    function(expr)
        if not expr then
            ntos.command_usage()
            return
        end

        local addr = ntos.eval(expr)
        local irp = ntos.try_read_struct("_IRP", addr)
        if not irp then
            print(("%s is not a readable _IRP"):format(tostring(addr)))
            return
        end

        print(("irp %s"):format(tostring(addr)))
        if irp.Type then print(("  type          : 0x%x"):format(irp.Type)) end
        if irp.Size then print(("  size          : 0x%x"):format(irp.Size)) end
        if irp.StackCount then print(("  stack count   : %d"):format(irp.StackCount)) end
        if irp.CurrentLocation then print(("  current loc   : %d"):format(irp.CurrentLocation)) end
        if irp.PendingReturned then print(("  pending       : %s"):format(irp.PendingReturned ~= 0 and "yes" or "no")) end
        if irp.RequestorMode then print(("  requestor mode: %s (0x%x)"):format(irp.RequestorMode == 0 and "KernelMode" or "UserMode", irp.RequestorMode)) end
        local io_status_off = ntos.try_offset_of("_IRP", "IoStatus")
        local status = io_status_off
            and ntos.try_read_field_dword("_IO_STATUS_BLOCK", "Status", addr + io_status_off)
        if status then print(("  io status     : 0x%x"):format(status)) end
        if irp.UserEvent then print(("  user event    : %s"):format(tostring(irp.UserEvent))) end
        if irp.UserBuffer then print(("  user buffer   : %s"):format(tostring(irp.UserBuffer))) end
        if irp.MdlAddress then print(("  mdl           : %s"):format(tostring(irp.MdlAddress))) end
        if irp.Thread then print(("  thread        : %s"):format(tostring(irp.Thread))) end

        local irp_size = ntos.try_type_size("_IRP")
        local stack_size = ntos.try_type_size("_IO_STACK_LOCATION")
        local current = irp.CurrentLocation
        if current and current > 0 and current <= 0x40 and irp_size and stack_size then
            read_iostack(addr + irp_size + (current - 1) * stack_size)
        else
            print("  current stack : unavailable")
        end
    end)
