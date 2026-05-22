-- Inspect a DRIVER_OBJECT and its device chain

local PTR_SIZE = 8
local MAJOR_FUNCTION_OFFSET = ntos.offset_of("_DRIVER_OBJECT", "MajorFunction")

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

local function is_driver_object(drv)
    return drv.Type == 4 and drv.Size and drv.Size >= MAJOR_FUNCTION_OFFSET + 28 * PTR_SIZE
end

local function read_driver_object(addr)
    local drv = ntos.try_read_struct("_DRIVER_OBJECT", addr)
    if drv and is_driver_object(drv) then return addr, drv, "direct" end

    local ptr = ntos.try_read_qword(addr)
    if ptr and ptr ~= ntos.addr(0) then
        drv = ntos.try_read_struct("_DRIVER_OBJECT", ptr)
        if drv and is_driver_object(drv) then return ptr, drv, "pointer" end
    end

    if drv then return nil, drv, "direct" end
    return nil, nil, nil
end

local function resolve_driver_input(expr)
    local value = ntos.try_eval(expr)
    if value then return value end

    local driver = ntos.try_find_driver_object(expr)
    if driver then return driver.object end

    return nil
end

local function print_dispatch_table(driver)
    local base = driver + MAJOR_FUNCTION_OFFSET
    print("  dispatch table:")
    for i = 0, 0x1b do
        local fn = ntos.read_qword(base + i * PTR_SIZE)
        local name = IRP_MJ[i] or ("0x%x"):format(i)
        print(("    IRP_MJ_%-28s %s"):format(name, ntos.format_symbol(fn)))
    end
end

local function print_devices(first)
    print("  devices:")
    if not first or first == ntos.addr(0) then
        print("    (none)")
        return
    end

    local seen = {}
    local cur = first
    for _ = 1, 128 do
        local key = tostring(cur)
        if seen[key] then
            print(("    %s (cycle)"):format(key))
            return
        end
        seen[key] = true

        local dev = ntos.try_read_struct("_DEVICE_OBJECT", cur)
        if not dev then
            print(("    %s (unreadable)"):format(tostring(cur)))
            return
        end

        local attached = dev.AttachedDevice or ntos.addr(0)
        local next_dev = dev.NextDevice or ntos.addr(0)
        print(("    %s type=0x%x flags=0x%x characteristics=0x%x attached=%s next=%s"):format(
            tostring(cur),
            dev.DeviceType or 0,
            dev.Flags or 0,
            dev.Characteristics or 0,
            tostring(attached),
            tostring(next_dev)))

        if next_dev == ntos.addr(0) then return end
        cur = next_dev
    end
    print("    (stopped after 128 devices)")
end

register_command("drvobj",
    "Inspect a DRIVER_OBJECT and its device chain\n" ..
    "(usage: drvobj <driver-object-expression-or-name>)",
    {"driver"},
    function(expr)
        if not expr then
            ntos.command_usage()
            return
        end

        local input = resolve_driver_input(expr)
        if not input then
            print(("unknown driver object expression or name: %s"):format(expr))
            return
        end
        local addr, drv, mode = read_driver_object(input)
        if not addr then
            print(("%s does not look like a DRIVER_OBJECT or pointer to one"):format(tostring(input)))
            if drv and drv.Type then print(("  Type: 0x%x (expected 0x4)"):format(drv.Type)) end
            if drv and drv.Size then print(("  Size: 0x%x"):format(drv.Size)) end
            return
        end
        local name = ntos.try_read_unicode_string(addr + ntos.offset_of("_DRIVER_OBJECT", "DriverName"))

        print(("driver object %s (%s)"):format(tostring(addr), mode))
        if name then print(("  name          : %s"):format(name)) end
        print(("  driver start  : %s"):format(tostring(drv.DriverStart)))
        print(("  driver size   : 0x%x"):format(drv.DriverSize or 0))
        print(("  driver section: %s"):format(tostring(drv.DriverSection)))
        print(("  driver unload : %s"):format(ntos.format_symbol(drv.DriverUnload or ntos.addr(0))))
        print_devices(drv.DeviceObject)
        print_dispatch_table(addr)
    end)
