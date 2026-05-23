-- Inspect a DEVICE_OBJECT and its stack links

local function is_device_object(dev)
    return dev.Type == 3 and dev.Size and dev.Size >= ntos.type_size("_DEVICE_OBJECT")
end

local function read_device_object(addr)
    local dev = ntos.try_read_struct("_DEVICE_OBJECT", addr)
    if dev and is_device_object(dev) then return addr, dev, "direct" end

    local ptr = ntos.try_read_qword(addr)
    if ptr and ptr ~= ntos.addr(0) then
        dev = ntos.try_read_struct("_DEVICE_OBJECT", ptr)
        if dev and is_device_object(dev) then return ptr, dev, "pointer" end
    end

    if dev then return nil, dev, "direct" end
    return nil, nil, nil
end

local function print_device(addr, label)
    local real_addr, dev = read_device_object(addr)
    if not real_addr then
        print(("  %s: %s (not a DEVICE_OBJECT or pointer to one)"):format(label, tostring(addr)))
        if dev and dev.Type then print(("    Type: 0x%x (expected 0x3)"):format(dev.Type)) end
        if dev and dev.Size then print(("    Size: 0x%x"):format(dev.Size)) end
        return nil
    end
    addr = real_addr
    print(("  %s: %s"):format(label, tostring(addr)))
    print(("    type            : 0x%x"):format(dev.DeviceType or 0))
    print(("    flags           : 0x%x"):format(dev.Flags or 0))
    print(("    characteristics : 0x%x"):format(dev.Characteristics or 0))
    print(("    driver object   : %s"):format(tostring(dev.DriverObject)))
    print(("    attached device : %s"):format(tostring(dev.AttachedDevice)))
    print(("    next device     : %s"):format(tostring(dev.NextDevice)))
    print(("    current irp     : %s"):format(tostring(dev.CurrentIrp)))
    print(("    device extension: %s"):format(tostring(dev.DeviceExtension)))
    return dev
end

local function print_attached_stack(first)
    if not first or first == ntos.addr(0) then return end
    print("attached stack:")

    local seen = {}
    local cur = first
    for i = 1, 64 do
        local key = tostring(cur)
        if seen[key] then
            print(("  #%d %s (cycle)"):format(i, key))
            return
        end
        seen[key] = true

        local dev = ntos.try_read_struct("_DEVICE_OBJECT", cur)
        if not dev then
            print(("  #%d %s (unreadable)"):format(i, tostring(cur)))
            return
        end

        local driver = dev.DriverObject or ntos.addr(0)
        local driver_name = ntos.format_symbol(driver)
        print(("  #%d %s driver=%s type=0x%x flags=0x%x"):format(
            i,
            tostring(cur),
            driver_name,
            dev.DeviceType or 0,
            dev.Flags or 0))

        if not dev.AttachedDevice or dev.AttachedDevice == ntos.addr(0) then return end
        cur = dev.AttachedDevice
    end
    print("  (stopped after 64 attached devices)")
end

register_command("devobj",
    "Inspect a DEVICE_OBJECT and its attached stack\n" ..
    "(usage: devobj <device-object-expression-or-pointer-symbol>)",
    {"symbol"},
    function(expr)
        if not expr then
            ntos.command_usage()
            return
        end

        local addr = ntos.eval(expr)
        print(("device object %s"):format(tostring(addr)))
        local dev = print_device(addr, "device")
        if not dev then return end
        print_attached_stack(dev.AttachedDevice)
    end)
