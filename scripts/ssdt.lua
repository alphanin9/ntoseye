-- Dump the x64 system service descriptor table and, when available, the
-- win32k entries from KeServiceDescriptorTableShadow
--
-- Each entry is a signed 32-bit value encoding an offset relative to the
-- table base: target = table_base + (entry >> 4). The low 4 bits hold the
-- number of arguments spilled to the stack (max(0, total_args - 4) on x64)

local function dump_table(label, table_base, limit, expected_module)
    if limit <= 0 or limit > 0x4000 then
        print(("%s: implausible limit=%d, aborting"):format(label, limit))
        return
    end

    print(("%s: base=%s limit=%d"):format(label, tostring(table_base), limit))

    local hooks = 0
    for i = 0, limit - 1 do
        local raw = ntos.read_dword(table_base + i * 4)
        local spilled_args = raw & 0xf
        if raw >= 0x80000000 then raw = raw - 0x100000000 end
        local target = table_base + (raw // 16)

        local sym = ntos.try_closest_symbol_any(target)
        local module = sym and sym.module or nil
        local display
        if not sym then
            display = tostring(target)
        elseif sym.offset == 0 then
            display = ("%s!%s"):format(module, sym.name)
        else
            display = ("%s!%s+0x%x"):format(module, sym.name, sym.offset)
        end

        local hooked = module and expected
            and not module:lower():find(expected, 1, true)
        local mark = hooked and "  [HOOK]" or ""
        if hooked then hooks = hooks + 1 end

        -- spilled_args column omitted; its the stack-spill count, not the
        -- total arg count, so it conflates all 0-4-arg syscalls into 0.
        -- print(("  [%4d] %-50s spilled_args=%d%s"):format(i, display, spilled_args, mark))
        local _ = spilled_args
        print(("  [%4d] %-50s%s"):format(i, display, mark))
    end

    if hooks > 0 then
        print(("  %d hook(s) detected"):format(hooks))
    end
end

local function dump_shadow()
    local sdt = ntos.try_eval("KeServiceDescriptorTableShadow")
    if not sdt then
        print("shadow SSDT: KeServiceDescriptorTableShadow unavailable in symbols")
        return
    end

    -- KSERVICE_TABLE_DESCRIPTOR layout (x64): Base, Count, Limit, Number
    local desc_size = ntos.try_type_size("_KSERVICE_TABLE_DESCRIPTOR") or 0x20
    local base_off = ntos.try_offset_of("_KSERVICE_TABLE_DESCRIPTOR", "Base") or 0
    local limit_off = ntos.try_offset_of("_KSERVICE_TABLE_DESCRIPTOR", "Limit") or 0x10

    -- [0] = kernel SSDT (same as KiServiceTable), [1] = win32k
    local win32k = sdt + desc_size
    local base = ntos.read_qword(win32k + base_off)
    if base == ntos.addr(0) then
        print("shadow SSDT: win32k descriptor not initialized (no GUI threads yet?)")
        return
    end
    local limit = ntos.read_dword(win32k + limit_off)
    dump_table("shadow SSDT (win32k)", base, limit, "win32k")
end

register_command("ssdt", "Dump the SSDT and shadow SSDT.\n(usage: ssdt)", function()
    dump_table("SSDT", ntos.eval("KiServiceTable"),
        ntos.read_dword(ntos.eval("KiServiceLimit")), "nt")
    print()
    dump_shadow()
end)
