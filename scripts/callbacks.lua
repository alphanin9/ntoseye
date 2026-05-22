-- Enumerate common kernel notification callbacks

local PTR_SIZE = 8
local MAX_NOTIFY = 64

local CALLBACK_SETS = {
    { label = "process", symbol = "PspCreateProcessNotifyRoutine" },
    { label = "thread",  symbol = "PspCreateThreadNotifyRoutine" },
    { label = "image",   symbol = "PspLoadImageNotifyRoutine" },
}

local function clear_fast_ref(addr)
    return addr & ~0xf
end

local function plausible_callback_function(addr)
    return addr and ntos.is_kernel_address(addr)
end

local function read_callback_block(block)
    local function_off = ntos.try_offset_of("_EX_CALLBACK_ROUTINE_BLOCK", "Function") or PTR_SIZE
    local context_off = ntos.try_offset_of("_EX_CALLBACK_ROUTINE_BLOCK", "Context") or (PTR_SIZE * 2)

    local fn = ntos.try_read_qword(block + function_off)
    local ctx = ntos.try_read_qword(block + context_off)
    if plausible_callback_function(fn) then
        return fn, ctx
    end

    -- Some public PDBs describe this opaque block poorly, the stable layout is:
    -- EX_RUNDOWN_REF, callback function, context
    return ntos.try_read_qword(block + PTR_SIZE), ntos.try_read_qword(block + PTR_SIZE * 2)
end

local function read_ex_callback_entry(entry)
    local raw = ntos.try_read_qword(entry)
    if not raw or raw == ntos.addr(0) then return nil end

    local block = clear_fast_ref(raw)
    if block == ntos.addr(0) then return nil end

    local fn, ctx = read_callback_block(block)
    if not plausible_callback_function(fn) then return nil end
    return raw, block, fn, ctx
end

local function print_notify_array(label, symbol, filter)
    local base = ntos.try_eval(symbol)
    if not base then return 0 end

    local ex_callback_size = ntos.try_type_size("_EX_CALLBACK") or PTR_SIZE
    if ex_callback_size < PTR_SIZE or ex_callback_size > 0x40 then
        ex_callback_size = PTR_SIZE
    end

    local printed = 0
    for i = 0, MAX_NOTIFY - 1 do
        local entry = base + i * ex_callback_size
        local raw, block, fn, ctx = read_ex_callback_entry(entry)
        if fn then
            local target = ntos.format_symbol(fn)
            if not filter or target:lower():find(filter, 1, true) then
                if printed == 0 then
                    print(("%s callbacks (%s @ %s):"):format(label, symbol, tostring(base)))
                end
                print(("  [%02d] fn=%s  block=%s  raw=%s  ctx=%s"):format(
                    i, target, tostring(block), tostring(raw), tostring(ctx or ntos.addr(0))))
                printed = printed + 1
            end
        end
    end

    return printed
end

register_command("callbacks",
    "Enumerate process/thread/image notification callbacks\n" ..
    "(usage: callbacks [symbol-filter])",
    {"symbol"},
    function(filter)
        local needle = filter and filter:lower() or nil
        local total = 0

        for _, set in ipairs(CALLBACK_SETS) do
            total = total + print_notify_array(set.label, set.symbol, needle)
        end

        if total == 0 then
            if needle then
                print(("no callbacks matching '%s'"):format(filter))
            else
                print("no registered callbacks found")
            end
        end
    end)
