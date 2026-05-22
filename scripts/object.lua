-- Inspect a Windows executive object header and body

local PTR_SIZE = 8
local HEADER_SIZE = ntos.type_size("_OBJECT_HEADER")
local BODY_OFFSET = ntos.offset_of("_OBJECT_HEADER", "Body")
local NAME_INFO_SIZE = ntos.type_size("_OBJECT_HEADER_NAME_INFO")

local function object_header_from_body(body)
    return body - BODY_OFFSET
end

local function maybe_object_header(addr)
    local h = ntos.try_read_struct("_OBJECT_HEADER", addr)
    if not h then return nil end
    if not ntos.can_read(addr, HEADER_SIZE) then return nil end
    return h
end

local function resolve_header(addr)
    local body_header = object_header_from_body(addr)
    local h = maybe_object_header(body_header)
    if h then return body_header, addr, h, "body" end

    h = maybe_object_header(addr)
    if h then return addr, addr + BODY_OFFSET, h, "header" end
    return nil
end

local function object_type_name(type_obj)
    if not type_obj then return nil end
    local name_off = ntos.try_offset_of("_OBJECT_TYPE", "Name")
    if not name_off then return nil end
    return ntos.try_read_unicode_string(type_obj + name_off)
end

local function object_type_by_index(type_index)
    local table_eval = ntos.try_eval("ObTypeIndexTable")
    if not table_eval or not type_index then return nil, nil end
    local table_addr = ntos.try_read_qword(table_eval)
    if not table_addr then return nil, nil end
    local type_obj = ntos.try_read_qword(table_addr + type_index * PTR_SIZE)
    return type_obj, object_type_name(type_obj)
end

local function object_name(header, mask)
    if not mask or (mask & 0x02) == 0 then return nil, nil end
    local info = header - NAME_INFO_SIZE
    local name_off = ntos.try_offset_of("_OBJECT_HEADER_NAME_INFO", "Name")
    if not name_off then return info, nil end
    return info, ntos.try_read_unicode_string(info + name_off)
end

local function count_number(value)
    if not value then return nil end
    if type(value) == "userdata" then return value:to_int() end
    if type(value) == "number" then return value end
    return nil
end

local function count_string(value)
    local n = count_number(value)
    if n then return tostring(n) end
    if not value then return "?" end
    return tostring(value)
end

local function header_type(h)
    local type_obj, type_name = object_type_by_index(h.TypeIndex)
    return h.TypeIndex, type_obj, type_name
end

register_command("object",
    "Inspect a Windows executive object header/body\n" ..
    "(usage: object <object-expression>)",
    {"symbol"},
    function(expr)
        if not expr then
            ntos.command_usage()
            return
        end

        local target = ntos.eval(expr)
        local header, body, h, mode = resolve_header(target)
        if not header then
            print(("no plausible _OBJECT_HEADER for %s"):format(tostring(target)))
            return
        end

        local type_index, type_obj, type_name = header_type(h)
        local name_info, name = object_name(header, h.InfoMask)

        print(("object %s"):format(tostring(body)))
        print(("  input         : %s (%s)"):format(tostring(target), mode))
        print(("  header        : %s"):format(tostring(header)))
        print(("  pointer count : %s"):format(count_string(h.PointerCount)))
        print(("  handle count  : %s"):format(count_string(h.HandleCount)))
        if type_index then print(("  type index    : 0x%x"):format(type_index)) end
        if type_obj then print(("  type object   : %s"):format(tostring(type_obj))) end
        if type_name then print(("  type name     : %s"):format(type_name)) end
        if h.InfoMask then print(("  info mask     : 0x%x"):format(h.InfoMask)) end
        if name_info then print(("  name info     : %s"):format(tostring(name_info))) end
        if name then print(("  name          : %s"):format(name)) end
    end)
