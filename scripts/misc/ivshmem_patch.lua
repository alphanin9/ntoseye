-- Patch the Windows IVSHMEM driver's ioctl_request_mmap to allow multiple
-- concurrent handles to the shared memory buffer. The unpatched driver fails
-- with STATUS_DEVICE_ALREADY_ATTACHED if DeviceContext->shmemMap is non-null,
-- so only one process can hold a mapping at a time; flipping the je over the
-- early-return into a jmp skips the check

local PATTERN     = "\x48\x83\x79\x20\x00\x74\x0a"
local REPLACEMENT = "\x48\x83\x79\x20\x00\xeb\x0a"

register_command("ivshmem_patch", "Patch IVSHMEM driver to skip the shared-memory size check.\n(usage: ivshmem_patch)", function()
    local m = ntos.try_find_kernel_module("ivshmem")
    if not m then
        print("ivshmem module not loaded")
        return
    end

    print(("ivshmem: %s  base=%s  size=0x%x"):format(m.name, tostring(m.base), m.size))

    local match = ntos.search_first(m.base, m.size, PATTERN)
    if not match then
        print("pattern not found; driver may already be patched or be a different build")
        return
    end

    ntos.write_bytes(match, REPLACEMENT)
    print(("patched %d bytes at %s"):format(#REPLACEMENT, tostring(match)))
end)
