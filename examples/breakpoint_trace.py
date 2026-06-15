#!/usr/bin/env python3
"""Set a breakpoint, run until it hits, and inspect context.

Requires an execution-control backend (`gdb` or `kd`); the passive `memory`
backend cannot set breakpoints or control execution.

    python3 breakpoint_trace.py --backend gdb --connect 127.0.0.1:1234
    python3 breakpoint_trace.py --symbol nt!KeWaitForSingleObject --hits 5
"""

import argparse
import ntoseye

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="gdb", choices=["gdb", "kd"])
    ap.add_argument("--connect", default=None)
    ap.add_argument("--symbol", default="nt!KeWaitForSingleObject")
    ap.add_argument("--hits", type=int, default=3, help="how many times to run-to-hit")
    ap.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="max time to wait for each stop; use 0 to wait indefinitely",
    )
    args = ap.parse_args()

    dbg = ntoseye.attach(backend=args.backend, connect=args.connect)
    dbg.interrupt()

    addr = dbg.eval(args.symbol)
    bid = dbg.set_breakpoint(addr)
    print(f"breakpoint {bid} at {args.symbol} = {addr:#x}\n")

    vm_running = False
    leave_running = True
    try:
        hits = 0
        timeout = None if args.timeout_ms == 0 else args.timeout_ms
        while hits < args.hits:
            stop = dbg.run(timeout_ms=timeout)
            stop_kind = stop.get("stop")
            vm_running = stop_kind == "running"
            if vm_running:
                print(f"timeout waiting for a stop after {args.timeout_ms}ms")
                break

            rip = stop.get("rip", 0)
            sym = stop.get("symbol") or dbg.closest_symbol(rip)
            if stop_kind != "breakpoint" or stop.get("breakpoint") != bid:
                print(
                    f"stop: {stop_kind}  rip={rip:#x} ({sym})  "
                    f"bp={stop.get('breakpoint')}  exception={stop.get('exception_code')}"
                )
                if stop_kind in {"bugcheck", "target_reloaded"}:
                    leave_running = False
                    break
                continue

            hits += 1
            regs = dbg.registers()
            print(
                f"hit #{hits}: rip={rip:#x} ({sym})  "
                f"bp={stop.get('breakpoint')}  rcx={regs.get('rcx', 0):#x}"
            )
            # show the next two instructions at the hit
            for ip, _hex, asm, comment in dbg.disassemble(rip, 2):
                c = f"   ; {comment}" if comment else ""
                print(f"    {ip:#x}: {asm}{c}")
    finally:
        if vm_running:
            dbg.interrupt()
        try:
            dbg.clear_breakpoint(bid)
            cleared = True
        except RuntimeError as exc:
            cleared = False
            print(f"\nbreakpoint cleanup skipped: {exc}")

        if leave_running:
            dbg.cont()
            if cleared:
                print("\nbreakpoint cleared, VM resumed.")
            else:
                print("\nVM resumed.")
        elif cleared:
            print("\nbreakpoint cleared, VM left halted.")


if __name__ == "__main__":
    main()
