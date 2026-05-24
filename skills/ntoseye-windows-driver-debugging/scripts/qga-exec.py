#!/usr/bin/env python3
import argparse
import base64
import json
import subprocess
import sys
import time


def virsh_agent(domain, payload, connect):
    cmd = ["virsh", "-c", connect, "qemu-agent-command", domain, json.dumps(payload)]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or f"virsh exited {proc.returncode}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not parse virsh JSON output: {exc}\n{proc.stdout}") from exc


def decode_field(obj, key):
    value = obj.get(key)
    if not value:
        return ""
    return base64.b64decode(value).decode("utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description="Run a command in a Windows VM through QEMU Guest Agent.")
    parser.add_argument("--domain", default="Win11 Debug target", help="libvirt domain name")
    parser.add_argument("--connect", default="qemu:///system", help="libvirt connection URI")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for process exit")
    parser.add_argument("--interval", type=float, default=0.25, help="poll interval in seconds")
    parser.add_argument("--no-capture", action="store_true", help="do not capture stdout/stderr")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="guest command after --")
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing guest command; use: qga-exec.py -- C:\\\\Windows\\\\System32\\\\cmd.exe /c whoami")

    payload = {
        "execute": "guest-exec",
        "arguments": {
            "path": command[0],
            "arg": command[1:],
            "capture-output": not args.no_capture,
        },
    }
    started = virsh_agent(args.domain, payload, args.connect)
    pid = started["return"]["pid"]

    deadline = time.time() + args.timeout
    status = None
    while time.time() < deadline:
        status = virsh_agent(args.domain, {"execute": "guest-exec-status", "arguments": {"pid": pid}}, args.connect)
        result = status["return"]
        if result.get("exited"):
            out = decode_field(result, "out-data")
            err = decode_field(result, "err-data")
            if out:
                print(out, end="" if out.endswith(("\n", "\r\n")) else "\n")
            if err:
                print(err, end="" if err.endswith(("\n", "\r\n")) else "\n", file=sys.stderr)
            return int(result.get("exitcode", 0))
        time.sleep(args.interval)

    print(f"Timed out waiting for guest PID {pid}", file=sys.stderr)
    if status is not None:
        print(json.dumps(status), file=sys.stderr)
    return 124


if __name__ == "__main__":
    raise SystemExit(main())
