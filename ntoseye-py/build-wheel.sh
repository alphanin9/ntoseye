#!/usr/bin/env bash
# Produces a manylinux_2_17 wheel via zig (installs on any non-EOL distro, not
# just this build host's glibc) into a clean dist/, then runs `twine check` and
# an import test in a throwaway venv.
# Self-contained: if no virtualenv is active it provisions a local .venv with the
# build tools, so a bare checkout works and `twine` is always present.
set -euo pipefail

cd "$(dirname "$0")"

# Use the active virtualenv if there is one; otherwise fall back to a local .venv
# (created on first run) so we never touch the system Python.
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    if [[ ! -d .venv ]]; then
        echo "==> creating .venv"
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

echo "==> ensuring build tools (maturin, ziglang, twine)"
python -m pip install --quiet maturin ziglang twine

echo "==> building manylinux_2_17 wheel"
rm -rf dist
maturin develop --release
maturin build --release --zig --compatibility manylinux_2_17 --out dist

echo "==> twine check"
twine check dist/*

# Import-test in a throwaway venv (not the build one): proves the wheel actually
# installs and re-exports its surface, which twine check never touches.
echo "==> import test"
smoke_venv="$(mktemp -d)"
trap 'rm -rf "$smoke_venv"' EXIT
python3 -m venv "$smoke_venv"
"$smoke_venv/bin/pip" install --quiet --upgrade pip
"$smoke_venv/bin/pip" install --quiet dist/*.whl
"$smoke_venv/bin/python" - <<'PY'
import ntoseye
print("version:", ntoseye.__version__)
assert hasattr(ntoseye, "attach"), "attach missing"
assert hasattr(ntoseye, "Debugger"), "Debugger missing"
for m in ("backtrace", "pte_walk", "read_struct", "disassemble"):
    assert hasattr(ntoseye.Debugger, m), f"Debugger.{m} missing"
print("import + surface OK")
PY

echo
echo "Wheel ready in dist/:"
ls -1 dist/*.whl
echo
echo "Publish with:  twine upload dist/*"
