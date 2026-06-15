# ntoseye (Python SDK)

Drive the [ntoseye](https://github.com/dmaivel/ntoseye) Windows kernel debugger
from Python.

## Install

```sh
pip install ntoseye
```

Or build from source into a virtualenv with maturin:

```sh
cd ntoseye-py
python3 -m venv .venv
source .venv/bin/activate
maturin develop --release
```

Or build a wheel and install it:

```sh
cd ntoseye-py
maturin build --release --out dist
pip install dist/ntoseye-*.whl
```

## Releasing (portable wheel)

A plain `maturin build` tags the wheel against the build host's glibc, so on a rolling-release distro it can demand a glibc newer than most users have. Build against an old glibc floor with [zig](https://www.maturin.rs/distribution#cross-compile-using-zig) so the wheel installs everywhere.

Run `./build-wheel.sh` to do it in one step (it provisions a local `.venv` with the build tools if no virtualenv is active, builds into a clean `dist/`, and runs `twine check`). The equivalent manual steps:

```sh
pip install ziglang
cd ntoseye-py
rm -rf dist
maturin build --release --zig --compatibility manylinux_2_17 --out dist
```

```sh
twine check dist/*
twine upload dist/*
```