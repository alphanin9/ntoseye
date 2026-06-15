//! Bake an rpath to the embedded interpreter's library directory so the
//! `python-embed` binary can load `libpython` at runtime even under a sanitized
//! environment (notably `sudo`, which clears `LD_LIBRARY_PATH`). Without this, a
//! non-system Python linkage (e.g. a `pyenv` interpreter whose `libpython` is not
//! on the default loader path) fails to start under `sudo` — the path ntoseye
//! uses for KVM/QEMU access.
//!
//! Gated on `python-embed`: only that binary links `libpython`. The
//! extension-module wheel (`python-extension`) resolves `libpython` at load time
//! from the host process and must NOT carry a build-host rpath.

fn main() {
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");

    // Only the embedded-interpreter binary needs the rpath.
    if std::env::var_os("CARGO_FEATURE_PYTHON_EMBED").is_none() {
        return;
    }

    // Resolve the interpreter the same way PyO3 does (PYO3_PYTHON, else `python3`
    // from PATH), then ask it for its shared-library directory. This tracks the
    // active interpreter automatically, so a pyenv version bump needs no edits.
    let python = std::env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let Ok(output) = std::process::Command::new(&python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_config_var('LIBDIR') or '')",
        ])
        .output()
    else {
        return;
    };

    let libdir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !libdir.is_empty() {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
    }
}
