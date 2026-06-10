//! The single presentation layer for terminal styling. Domain types (e.g.
//! `VirtAddr`) stay plain; everything that adds color goes through here, so the
//! palette lives in one place and stays consistent. This is also the one spot
//! that would gate `NO_COLOR` / non-TTY handling if we ever want it.

use owo_colors::OwoColorize;
use std::fmt::Display;

use crate::types::VirtAddr;

/// Absolute address: bare 16-digit, bright_white + bold. The canonical way to
/// render any pointer/address; never format a `VirtAddr` with `{:#x}` for
/// display, route it through here so the styling can't drift.
pub fn addr(value: u64) -> String {
    format!("{value:016x}").bright_white().bold().to_string()
}

/// An address, or a muted `unavailable` when null.
pub fn addr_opt(value: VirtAddr) -> String {
    if value.is_zero() {
        muted("unavailable")
    } else {
        addr(value.0)
    }
}

/// A resolved symbol: green name, with any trailing `+0x...` offset dimmed so
/// the eye lands on the name. A raw `0x...` fallback (nothing resolved) renders
/// fully muted.
pub fn symbol(sym: &str) -> String {
    if sym.starts_with("0x") {
        return muted(sym);
    }
    match sym.rfind("+0x") {
        Some(idx) => format!("{}{}", (&sym[..idx]).green(), (&sym[idx..]).bright_black()),
        None => sym.green().to_string(),
    }
}

/// Secondary / de-emphasized text: scan tags, "N more", offsets, raw fallbacks.
pub fn muted(text: &str) -> String {
    text.bright_black().to_string()
}

/// A bold, uncolored label/header (e.g. `break:`, `breakpoint:`, section
/// titles). Color is reserved for content; labels are bold only.
pub fn label(text: &str) -> String {
    text.bold().to_string()
}

/// A breakpoint identifier accent, e.g. `#3` in cyan. Used consistently across
/// every breakpoint message (set/hit/cleared/disabled/enabled).
pub fn bp_id(id: impl Display) -> String {
    format!("#{id}").cyan().to_string()
}
