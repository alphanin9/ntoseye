//! Backend-neutral inspection helpers shared by the REPL and the agent.
//!
//! Each helper extracts a structured view of guest state (descriptor tables,
//! pool blocks, local symbol loading). Frontends own their own formatting: the
//! REPL renders tables/text, the agent serializes JSON.

pub mod descriptors;
pub mod local_symbols;
pub mod pool;
