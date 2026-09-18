//! Deterministic JSON renderer.

use serde::Serialize;
use std::io;

/// Print serialized JSON value to writer.
pub fn print_json<T: Serialize, W: io::Write>(value: &T, writer: &mut W) -> io::Result<()> {
    if let Ok(json_str) = serde_json::to_string_pretty(value) {
        writeln!(writer, "{json_str}")?;
    }
    Ok(())
}
