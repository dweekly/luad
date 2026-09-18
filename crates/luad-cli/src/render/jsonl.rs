//! Streaming JSONL renderer.

use serde::Serialize;
use std::io;

/// Print serialized objects line-by-line in JSON Lines format.
pub fn print_jsonl<T: Serialize, W: io::Write>(items: &[T], writer: &mut W) -> io::Result<()> {
    for item in items {
        if let Ok(line) = serde_json::to_string(item) {
            writeln!(writer, "{line}")?;
        }
    }
    Ok(())
}
