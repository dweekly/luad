//! Streaming JSONL renderer.

use serde::Serialize;

/// Print serialized objects line-by-line in JSON Lines format.
pub fn print_jsonl<T: Serialize>(items: &[T]) {
    for item in items {
        if let Ok(line) = serde_json::to_string(item) {
            println!("{line}");
        }
    }
}
