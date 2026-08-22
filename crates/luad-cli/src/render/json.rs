//! Deterministic JSON renderer.

use serde::Serialize;

/// Print serialized JSON value to stdout.
pub fn print_json<T: Serialize>(value: &T) {
    if let Ok(json_str) = serde_json::to_string_pretty(value) {
        println!("{json_str}");
    }
}
