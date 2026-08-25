//! Output renderers for text, JSON, and JSONL.

pub mod json;
pub mod jsonl;
pub mod text;

pub use json::print_json;
pub use jsonl::print_jsonl;
pub use text::{
    render_capabilities, render_cfg, render_diagnostic_descriptors, render_diff, render_disasm,
    render_explain_instruction, render_inspect, render_query, render_validate, render_xrefs,
};
