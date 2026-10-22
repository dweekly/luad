//! Positional comparison of decoded chunk content, never behavioral equivalence.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::ProtoPath;
use luad_core::model::{Chunk, ConstantValue, LuaString, Prototype};
use luad_dialect_lua51::roles::discover_roles_lua51;

/// Difference in an instruction slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InstructionDiff {
    /// Program counter.
    pub pc: usize,
    /// Bounded representation in first (old) chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// Bounded representation in second (new) chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// Differences identified within a matching positional prototype path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProtoDiff {
    /// Positional prototype path.
    pub path: ProtoPath,
    /// Prototype metadata changes, including selected debug content.
    pub header_diffs: Vec<String>,
    /// Constant changes.
    pub constant_diffs: Vec<String>,
    /// Upvalue changes.
    pub upvalue_diffs: Vec<String>,
    /// Instruction changes.
    pub instruction_diffs: Vec<InstructionDiff>,
}

/// Complete decoded-content difference report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkDiff {
    /// Old input identity (not compared content).
    pub old_sha256: String,
    /// New input identity (not compared content).
    pub new_sha256: String,
    /// Differences in chunk header, interpretation, or trailing content.
    pub header_diffs: Vec<String>,
    /// Differences across prototypes.
    pub proto_diffs: Vec<ProtoDiff>,
    /// No differences in compared content under the selected options.
    /// This does not assert runtime or behavioral equivalence.
    pub is_identical: bool,
}

/// Compare parsed, bounded chunks by position, without cross-build alignment.
///
/// Both modes preserve all physical instruction bits. Semantic mode adds decoded
/// fields and physical roles rather than comparing explanatory prose. It deliberately
/// does not discard unused fields or claim cross-dialect behavioral normalization.
/// Constants are compared once per table slot, without cloning payloads per use.
/// Debug exclusion covers names, lines, and scopes; provenance and derived display
/// strings/IDs are never content. Callers remain responsible for parser bounds.
#[must_use]
pub fn diff_chunks(old: &Chunk, new: &Chunk, semantic: bool, ignore_debug: bool) -> ChunkDiff {
    let mut header_diffs = Vec::new();
    macro_rules! field {
        ($name:ident) => {
            changed(
                &mut header_diffs,
                stringify!($name),
                &old.header.$name,
                &new.header.$name,
            );
        };
    }
    changed(&mut header_diffs, "dialect", &old.dialect, &new.dialect);
    field!(signature);
    field!(version);
    field!(format);
    field!(luac_data);
    field!(instruction_size);
    field!(lua_integer_size);
    field!(sizeof_sizet);
    field!(lua_number_size);
    field!(luac_int);
    changed(
        &mut header_diffs,
        "luac_num",
        &old.header.luac_num.to_bits(),
        &new.header.luac_num.to_bits(),
    );
    // Selection mode, parser mode and detection prose describe the invocation,
    // not the artifact. The validated interpretation still determines its meaning.
    let old_i = interpretation(old);
    let new_i = interpretation(new);
    changed(
        &mut header_diffs,
        "resolved interpretation/layout",
        &old_i,
        &new_i,
    );
    changed(
        &mut header_diffs,
        "trailing bytes",
        &old.trailing_bytes,
        &new.trailing_bytes,
    );

    let mut proto_diffs = Vec::new();
    let mut pending = vec![(&old.main_proto, &new.main_proto, ProtoPath::root())];
    while let Some((a, b, path)) = pending.pop() {
        let diff = diff_prototype(
            &old.dialect,
            a,
            &new.dialect,
            b,
            path.clone(),
            semantic,
            ignore_debug,
        );
        if !diff.header_diffs.is_empty()
            || !diff.constant_diffs.is_empty()
            || !diff.upvalue_diffs.is_empty()
            || !diff.instruction_diffs.is_empty()
        {
            proto_diffs.push(diff);
        }
        // A parent count difference records whole child additions/removals. Never
        // dump an unmatched subtree or trust its provenance path as an identity.
        for i in (0..a.protos.len().min(b.protos.len())).rev() {
            pending.push((&a.protos[i], &b.protos[i], path.child(i)));
        }
    }
    ChunkDiff {
        old_sha256: old.sha256.clone(),
        new_sha256: new.sha256.clone(),
        is_identical: header_diffs.is_empty() && proto_diffs.is_empty(),
        header_diffs,
        proto_diffs,
    }
}

#[derive(PartialEq, Eq)]
struct InterpretationContent<'a> {
    base: &'a str,
    patch: Option<&'a str>,
    profile: &'a str,
    version: Option<&'a str>,
    layout: Option<&'a str>,
}

fn interpretation(chunk: &Chunk) -> Option<InterpretationContent<'_>> {
    chunk
        .interpretation
        .as_ref()
        .map(|i| InterpretationContent {
            base: &i.base_dialect,
            patch: i.patch_or_oracle_version.as_deref(),
            profile: &i.profile,
            version: i.profile_version_or_hash.as_deref(),
            layout: i.validated_layout.as_deref(),
        })
}

fn changed<T: PartialEq + ?Sized>(out: &mut Vec<String>, field: &str, a: &T, b: &T) {
    if a != b {
        out.push(format!("{field} changed"));
    }
}

fn bytes(s: &Option<LuaString>) -> Option<&[u8]> {
    s.as_ref().map(|s| s.raw_bytes.as_slice())
}

fn diff_prototype(
    old_dialect: &str,
    a: &Prototype,
    new_dialect: &str,
    b: &Prototype,
    path: ProtoPath,
    semantic: bool,
    ignore_debug: bool,
) -> ProtoDiff {
    let mut result = ProtoDiff {
        path,
        header_diffs: Vec::new(),
        constant_diffs: Vec::new(),
        upvalue_diffs: Vec::new(),
        instruction_diffs: Vec::new(),
    };
    let h = &mut result.header_diffs;
    changed(h, "numparams", &a.numparams, &b.numparams);
    changed(h, "is_vararg", &a.is_vararg, &b.is_vararg);
    changed(h, "maxstacksize", &a.maxstacksize, &b.maxstacksize);
    changed(h, "child prototype count", &a.protos.len(), &b.protos.len());
    if !ignore_debug {
        changed(
            h,
            "source name bytes",
            &bytes(&a.source_name),
            &bytes(&b.source_name),
        );
        changed(h, "line_defined", &a.line_defined, &b.line_defined);
        changed(
            h,
            "last_line_defined",
            &a.last_line_defined,
            &b.last_line_defined,
        );
        changed(h, "line_info", &a.line_info, &b.line_info);
        if !a
            .abs_line_info
            .iter()
            .map(|x| (x.pc, x.line))
            .eq(b.abs_line_info.iter().map(|x| (x.pc, x.line)))
        {
            h.push("absolute line info changed".into());
        }
        if !a
            .loc_vars
            .iter()
            .map(|x| (&x.name.raw_bytes, x.startpc, x.endpc))
            .eq(b
                .loc_vars
                .iter()
                .map(|x| (&x.name.raw_bytes, x.startpc, x.endpc)))
        {
            h.push("local names/scopes changed".into());
        }
        if !a
            .upvalue_names
            .iter()
            .map(bytes)
            .eq(b.upvalue_names.iter().map(bytes))
        {
            h.push("upvalue debug names changed".into());
        }
    }
    changed(
        &mut result.constant_diffs,
        "constant count",
        &a.constants.len(),
        &b.constants.len(),
    );
    for (index, (x, y)) in a.constants.iter().zip(&b.constants).enumerate() {
        if !constant_equal(&x.value, &y.value) {
            result.constant_diffs.push(format!(
                "K[{index}]: {} -> {}",
                luad_core::scalar::render_constant_evidence(&x.value),
                luad_core::scalar::render_constant_evidence(&y.value)
            ));
        }
    }
    changed(
        &mut result.upvalue_diffs,
        "upvalue count",
        &a.upvalues.len(),
        &b.upvalues.len(),
    );
    for (index, (x, y)) in a.upvalues.iter().zip(&b.upvalues).enumerate() {
        if (x.instack, x.idx, x.kind) != (y.instack, y.idx, y.kind) {
            result
                .upvalue_diffs
                .push(format!("upvalue[{index}] capture descriptor changed"));
        }
        if !ignore_debug && bytes(&x.name) != bytes(&y.name) {
            result
                .upvalue_diffs
                .push(format!("upvalue[{index}] debug name changed"));
        }
    }
    // Role discovery is linear and borrows the constant/child tables. The general
    // lifter embeds constant values in operands, which is unnecessary amplification
    // for repeated uses of a large string in an untrusted input.
    let old_roles = (semantic && is_lua51(old_dialect)).then(|| discover_roles_lua51(a));
    let new_roles = (semantic && is_lua51(new_dialect)).then(|| discover_roles_lua51(b));
    for pc in 0..a.instructions.len().max(b.instructions.len()) {
        if old_dialect == new_dialect
            && a.instructions.get(pc).map(|i| i.raw_word)
                == b.instructions.get(pc).map(|i| i.raw_word)
            && old_roles.as_ref().map(|r| r.get(pc)) == new_roles.as_ref().map(|r| r.get(pc))
        {
            continue;
        }
        let describe =
            |p: &Prototype,
             dialect: &str,
             roles: &Option<luad_dialect_lua51::roles::Lua51RoleMap>| {
                p.instructions.get(pc).map(|i| {
                    if !semantic {
                        return format!("0x{:08x}", i.raw_word);
                    }
                    if let Some(roles) = roles {
                        let role = roles.get(pc);
                        if !role.is_executable() {
                            return format!("{role:?} physical_word=0x{:08x}", i.raw_word);
                        }
                    }
                    decoded_word(dialect, i.raw_word)
                })
            };
        let old = describe(a, old_dialect, &old_roles);
        let new = describe(b, new_dialect, &new_roles);
        if old != new {
            result
                .instruction_diffs
                .push(InstructionDiff { pc, old, new });
        }
    }
    result
}

fn is_lua51(dialect: &str) -> bool {
    matches!(dialect, "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32")
}

fn decoded_word(dialect: &str, word: u32) -> String {
    // Retain the physical word even for unused fields and unknown opcodes.
    macro_rules! decode {
        ($ty:path) => {{
            let raw = <$ty>::decode(word);
            format!(
                "{} opcode={} A={} B={} C={} Bx={} sBx={} physical_word=0x{word:08x}",
                raw.opcode.map_or("UNKNOWN", |op| op.name()),
                raw.opcode_num,
                raw.a,
                raw.b,
                raw.c,
                raw.bx,
                raw.sbx
            )
        }};
    }
    match dialect {
        "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32" => {
            decode!(luad_dialect_lua51::opcodes::RawInstruction51)
        }
        "lua5.2" => decode!(luad_dialect_lua52::opcodes::RawInstruction52),
        "lua5.3" => decode!(luad_dialect_lua53::opcodes::RawInstruction53),
        "lua5.4" => decode!(luad_dialect_lua54::opcodes::RawInstruction54),
        "lua5.5" => decode!(luad_dialect_lua55::opcodes::RawInstruction55),
        _ => format!("uninterpreted physical_word=0x{word:08x}"),
    }
}

fn constant_equal(a: &ConstantValue, b: &ConstantValue) -> bool {
    use ConstantValue::{Boolean, Float, Integer, LongString, Nil, ShortString};
    match (a, b) {
        (Nil, Nil) => true,
        (Boolean(x), Boolean(y)) => x == y,
        (
            Integer {
                val: x,
                raw_hex: xr,
            },
            Integer {
                val: y,
                raw_hex: yr,
            },
        ) => x == y && xr == yr,
        (
            Float {
                val: x,
                raw_hex: xr,
                is_nan: xn,
                is_inf: xi,
            },
            Float {
                val: y,
                raw_hex: yr,
                is_nan: yn,
                is_inf: yi,
            },
        ) => x.to_bits() == y.to_bits() && xr == yr && xn == yn && xi == yi,
        (ShortString(x), ShortString(y)) | (LongString(x), LongString(y)) => {
            x.raw_bytes == y.raw_bytes
        }
        _ => false,
    }
}
