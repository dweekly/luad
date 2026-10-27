//! Opt-in `trusted-init` admission for Lua 5.1 modules the strict convention refuses.
//!
//! The strict convention admits only a declarative root. This admission lets the root run
//! other code under the `trusted-init` assumption, which covers what the root cannot show:
//!
//! 1. No function run during initialization, other than the root itself, defines, replaces
//!    or removes a function in a module namespace, or changes a module's environment or
//!    metatable. That includes required modules, library functions and same-file
//!    functions, however they are called.
//! 2. `require(name)` returns the table at the global dotted path `name`, and no other call
//!    returns a module namespace table.
//! 3. Initialization completes.
//!
//! Everything the root's own instructions do is checked. A register-token dataflow over the
//! root CFG, joined by union and iterated to a fixpoint, tracks which global table paths
//! each register may hold. Writes into, and escapes of, those paths become dynamic label
//! prefixes ("marks"). Writes the analysis cannot name, and environment changes, refuse the
//! module for the whole corpus.

use std::collections::{BTreeMap, BTreeSet};

use luad_core::model::{Chunk, ConstantValue};
use luad_core::{EffectTarget, ProtoPath, StableId};
use luad_dialect_lua51::{Opcode51 as Op, RawInstruction51};

use crate::callees::{analyze_root_global_stores, GlobalStoreValue};
use crate::cfg::ControlFlowGraph;

/// Largest token set one register may carry before the admission is a limit.
const MAX_REGISTER_TOKENS: usize = 32;
/// Deepest path tracked; callee symbolic paths admit at most 32 segments.
const MAX_PATH_SEGMENTS: usize = 31;
/// Whole-root passes allowed for fresh-table contents to settle.
const MAX_FIELD_ROUNDS: usize = 8;
/// Marks, after following aliases, before the admission is a limit.
const MAX_RESOLVED_MARKS: usize = 4096;

/// A module admitted under `trusted-init`.
pub(crate) struct TrustedModule {
    pub segments: Vec<String>,
    pub declaration_evidence: Vec<StableId>,
    /// `(export name, defining prototype, evidence)` in root order.
    pub exports: Vec<(String, ProtoPath, Vec<StableId>)>,
    /// Dynamic label prefixes with their evidence.
    pub marks: BTreeMap<Vec<String>, BTreeSet<StableId>>,
}

pub(crate) enum TrustedOutcome {
    Admitted(TrustedModule),
    /// The module's namespace or writes cannot be bounded; the whole corpus degrades.
    Refused(Vec<StableId>),
    Limited,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Token {
    /// A value that is not a module namespace table under the assumption.
    Opaque,
    /// A table this root created at the `NEWTABLE` with this PC.
    Fresh(usize),
    /// The global `module`.
    Module,
    /// A string loaded by `LOADK` at this PC.
    Literal(usize),
    /// Some module namespace table the analysis cannot name.
    AnyNamespace,
    /// A table reached by global lookup. `own` paths are relative to the module name.
    Path {
        own: bool,
        segments: Vec<String>,
        exact: bool,
    },
}

type Tokens = BTreeSet<Token>;
type PathKey = (bool, Vec<String>);

#[derive(Default)]
struct Facts {
    refusals: BTreeSet<usize>,
    /// `(own, segments)` prefixes and the PCs that marked them.
    marks: BTreeMap<PathKey, BTreeSet<usize>>,
    /// Declaration candidates: call PC to the PCs of its literal name load.
    declarations: BTreeMap<usize, BTreeSet<usize>>,
    /// Declarations that pass options other than `package.seeall`.
    declaration_options: BTreeSet<usize>,
    /// What each fresh table may hold: `(allocation PC, constant key or None for any
    /// other key and list items)` to the union of stored values.
    fresh_fields: BTreeMap<(usize, Option<String>), Tokens>,
    /// Named destinations that hold an exact path: destination to sources.
    aliases: BTreeMap<PathKey, BTreeSet<PathKey>>,
    limited: bool,
}

impl Facts {
    /// Every value a fresh table may hold under `key` (`None`: any key).
    fn fresh_read(&self, site: usize, key: Option<&str>) -> Tokens {
        self.fresh_fields
            .range((site, None)..)
            .take_while(|((s, _), _)| *s == site)
            .filter(|((_, k), _)| key.is_none() || k.is_none() || k.as_deref() == key)
            .flat_map(|(_, v)| v.iter().cloned())
            .collect()
    }
}

fn string_bytes(value: &ConstantValue) -> Option<&[u8]> {
    match value {
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => Some(&s.raw_bytes),
        _ => None,
    }
}

/// An admitted selector, as the strict rule spells it, decoded to text.
fn admitted_name(value: &ConstantValue) -> Option<String> {
    let bytes = string_bytes(value)?;
    if !super::linking::admitted_selector(bytes) {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// The global path a dotted module name denotes, if every segment is admitted.
fn dotted_path(name: &str) -> Option<Vec<String>> {
    let parts: Vec<String> = name.split('.').map(str::to_owned).collect();
    (parts.len() <= MAX_PATH_SEGMENTS && parts.iter().all(|p| !p.is_empty())).then_some(parts)
}

fn path(own: bool, segments: Vec<String>, exact: bool) -> Token {
    Token::Path {
        own,
        segments,
        exact,
    }
}

fn has_path(tokens: &Tokens, wanted: &[&str]) -> bool {
    tokens.iter().any(|t| {
        matches!(t, Token::Path { segments, .. }
            if segments.len() == wanted.len() && segments.iter().zip(wanted).all(|(a, b)| a == b))
    })
}

/// Functions that change an environment or a metatable without going through a path.
fn is_environment_mutator(segments: &[String], exact: bool) -> bool {
    let names: Vec<&str> = segments.iter().map(String::as_str).collect();
    if !exact {
        // `_G[k]` or `debug[k]` could be any of the functions below.
        return matches!(names.as_slice(), [] | ["debug"]);
    }
    matches!(
        names.as_slice(),
        ["setfenv"]
            | [
                "debug",
                "setfenv" | "setmetatable" | "setupvalue" | "setlocal"
            ]
    )
}

/// Builtins whose purpose is to change a table or its metatable, or to expose the
/// metatable for the root to change. Their arguments escape; other callees are covered
/// by the assumption.
fn is_table_mutator(segments: &[String], exact: bool) -> bool {
    let names: Vec<&str> = segments.iter().map(String::as_str).collect();
    exact
        && matches!(
            names.as_slice(),
            ["setmetatable" | "getmetatable" | "rawset"]
        )
}

/// Functions whose results may be module namespace tables the analysis cannot name.
fn is_namespace_source(segments: &[String], exact: bool) -> bool {
    let names: Vec<&str> = segments.iter().map(String::as_str).collect();
    exact
        && matches!(
            names.as_slice(),
            ["require"]
                | ["getfenv"]
                | [
                    "debug",
                    "getfenv" | "getregistry" | "getlocal" | "getupvalue"
                ]
        )
}

fn path_parts(tokens: &Tokens) -> impl Iterator<Item = (&Vec<String>, bool)> {
    tokens.iter().filter_map(|t| match t {
        Token::Path {
            segments, exact, ..
        } => Some((segments, *exact)),
        _ => None,
    })
}

struct Root<'a> {
    chunk: &'a Chunk,
    frame: usize,
}

impl Root<'_> {
    fn constant(&self, index: usize) -> Option<&ConstantValue> {
        self.chunk.main_proto.constants.get(index).map(|c| &c.value)
    }

    /// RK operand: a constant admitted string key, if that is what it names.
    fn rk_name(&self, rk: u16) -> Option<String> {
        if rk >= 256 {
            self.constant((rk - 256) as usize).and_then(admitted_name)
        } else {
            None
        }
    }

    /// RK operand: any constant string key.
    fn rk_string(&self, rk: u16) -> Option<&[u8]> {
        if rk >= 256 {
            self.constant((rk - 256) as usize).and_then(string_bytes)
        } else {
            None
        }
    }

    fn literal_text(&self, load_pc: usize) -> Option<&str> {
        let word = self.chunk.main_proto.instructions.get(load_pc)?;
        let raw = RawInstruction51::decode(word.raw_word);
        std::str::from_utf8(string_bytes(self.constant(raw.bx as usize)?)?).ok()
    }
}

fn record_mark(facts: &mut Facts, own: bool, segments: Vec<String>, pc: usize) {
    facts.marks.entry((own, segments)).or_default().insert(pc);
}

/// A value escaped (stored, passed or listed): the paths it carries are marked, and
/// values that could redirect later stores refuse. A fresh table escapes with
/// everything it may hold.
fn escape(facts: &mut Facts, tokens: &Tokens, pc: usize) {
    let mut pending: Vec<Token> = tokens.iter().cloned().collect();
    let mut seen_sites = BTreeSet::new();
    while let Some(token) = pending.pop() {
        match &token {
            Token::Fresh(site) => {
                if seen_sites.insert(*site) {
                    pending.extend(facts.fresh_read(*site, None));
                }
            }
            Token::Module | Token::AnyNamespace => {
                facts.refusals.insert(pc);
            }
            Token::Path {
                own,
                segments,
                exact,
            } => {
                if is_environment_mutator(segments, *exact) {
                    facts.refusals.insert(pc);
                }
                record_mark(facts, *own, segments.clone(), pc);
            }
            _ => {}
        }
    }
}

/// A write into table register `table` with key `key` and value `value`. A value stored
/// only into fresh tables is remembered there; stored anywhere else, it escapes.
fn table_write(facts: &mut Facts, table: &Tokens, key: Option<&str>, value: &Tokens, pc: usize) {
    let mut escapes = table.is_empty();
    let mut destinations = Vec::new();
    for token in table {
        match token {
            Token::Fresh(site) => {
                facts
                    .fresh_fields
                    .entry((*site, key.map(str::to_owned)))
                    .or_default()
                    .extend(value.iter().cloned());
            }
            Token::Path {
                own,
                segments,
                exact,
            } => {
                let mut target = segments.clone();
                match (*exact, key) {
                    (true, Some(key)) => {
                        target.push(key.to_string());
                        destinations.push((*own, target.clone()));
                    }
                    _ => escapes = true,
                }
                record_mark(facts, *own, target, pc);
            }
            // A namespace the analysis cannot name was written.
            Token::AnyNamespace | Token::Module => {
                facts.refusals.insert(pc);
                escapes = true;
            }
            _ => escapes = true,
        }
    }
    if escapes {
        escape(facts, value, pc);
    } else {
        store_named(facts, &destinations, value, pc);
    }
}

/// A value stored only under names the analysis follows (fresh-table fields, or exact
/// paths). An exact path value becomes an alias of each destination, so later writes
/// through the destination also mark the source. Anything else escapes.
fn store_named(facts: &mut Facts, destinations: &[PathKey], value: &Tokens, pc: usize) {
    let mut rest = Tokens::new();
    for token in value {
        match token {
            Token::Path {
                own,
                segments,
                exact: true,
            } if !is_environment_mutator(segments, true) => {
                for destination in destinations {
                    facts
                        .aliases
                        .entry(destination.clone())
                        .or_default()
                        .insert((*own, segments.clone()));
                }
            }
            other => {
                rest.insert(other.clone());
            }
        }
    }
    escape(facts, &rest, pc);
}

fn set_register(state: &mut [Tokens], facts: &mut Facts, register: usize, tokens: Tokens) {
    if tokens.len() > MAX_REGISTER_TOKENS {
        facts.limited = true;
    }
    if let Some(slot) = state.get_mut(register) {
        *slot = tokens;
    }
}

fn get_table(root: &Root<'_>, facts: &mut Facts, table: &Tokens, key_rk: u16) -> Tokens {
    let key = root.rk_name(key_rk);
    let mut out = Tokens::new();
    for token in table {
        match token {
            // `package.loaded[name]` is the namespace `name` itself.
            Token::Path {
                own: false,
                segments,
                ..
            } if segments.len() == 2 && segments[0] == "package" && segments[1] == "loaded" => {
                let named = root
                    .rk_string(key_rk)
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .filter(|n| super::linking::admitted_selector(n.as_bytes()))
                    .and_then(dotted_path);
                out.insert(match named {
                    Some(segments) => path(false, segments, true),
                    None => Token::AnyNamespace,
                });
            }
            Token::Path {
                own,
                segments,
                exact,
            } => {
                let mut segments = segments.clone();
                let exact = match (&key, exact) {
                    (Some(key), true) => {
                        segments.push(key.clone());
                        true
                    }
                    _ => false,
                };
                if segments.len() > MAX_PATH_SEGMENTS {
                    facts.limited = true;
                    continue;
                }
                out.insert(path(*own, segments, exact));
            }
            Token::AnyNamespace => {
                out.insert(Token::AnyNamespace);
            }
            Token::Fresh(site) => {
                // An unset field, or one the root stored here.
                out.insert(Token::Opaque);
                out.extend(facts.fresh_read(*site, key.as_deref()));
            }
            _ => {
                out.insert(Token::Opaque);
            }
        }
    }
    if out.is_empty() {
        out.insert(Token::Opaque);
    }
    out
}

fn written_registers(target: &EffectTarget, frame: usize) -> std::ops::Range<usize> {
    match target {
        EffectTarget::Register { index } => *index as usize..*index as usize + 1,
        EffectTarget::RegisterRange { start, end } => *start as usize..*end as usize + 1,
        EffectTarget::RegisterRangeToTop { start } => *start as usize..frame.max(*start as usize),
        _ => 0..0,
    }
}

/// Handle one call; returns the token set for its first result.
fn call(
    root: &Root<'_>,
    raw: &RawInstruction51,
    reg: &dyn Fn(usize) -> Tokens,
    facts: &mut Facts,
    pc: usize,
) -> Tokens {
    let a = raw.a as usize;
    let function = reg(a);
    let arguments: Vec<usize> = if raw.b == 0 {
        (a + 1..root.frame).collect()
    } else {
        (a + 1..a + raw.b as usize).collect()
    };
    if function.contains(&Token::Module) {
        let literal = match reg(a + 1).iter().collect::<Vec<_>>().as_slice() {
            [Token::Literal(load)] => Some(*load),
            _ => None,
        };
        let shape = function.len() == 1 && raw.opcode == Some(Op::Call) && raw.c == 1 && raw.b >= 2;
        match (shape, literal) {
            (true, Some(load)) => {
                facts.declarations.entry(pc).or_default().insert(load);
                let seeall_only = raw.b == 2
                    || (raw.b == 3
                        && {
                            let third = reg(a + 2);
                            !third.is_empty()
                            && third.iter().all(|t| {
                                matches!(t, Token::Path { segments, exact: true, .. }
                                    if segments.len() == 2 && segments[0] == "package" && segments[1] == "seeall")
                            })
                        });
                if !seeall_only {
                    // Options receive the module table and may change its metatable.
                    facts.declaration_options.insert(pc);
                    for argument in arguments.iter().skip(1) {
                        escape(facts, &reg(*argument), pc);
                    }
                }
            }
            _ => {
                facts.refusals.insert(pc);
            }
        }
        return Tokens::from([Token::Opaque]);
    }
    if path_parts(&function).any(|(segments, exact)| is_environment_mutator(segments, exact)) {
        facts.refusals.insert(pc);
    }
    // Other callees are inside the assumption; the mutating builtins are not, so what
    // they receive escapes. Handing over `module` or an environment mutator always counts.
    let mutating = path_parts(&function).any(|(s, exact)| is_table_mutator(s, exact));
    let mut passes_source = false;
    for argument in &arguments {
        let tokens = reg(*argument);
        passes_source |= path_parts(&tokens).any(|(s, exact)| is_namespace_source(s, exact));
        if mutating {
            escape(facts, &tokens, pc);
        } else if tokens.contains(&Token::Module)
            || path_parts(&tokens).any(|(s, exact)| is_environment_mutator(s, exact))
        {
            facts.refusals.insert(pc);
        }
    }
    let mut result = Tokens::new();
    let is_require = |s: &[String]| s.len() == 1 && s[0] == "require";
    if path_parts(&function).any(|(s, exact)| is_namespace_source(s, exact) && !is_require(s)) {
        result.insert(Token::AnyNamespace);
    }
    if has_path(&function, &["require"]) {
        let named = (raw.b == 2)
            .then(|| match reg(a + 1).iter().collect::<Vec<_>>().as_slice() {
                [Token::Literal(load)] => root.literal_text(*load).map(str::to_owned),
                _ => None,
            })
            .flatten()
            .filter(|n| super::linking::admitted_selector(n.as_bytes()))
            .and_then(|n| dotted_path(&n));
        result.insert(match named {
            Some(segments) => path(false, segments, true),
            None => Token::AnyNamespace,
        });
    }
    if passes_source {
        result.insert(Token::AnyNamespace);
    }
    // Any other callee returns something that is not a namespace, under the assumption.
    if function.iter().any(|t| {
        !matches!(t, Token::Path { segments, exact, .. } if is_namespace_source(segments, *exact))
    }) {
        result.insert(Token::Opaque);
    }
    result
}

fn transfer(
    root: &Root<'_>,
    instruction: &luad_core::SemanticInstruction,
    state: &mut [Tokens],
    facts: &mut Facts,
) {
    let pc = instruction.pc;
    let raw = RawInstruction51::decode(instruction.raw_word);
    let a = raw.a as usize;
    let before: Vec<Tokens> = state.to_vec();
    let reg = |r: usize| before.get(r).cloned().unwrap_or_default();

    let mut call_result = None;
    match raw.opcode {
        Some(Op::Call | Op::TailCall) => {
            call_result = Some(call(root, &raw, &reg, facts, pc));
        }
        Some(Op::SetTable) => {
            let value = if raw.c < 256 {
                reg(raw.c as usize)
            } else {
                Tokens::new()
            };
            table_write(facts, &reg(a), root.rk_name(raw.b).as_deref(), &value, pc);
        }
        Some(Op::SetList) => {
            let values: Vec<usize> = if raw.b == 0 {
                (a + 1..root.frame).collect()
            } else {
                (a + 1..=a + raw.b as usize).collect()
            };
            for value in values {
                table_write(facts, &reg(a), None, &reg(value), pc);
            }
            // The table register still holds the same table.
            return;
        }
        Some(Op::SetGlobal) => match root.constant(raw.bx as usize).and_then(admitted_name) {
            // Before the declaration the store lands in `_G`; after it, in the module.
            Some(name) => store_named(
                facts,
                &[(true, vec![name.clone()]), (false, vec![name])],
                &reg(a),
                pc,
            ),
            None => escape(facts, &reg(a), pc),
        },
        _ => {}
    }

    // Every result of a call carries the call's result tokens, since `pcall(require, n)`
    // returns the namespace second.
    let written = call_result.unwrap_or_else(|| Tokens::from([Token::Opaque]));
    for target in &instruction.writes {
        for register in written_registers(target, root.frame) {
            set_register(state, facts, register, written.clone());
        }
    }

    let produced = match raw.opcode {
        Some(Op::Move) => Some(reg(raw.b as usize)),
        Some(Op::TestSet) => {
            let mut joined = reg(raw.b as usize);
            joined.extend(reg(a));
            Some(joined)
        }
        Some(Op::LoadK) => Some(Tokens::from([
            match root.constant(raw.bx as usize).and_then(string_bytes) {
                Some(_) => Token::Literal(pc),
                None => Token::Opaque,
            },
        ])),
        Some(Op::GetGlobal) => {
            let name = root.constant(raw.bx as usize);
            Some(
                match (name.and_then(string_bytes), name.and_then(admitted_name)) {
                    (Some(b"module"), _) => Tokens::from([Token::Module]),
                    (Some(b"_G"), _) => Tokens::from([path(false, Vec::new(), true)]),
                    (Some(b"_M"), _) => Tokens::from([path(true, Vec::new(), true)]),
                    (_, Some(name)) => Tokens::from([
                        path(true, vec![name.clone()], true),
                        path(false, vec![name], true),
                    ]),
                    // A global whose name no admitted label can spell.
                    _ => Tokens::from([Token::AnyNamespace]),
                },
            )
        }
        Some(Op::GetTable) => Some(get_table(root, facts, &reg(raw.b as usize), raw.c)),
        Some(Op::SelfOp) => {
            let table = reg(raw.b as usize);
            set_register(state, facts, a + 1, table.clone());
            Some(get_table(root, facts, &table, raw.c))
        }
        Some(Op::NewTable) => Some(Tokens::from([Token::Fresh(pc)])),
        _ => None,
    };
    if let Some(tokens) = produced {
        set_register(state, facts, a, tokens);
    }
}

fn dominates(cfg: &ControlFlowGraph, dominator: usize, block: usize) -> bool {
    let mut current = Some(block);
    let mut steps = 0;
    while let Some(b) = current {
        if b == dominator {
            return true;
        }
        steps += 1;
        if steps > cfg.blocks.len() {
            return false;
        }
        current = cfg.blocks[b].immediate_dominator.filter(|&d| d != b);
    }
    false
}

fn dominates_exits(cfg: &ControlFlowGraph, block: usize) -> bool {
    let exits: Vec<usize> = cfg
        .blocks
        .iter()
        .filter(|b| b.is_reachable && b.is_exit)
        .map(|b| b.index)
        .collect();
    cfg.blocks[block].is_reachable
        && !exits.is_empty()
        && exits.iter().all(|&exit| dominates(cfg, block, exit))
}

/// One forward union pass to a register fixpoint; `Some` ends the admission early.
fn run_dataflow(
    root: &Root<'_>,
    cfg: &ControlFlowGraph,
    instructions: &[luad_core::SemanticInstruction],
    facts: &mut Facts,
    budget: usize,
) -> Option<TrustedOutcome> {
    let mut entry: Vec<Option<Vec<Tokens>>> = vec![None; cfg.blocks.len()];
    entry[0] = Some(vec![Tokens::from([Token::Opaque]); root.frame]);
    let mut work = vec![0usize];
    let mut visits = 0usize;
    while let Some(b) = work.pop() {
        visits += 1;
        if visits > budget || facts.limited {
            return Some(TrustedOutcome::Limited);
        }
        let mut state = entry[b].clone().expect("queued blocks have a state");
        for &pc in &cfg.blocks[b].instruction_pcs {
            transfer(root, &instructions[pc], &mut state, facts);
        }
        for edge in &cfg.blocks[b].successors {
            let next = edge.to_block;
            let changed = match &mut entry[next] {
                None => {
                    entry[next] = Some(state.clone());
                    true
                }
                Some(existing) => {
                    let mut grew = false;
                    for (slot, tokens) in existing.iter_mut().zip(&state) {
                        for token in tokens {
                            grew |= slot.insert(token.clone());
                        }
                        if slot.len() > MAX_REGISTER_TOKENS {
                            return Some(TrustedOutcome::Limited);
                        }
                    }
                    grew
                }
            };
            if changed && !work.contains(&next) {
                work.push(next);
            }
        }
    }
    None
}

fn root_pc(id: &StableId) -> Option<usize> {
    match id {
        StableId::Instruction { proto, pc } if proto == &ProtoPath::root() => Some(*pc),
        _ => None,
    }
}

/// Re-examine a root the strict rule refused. The caller has already checked the chunk
/// is Lua 5.1 and loads `module`.
pub(crate) fn admit_trusted_module(chunk: &Chunk) -> TrustedOutcome {
    let p = &chunk.main_proto;
    let refused = |pcs: &mut dyn Iterator<Item = usize>| {
        let mut evidence: Vec<StableId> = pcs
            .filter_map(|pc| p.instructions.get(pc).map(|w| w.id.clone()))
            .collect();
        if evidence.is_empty() {
            evidence.push(p.id.clone());
        }
        TrustedOutcome::Refused(evidence)
    };
    if crate::validate_for_analysis(chunk).is_err() {
        return refused(&mut std::iter::empty());
    }
    if p.instructions.len() > super::linking::MAX_MODULE_INIT_WORDS {
        return TrustedOutcome::Limited;
    }
    let instructions = crate::lift_proto_for_dialect(&chunk.dialect, p);
    let cfg = ControlFlowGraph::build(p, &instructions);
    let root = Root {
        chunk,
        frame: (p.maxstacksize as usize).clamp(1, 256),
    };

    let mut block_of = BTreeMap::new();
    let mut module_loads = Vec::new();
    let mut constant_bytes = 0usize;
    for block in &cfg.blocks {
        for &pc in &block.instruction_pcs {
            block_of.insert(pc, block.index);
            let raw = RawInstruction51::decode(instructions[pc].raw_word);
            let keys = match raw.opcode {
                Some(Op::LoadK | Op::GetGlobal | Op::SetGlobal) => vec![raw.bx as usize],
                Some(Op::GetTable | Op::SelfOp) if raw.c >= 256 => vec![(raw.c - 256) as usize],
                Some(Op::SetTable) => [raw.b, raw.c]
                    .into_iter()
                    .filter(|rk| *rk >= 256)
                    .map(|rk| (rk - 256) as usize)
                    .collect(),
                _ => Vec::new(),
            };
            for value in keys.into_iter().filter_map(|k| root.constant(k)) {
                constant_bytes = constant_bytes.saturating_add(match value {
                    ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
                        s.raw_bytes.len().saturating_add(s.display.len())
                    }
                    ConstantValue::Float { raw_hex, .. }
                    | ConstantValue::Integer { raw_hex, .. } => raw_hex.len(),
                    _ => 1,
                });
                if constant_bytes > super::linking::MAX_MODULE_INIT_CONSTANT_BYTES {
                    return TrustedOutcome::Limited;
                }
            }
            if raw.opcode == Some(Op::GetGlobal)
                && root.constant(raw.bx as usize).and_then(string_bytes) == Some(b"module")
            {
                module_loads.push(pc);
            }
        }
    }
    if module_loads.len() != 1 || cfg.blocks.is_empty() {
        return refused(&mut module_loads.into_iter());
    }

    // Forward union dataflow to a fixpoint over reachable blocks. Fresh-table contents
    // are flow-insensitive per allocation site, so the pass repeats until they settle.
    let mut facts = Facts::default();
    let budget = cfg.blocks.len().saturating_mul(16).saturating_add(64);
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        if rounds > MAX_FIELD_ROUNDS {
            return TrustedOutcome::Limited;
        }
        let fields_before = facts.fresh_fields.clone();
        if let Some(outcome) = run_dataflow(&root, &cfg, &instructions, &mut facts, budget) {
            return outcome;
        }
        if facts.fresh_fields == fields_before {
            break;
        }
    }
    if facts.limited {
        return TrustedOutcome::Limited;
    }
    if !facts.refusals.is_empty() {
        return refused(&mut facts.refusals.iter().copied());
    }

    let (call_pc, load_pc) = match facts.declarations.iter().collect::<Vec<_>>().as_slice() {
        [(call, loads)] if loads.len() == 1 => (**call, *loads.iter().next().expect("one load")),
        _ => return refused(&mut facts.declarations.keys().copied()),
    };
    let declaration_block = block_of[&call_pc];
    if !dominates_exits(&cfg, declaration_block) {
        return refused(&mut std::iter::once(call_pc));
    }
    let Some(name) = root.literal_text(load_pc) else {
        return refused(&mut std::iter::once(load_pc));
    };
    if name.as_bytes().contains(&0) || !super::linking::admitted_selector(name.as_bytes()) {
        return refused(&mut std::iter::once(load_pc));
    }
    let parts: Vec<_> = name.split('.').take(32).collect();
    if parts.len() >= 32 {
        return TrustedOutcome::Limited;
    }
    if parts.iter().any(|s| s.is_empty()) {
        return refused(&mut std::iter::once(load_pc));
    }
    let module: Vec<String> = parts.into_iter().map(str::to_owned).collect();
    let resolve = |own: bool, segments: &[String]| -> Vec<String> {
        let mut label = if own { module.clone() } else { Vec::new() };
        label.extend_from_slice(segments);
        label
    };

    let mut marks: BTreeMap<Vec<String>, BTreeSet<StableId>> = BTreeMap::new();
    let mut add_mark = |label: Vec<String>, pc: usize| {
        marks
            .entry(label)
            .or_default()
            .insert(p.instructions[pc].id.clone());
    };
    // A mark under an alias destination also marks the aliased source.
    let mut pending: Vec<(PathKey, BTreeSet<usize>)> = facts
        .marks
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(((own, segments), pcs)) = pending.pop() {
        if !seen.insert((own, segments.clone(), pcs.clone())) {
            continue;
        }
        if seen.len() > MAX_RESOLVED_MARKS || segments.len() > MAX_PATH_SEGMENTS {
            return TrustedOutcome::Limited;
        }
        let label = resolve(own, &segments);
        if label.is_empty() {
            return refused(&mut pcs.iter().copied());
        }
        for pc in &pcs {
            add_mark(label.clone(), *pc);
        }
        for ((dest_own, destination), sources) in &facts.aliases {
            if *dest_own == own && segments.starts_with(destination) {
                for (source_own, source) in sources {
                    let mut mapped = source.clone();
                    mapped.extend_from_slice(&segments[destination.len()..]);
                    pending.push(((*source_own, mapped), pcs.clone()));
                }
            }
        }
    }
    for pc in &facts.declaration_options {
        add_mark(module.clone(), *pc);
    }

    let Ok(stores) = analyze_root_global_stores(chunk) else {
        return TrustedOutcome::Limited;
    };
    let mut store_counts: BTreeMap<&[u8], usize> = BTreeMap::new();
    for store in &stores {
        *store_counts.entry(&store.name_raw).or_default() += 1;
    }
    let declared = |pc: usize, block: usize| {
        if block == declaration_block {
            pc > call_pc
        } else {
            dominates(&cfg, declaration_block, block)
        }
    };
    let mut exports = Vec::new();
    for store in &stores {
        let Some(pc) = root_pc(&store.store_id) else {
            continue;
        };
        // Labels with unadmitted segments resolve dynamic at every call site.
        let Ok(name) = std::str::from_utf8(&store.name_raw) else {
            continue;
        };
        if !super::linking::admitted_selector(name.as_bytes()) {
            continue;
        }
        let Some(&block) = block_of.get(&pc) else {
            continue;
        };
        if !declared(pc, block) {
            add_mark(vec![name.to_string()], pc);
            add_mark(resolve(true, &[name.to_string()]), pc);
            continue;
        }
        let in_block = |evidence: &[StableId]| {
            evidence
                .iter()
                .all(|id| root_pc(id).is_some_and(|e| e <= pc && block_of.get(&e) == Some(&block)))
        };
        let settled = store_counts[store.name_raw.as_slice()] == 1 && dominates_exits(&cfg, block);
        match &store.value {
            GlobalStoreValue::Closure {
                prototype,
                evidence,
            } if settled && in_block(evidence) => {
                exports.push((name.to_string(), prototype.clone(), evidence.clone()));
            }
            GlobalStoreValue::NonClosure { evidence } if settled && in_block(evidence) => {}
            _ => add_mark(resolve(true, &[name.to_string()]), pc),
        }
    }

    TrustedOutcome::Admitted(TrustedModule {
        segments: module,
        declaration_evidence: vec![
            p.instructions[module_loads[0]].id.clone(),
            p.instructions[load_pc].id.clone(),
            p.instructions[call_pc].id.clone(),
        ],
        exports,
        marks,
    })
}
