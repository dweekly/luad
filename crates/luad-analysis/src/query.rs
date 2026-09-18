//! Safe, bounded structured query engine over bytecode instructions and artifacts.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, SemanticInstruction};
use luad_core::model::{Chunk, Constant, ConstantValue, Prototype};

use crate::callees::{CalleeFact, CalleeLookupKind, CalleeResolution, CalleeUnresolvedReason};
use crate::callgraph::{CallRelationFact, CallRelationResolution, CallRelationUnresolvedReason};
use crate::origins::{CallArgumentWindow, CallOriginFact, OriginExpressionKind};
use crate::prototype_identity::PrototypeIdentityFact;
use crate::xrefs::find_proto;

/// Query error conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    Malformed(String),
    UnknownField(String),
    InvalidOperator(String, String),
    InvalidOperand(String, String),
    FactDerivation(String),
    InvalidCursor(String, usize),
    MissingValue(String),
    UnbalancedParentheses,
    TrailingTokens(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "Malformed query expression: {msg}"),
            Self::UnknownField(field) => write!(f, "Unknown query field '{field}'"),
            Self::InvalidOperator(op, field) => {
                write!(f, "Unsupported operator '{op}' for field '{field}'")
            }
            Self::InvalidOperand(field, val) => {
                write!(f, "Invalid operand for field '{field}': '{val}'")
            }
            Self::FactDerivation(message) => write!(f, "Required fact derivation failed: {message}"),
            Self::InvalidCursor(c, max) => write!(
                f,
                "Invalid cursor '{c}': expected a context-bound continuation token with offset at most {max}"
            ),
            Self::MissingValue(op) => write!(f, "Missing query value after operator '{op}'"),
            Self::UnbalancedParentheses => write!(f, "Unbalanced parentheses in query expression"),
            Self::TrailingTokens(tokens) => write!(f, "Unexpected trailing tokens: '{tokens}'"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Result record returned by a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryMatch {
    /// Stable identifier of the matching artifact.
    pub id: StableId,
    /// Artifact category ("instruction", "constant", "prototype", "upvalue", "interpretation").
    pub kind: String,
    /// Human-readable match summary.
    pub summary: String,
}

/// Paginated query response document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryResponse {
    /// Matching records.
    pub matches: Vec<QueryMatch>,
    /// Total number of matches returned in this page.
    pub count: usize,
    /// Continuation cursor if more results exist beyond the limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Whether results were truncated by the limit ceiling.
    pub is_truncated: bool,
}

/// Query target fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryField {
    Opcode,
    Mnemonic,
    Constant,
    String,
    ConstantType,
    CalleeStatus,
    CalleePath,
    CalleeLookupKind,
    CalleeLookupKey,
    CalleeReason,
    CallReason,
    CallTarget,
    OriginKind,
    OriginArgumentIndex,
    InterpretationProfile,
    PrototypeDigest,
    EffectReadRegister,
    EffectWriteRegister,
    EffectReadUpvalue,
    EffectWriteUpvalue,
}

impl QueryField {
    pub fn parse(s: &str) -> Result<Self, QueryError> {
        match s.to_lowercase().as_str() {
            "opcode" => Ok(Self::Opcode),
            "mnemonic" => Ok(Self::Mnemonic),
            "constant" | "k" => Ok(Self::Constant),
            "string" => Ok(Self::String),
            "constant.type" | "k.type" => Ok(Self::ConstantType),
            "callee.status" => Ok(Self::CalleeStatus),
            "callee.path" => Ok(Self::CalleePath),
            "callee.lookup.kind" => Ok(Self::CalleeLookupKind),
            "callee.lookup.key" => Ok(Self::CalleeLookupKey),
            "callee.reason" => Ok(Self::CalleeReason),
            "call.reason" => Ok(Self::CallReason),
            "call.target" => Ok(Self::CallTarget),
            "origin.kind" => Ok(Self::OriginKind),
            "origin.argument.index" => Ok(Self::OriginArgumentIndex),
            "interpretation.profile" => Ok(Self::InterpretationProfile),
            "prototype.digest" => Ok(Self::PrototypeDigest),
            "effect.read.register" | "read.register" | "read.reg" => Ok(Self::EffectReadRegister),
            "effect.write.register" | "write.register" | "write.reg" => {
                Ok(Self::EffectWriteRegister)
            }
            "effect.read.upvalue" | "read.upvalue" | "read.upval" => Ok(Self::EffectReadUpvalue),
            "effect.write.upvalue" | "write.upvalue" | "write.upval" => {
                Ok(Self::EffectWriteUpvalue)
            }
            other => Err(QueryError::UnknownField(other.to_string())),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Opcode => "opcode",
            Self::Mnemonic => "mnemonic",
            Self::Constant => "constant",
            Self::String => "string",
            Self::ConstantType => "constant.type",
            Self::CalleeStatus => "callee.status",
            Self::CalleePath => "callee.path",
            Self::CalleeLookupKind => "callee.lookup.kind",
            Self::CalleeLookupKey => "callee.lookup.key",
            Self::CalleeReason => "callee.reason",
            Self::CallReason => "call.reason",
            Self::CallTarget => "call.target",
            Self::OriginKind => "origin.kind",
            Self::OriginArgumentIndex => "origin.argument.index",
            Self::InterpretationProfile => "interpretation.profile",
            Self::PrototypeDigest => "prototype.digest",
            Self::EffectReadRegister => "effect.read.register",
            Self::EffectWriteRegister => "effect.write.register",
            Self::EffectReadUpvalue => "effect.read.upvalue",
            Self::EffectWriteUpvalue => "effect.write.upvalue",
        }
    }
}

/// Query comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOp {
    Equals,
    NotEquals,
    Contains,
}

/// Query operand preserving literal representation (quoted string vs bare token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryOperand {
    String(String),
    Bare(String),
}

impl QueryOperand {
    pub fn as_str(&self) -> &str {
        match self {
            Self::String(s) | Self::Bare(s) => s.as_str(),
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    pub fn is_bare(&self) -> bool {
        matches!(self, Self::Bare(_))
    }
}

/// Parsed Abstract Syntax Tree for a where expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryExpr {
    Comparison {
        field: QueryField,
        op: QueryOp,
        value: QueryOperand,
    },
    MnemonicDirect(String),
    And(Box<QueryExpr>, Box<QueryExpr>),
    Or(Box<QueryExpr>, Box<QueryExpr>),
}

impl QueryExpr {
    /// Parse a query where clause string into an AST.
    pub fn parse(input: &str) -> Result<Self, QueryError> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Err(QueryError::Malformed("Empty query expression".to_string()));
        }
        let mut cursor = 0;
        let expr = parse_or_expr(&tokens, &mut cursor)?;
        if cursor < tokens.len() {
            let trailing: Vec<String> = tokens[cursor..].iter().map(|t| t.to_string()).collect();
            return Err(QueryError::TrailingTokens(trailing.join(" ")));
        }
        Ok(expr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    StringLiteral(String),
    OpEquals,
    OpNotEquals,
    OpContains,
    KwAnd,
    KwOr,
    LParen,
    RParen,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Ident(s) => write!(f, "{s}"),
            Token::StringLiteral(s) => write!(f, "\"{s}\""),
            Token::OpEquals => write!(f, "=="),
            Token::OpNotEquals => write!(f, "!="),
            Token::OpContains => write!(f, "contains"),
            Token::KwAnd => write!(f, "and"),
            Token::KwOr => write!(f, "or"),
            Token::LParen => write!(f, "("),
            Token::RParen => write!(f, ")"),
        }
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, QueryError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
        } else if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
        } else if c == '=' {
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::OpEquals);
                i += 2;
            } else {
                return Err(QueryError::Malformed(
                    "Unexpected character '=': expected '=='".to_string(),
                ));
            }
        } else if c == '!' {
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::OpNotEquals);
                i += 2;
            } else {
                return Err(QueryError::Malformed(
                    "Unexpected character '!': expected '!='".to_string(),
                ));
            }
        } else if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < len {
                if chars[i] == quote {
                    closed = true;
                    i += 1;
                    break;
                } else if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                    match chars[i] {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        '\'' => s.push('\''),
                        '"' => s.push('"'),
                        other => s.push(other),
                    }
                    i += 1;
                } else {
                    s.push(chars[i]);
                    i += 1;
                }
            }
            if !closed {
                return Err(QueryError::Malformed(
                    "Unterminated string literal".to_string(),
                ));
            }
            tokens.push(Token::StringLiteral(s));
        } else {
            let mut ident = String::new();
            while i < len
                && !chars[i].is_whitespace()
                && chars[i] != '('
                && chars[i] != ')'
                && chars[i] != '='
                && chars[i] != '!'
                && chars[i] != '"'
                && chars[i] != '\''
            {
                ident.push(chars[i]);
                i += 1;
            }

            if ident.is_empty() {
                return Err(QueryError::Malformed(format!(
                    "Unexpected character '{}'",
                    chars[i]
                )));
            }

            match ident.to_lowercase().as_str() {
                "contains" => tokens.push(Token::OpContains),
                "and" | "&&" => tokens.push(Token::KwAnd),
                "or" | "||" => tokens.push(Token::KwOr),
                _ => tokens.push(Token::Ident(ident)),
            }
        }
    }

    Ok(tokens)
}

fn parse_or_expr(tokens: &[Token], cursor: &mut usize) -> Result<QueryExpr, QueryError> {
    let mut left = parse_and_expr(tokens, cursor)?;
    while *cursor < tokens.len() && tokens[*cursor] == Token::KwOr {
        *cursor += 1;
        let right = parse_and_expr(tokens, cursor)?;
        left = QueryExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and_expr(tokens: &[Token], cursor: &mut usize) -> Result<QueryExpr, QueryError> {
    let mut left = parse_primary(tokens, cursor)?;
    while *cursor < tokens.len() && tokens[*cursor] == Token::KwAnd {
        *cursor += 1;
        let right = parse_primary(tokens, cursor)?;
        left = QueryExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_primary(tokens: &[Token], cursor: &mut usize) -> Result<QueryExpr, QueryError> {
    if *cursor >= tokens.len() {
        return Err(QueryError::Malformed(
            "Unexpected end of query expression".to_string(),
        ));
    }

    if tokens[*cursor] == Token::LParen {
        *cursor += 1;
        let expr = parse_or_expr(tokens, cursor)?;
        if *cursor >= tokens.len() || tokens[*cursor] != Token::RParen {
            return Err(QueryError::UnbalancedParentheses);
        }
        *cursor += 1;
        return Ok(expr);
    }

    match &tokens[*cursor] {
        Token::Ident(name) => {
            let ident_str = name.clone();
            *cursor += 1;

            if *cursor < tokens.len() {
                match &tokens[*cursor] {
                    Token::OpEquals => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        let value = parse_operand(tokens, cursor, "==")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::Equals,
                            value,
                        })
                    }
                    Token::OpNotEquals => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        let value = parse_operand(tokens, cursor, "!=")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::NotEquals,
                            value,
                        })
                    }
                    Token::OpContains => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        let value = parse_operand(tokens, cursor, "contains")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::Contains,
                            value,
                        })
                    }
                    _ => Ok(QueryExpr::MnemonicDirect(ident_str)),
                }
            } else {
                Ok(QueryExpr::MnemonicDirect(ident_str))
            }
        }
        Token::StringLiteral(s) => {
            *cursor += 1;
            Ok(QueryExpr::MnemonicDirect(s.clone()))
        }
        other => Err(QueryError::Malformed(format!("Unexpected token '{other}'"))),
    }
}

fn parse_operand(
    tokens: &[Token],
    cursor: &mut usize,
    op_name: &str,
) -> Result<QueryOperand, QueryError> {
    if *cursor >= tokens.len() {
        return Err(QueryError::MissingValue(op_name.to_string()));
    }
    match &tokens[*cursor] {
        Token::StringLiteral(s) => {
            let val = s.clone();
            *cursor += 1;
            Ok(QueryOperand::String(val))
        }
        Token::Ident(s) => {
            let val = s.clone();
            *cursor += 1;
            Ok(QueryOperand::Bare(val))
        }
        _ => Err(QueryError::MissingValue(op_name.to_string())),
    }
}

fn is_valid_bare_typed_literal(s: &str) -> bool {
    if s == "nil"
        || s == "true"
        || s == "false"
        || s == "+0"
        || s == "-0"
        || s == "0"
        || s == "+0.0"
        || s == "-0.0"
    {
        return true;
    }
    s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok()
}

fn validate_expr(expr: &QueryExpr, chunk: &Chunk) -> Result<(), QueryError> {
    match expr {
        QueryExpr::And(l, r) | QueryExpr::Or(l, r) => {
            validate_expr(l, chunk)?;
            validate_expr(r, chunk)?;
            Ok(())
        }
        QueryExpr::MnemonicDirect(_) => Ok(()),
        QueryExpr::Comparison { field, op, value } => {
            const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
            if !LUA51_PROFILES.contains(&chunk.dialect.as_str())
                && matches!(
                    field,
                    QueryField::CalleeStatus
                        | QueryField::CalleePath
                        | QueryField::CalleeLookupKind
                        | QueryField::CalleeLookupKey
                        | QueryField::CalleeReason
                        | QueryField::CallReason
                        | QueryField::CallTarget
                        | QueryField::OriginKind
                        | QueryField::OriginArgumentIndex
                        | QueryField::PrototypeDigest
                )
            {
                return Err(QueryError::InvalidOperand(
                    field.name().to_string(),
                    format!("unavailable for {}", chunk.dialect),
                ));
            }

            match field {
                QueryField::Constant
                | QueryField::String
                | QueryField::CalleePath
                | QueryField::CalleeLookupKey => {
                    if *op == QueryOp::Contains && !value.is_string() {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                _ => {
                    if *op == QueryOp::Contains {
                        return Err(QueryError::InvalidOperator(
                            "contains".to_string(),
                            field.name().to_string(),
                        ));
                    }
                }
            }

            if matches!(
                field,
                QueryField::ConstantType
                    | QueryField::CalleeStatus
                    | QueryField::CalleePath
                    | QueryField::CalleeLookupKind
                    | QueryField::CalleeReason
                    | QueryField::CallReason
                    | QueryField::CallTarget
                    | QueryField::OriginKind
                    | QueryField::InterpretationProfile
                    | QueryField::PrototypeDigest
            ) && !value.is_string()
            {
                return Err(QueryError::InvalidOperand(
                    field.name().to_string(),
                    value.as_str().to_string(),
                ));
            }

            if matches!(
                field,
                QueryField::OriginArgumentIndex
                    | QueryField::EffectReadRegister
                    | QueryField::EffectWriteRegister
                    | QueryField::EffectReadUpvalue
                    | QueryField::EffectWriteUpvalue
            ) && !value.is_bare()
            {
                return Err(QueryError::InvalidOperand(
                    field.name().to_string(),
                    value.as_str().to_string(),
                ));
            }

            match field {
                QueryField::Constant | QueryField::String | QueryField::CalleeLookupKey => {
                    if value.is_bare() && !is_valid_bare_typed_literal(value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::ConstantType => {
                    const VALID: &[&str] = &[
                        "nil",
                        "boolean",
                        "integer",
                        "float",
                        "short-string",
                        "long-string",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::CalleeStatus => {
                    const VALID: &[&str] = &[
                        "resolved-prototype",
                        "lookup-label",
                        "resolved-path",
                        "unresolved",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::CalleeLookupKind => {
                    const VALID: &[&str] = &["gettable", "self"];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::CalleeReason => {
                    const VALID: &[&str] = &[
                        "missing-definition",
                        "control-flow-conflict",
                        "dynamic-key",
                        "overwritten",
                        "call-result",
                        "open-register-window",
                        "unsupported-value",
                        "unsupported-instruction",
                        "mutable-capture",
                        "ambiguous-capture",
                        "path-limit",
                        "analysis-limit",
                        "unreachable",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::CallReason => {
                    const VALID: &[&str] = &[
                        "missing-definition",
                        "control-flow-conflict",
                        "dynamic-key",
                        "overwritten",
                        "call-result",
                        "open-register-window",
                        "unsupported-value",
                        "unsupported-instruction",
                        "mutable-capture",
                        "ambiguous-capture",
                        "path-limit",
                        "analysis-limit",
                        "unreachable",
                        "symbolic-path-only",
                        "missing-prototype-store",
                        "multiple-prototype-stores",
                        "non-closure-store",
                        "ambiguous-store-value",
                        "lookup-label-only",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::OriginKind => {
                    const VALID: &[&str] = &[
                        "literal",
                        "parameter",
                        "upvalue",
                        "prototype",
                        "global",
                        "field",
                        "call-result",
                        "concat",
                        "table",
                        "table-literal",
                        "unary",
                        "binary",
                        "alternatives",
                        "unknown",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::OriginArgumentIndex => {
                    if value.as_str().parse::<usize>().is_err() {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::InterpretationProfile => {
                    const VALID: &[&str] = &[
                        "lua5.1",
                        "lua5.1-lnum32",
                        "lua5.1-stock32",
                        "lua5.2",
                        "lua5.3",
                        "lua5.4",
                        "lua5.5",
                    ];
                    if !VALID.contains(&value.as_str()) {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::EffectReadRegister | QueryField::EffectWriteRegister => {
                    if value.as_str().parse::<u8>().is_err() {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::EffectReadUpvalue | QueryField::EffectWriteUpvalue => {
                    if value.as_str().parse::<u8>().is_err() {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                QueryField::CallTarget => {
                    let Some(proto_str) = value.as_str().strip_prefix("proto:") else {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    };
                    let Ok(path) = proto_str.parse::<luad_core::id::ProtoPath>() else {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    };
                    if find_proto(&chunk.main_proto, &path).is_none() {
                        return Err(QueryError::InvalidOperand(
                            field.name().to_string(),
                            value.as_str().to_string(),
                        ));
                    }
                }
                _ => {}
            }
            Ok(())
        }
    }
}

fn compute_cursor_context_checksum(
    chunk: &Chunk,
    where_clause: Option<&str>,
    offset: usize,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(chunk.sha256.as_bytes());
    hasher.update(where_clause.unwrap_or("").as_bytes());
    hasher.update(offset.to_le_bytes());
    let hash = hex::encode(hasher.finalize());
    hash[..8].to_string()
}

fn callee_reason_str(r: &CalleeUnresolvedReason) -> &'static str {
    match r {
        CalleeUnresolvedReason::MissingDefinition => "missing-definition",
        CalleeUnresolvedReason::ControlFlowConflict => "control-flow-conflict",
        CalleeUnresolvedReason::DynamicKey => "dynamic-key",
        CalleeUnresolvedReason::Overwritten => "overwritten",
        CalleeUnresolvedReason::CallResult => "call-result",
        CalleeUnresolvedReason::OpenRegisterWindow => "open-register-window",
        CalleeUnresolvedReason::UnsupportedValue => "unsupported-value",
        CalleeUnresolvedReason::UnsupportedInstruction => "unsupported-instruction",
        CalleeUnresolvedReason::MutableCapture => "mutable-capture",
        CalleeUnresolvedReason::AmbiguousCapture => "ambiguous-capture",
        CalleeUnresolvedReason::PathLimit => "path-limit",
        CalleeUnresolvedReason::AnalysisLimit => "analysis-limit",
        CalleeUnresolvedReason::Unreachable => "unreachable",
    }
}

fn call_reason_str(r: &CallRelationUnresolvedReason) -> &'static str {
    match r {
        CallRelationUnresolvedReason::MissingDefinition => "missing-definition",
        CallRelationUnresolvedReason::ControlFlowConflict => "control-flow-conflict",
        CallRelationUnresolvedReason::DynamicKey => "dynamic-key",
        CallRelationUnresolvedReason::Overwritten => "overwritten",
        CallRelationUnresolvedReason::CallResult => "call-result",
        CallRelationUnresolvedReason::OpenRegisterWindow => "open-register-window",
        CallRelationUnresolvedReason::UnsupportedValue => "unsupported-value",
        CallRelationUnresolvedReason::UnsupportedInstruction => "unsupported-instruction",
        CallRelationUnresolvedReason::MutableCapture => "mutable-capture",
        CallRelationUnresolvedReason::AmbiguousCapture => "ambiguous-capture",
        CallRelationUnresolvedReason::PathLimit => "path-limit",
        CallRelationUnresolvedReason::AnalysisLimit => "analysis-limit",
        CallRelationUnresolvedReason::Unreachable => "unreachable",
        CallRelationUnresolvedReason::SymbolicPathOnly => "symbolic-path-only",
        CallRelationUnresolvedReason::MissingPrototypeStore => "missing-prototype-store",
        CallRelationUnresolvedReason::MultiplePrototypeStores => "multiple-prototype-stores",
        CallRelationUnresolvedReason::NonClosureStore => "non-closure-store",
        CallRelationUnresolvedReason::AmbiguousStoreValue => "ambiguous-store-value",
        CallRelationUnresolvedReason::LookupLabelOnly => "lookup-label-only",
    }
}

fn origin_kind_str(k: &OriginExpressionKind) -> &'static str {
    match k {
        OriginExpressionKind::Literal { .. } => "literal",
        OriginExpressionKind::Parameter { .. } => "parameter",
        OriginExpressionKind::Upvalue { .. } => "upvalue",
        OriginExpressionKind::Prototype { .. } => "prototype",
        OriginExpressionKind::Global { .. } => "global",
        OriginExpressionKind::Field { .. } => "field",
        OriginExpressionKind::CallResult { .. } => "call-result",
        OriginExpressionKind::Concat { .. } => "concat",
        OriginExpressionKind::Table { .. } => "table",
        OriginExpressionKind::TableLiteral { .. } => "table-literal",
        OriginExpressionKind::Unary { .. } => "unary",
        OriginExpressionKind::Binary { .. } => "binary",
        OriginExpressionKind::Alternatives { .. } => "alternatives",
        OriginExpressionKind::Unknown { .. } => "unknown",
    }
}

fn match_constant(c: &ConstantValue, op: QueryOp, operand: &QueryOperand) -> bool {
    match operand {
        QueryOperand::String(s) => match c {
            ConstantValue::ShortString(str_val) | ConstantValue::LongString(str_val) => match op {
                QueryOp::Equals => str_val.display == *s,
                QueryOp::NotEquals => str_val.display != *s,
                QueryOp::Contains => str_val.display.contains(s),
            },
            _ => match op {
                QueryOp::Equals => false,
                QueryOp::NotEquals => true,
                QueryOp::Contains => false,
            },
        },
        QueryOperand::Bare(b) => {
            if op == QueryOp::Contains {
                return false;
            }
            let is_eq = match c {
                ConstantValue::Nil => b == "nil",
                ConstantValue::Boolean(val) => {
                    if b == "true" {
                        *val
                    } else if b == "false" {
                        !*val
                    } else {
                        false
                    }
                }
                ConstantValue::Integer { val, .. } => {
                    if b == "+0" || b == "0" || b == "+0.0" || b == "0.0" {
                        *val == 0
                    } else if b == "-0" || b == "-0.0" {
                        false
                    } else if let Ok(i) = b.parse::<i64>() {
                        *val == i
                    } else if let Ok(f) = b.parse::<f64>() {
                        *val as f64 == f && (*val as f64).to_bits() == f.to_bits()
                    } else {
                        false
                    }
                }
                ConstantValue::Float { val, .. } => {
                    let target_bits = if b == "0" || b == "0.0" || b == "+0.0" || b == "+0" {
                        Some((0.0f64).to_bits())
                    } else if b == "-0" || b == "-0.0" {
                        Some((-0.0f64).to_bits())
                    } else if let Ok(f) = b.parse::<f64>() {
                        Some(f.to_bits())
                    } else {
                        None
                    };
                    if let Some(tb) = target_bits {
                        val.to_bits() == tb
                    } else {
                        false
                    }
                }
                ConstantValue::ShortString(_) | ConstantValue::LongString(_) => false,
            };
            match op {
                QueryOp::Equals => is_eq,
                QueryOp::NotEquals => !is_eq,
                QueryOp::Contains => false,
            }
        }
    }
}

struct QueryContext<'a> {
    dialect: &'a str,
    callees: BTreeMap<StableId, &'a CalleeFact>,
    call_relations: BTreeMap<StableId, &'a CallRelationFact>,
    origins: BTreeMap<StableId, &'a CallOriginFact>,
    proto_identities: BTreeMap<StableId, &'a PrototypeIdentityFact>,
}

fn expr_uses(expr: Option<&QueryExpr>, predicate: impl Fn(QueryField) -> bool + Copy) -> bool {
    match expr {
        Some(QueryExpr::Comparison { field, .. }) => predicate(*field),
        Some(QueryExpr::And(left, right) | QueryExpr::Or(left, right)) => {
            expr_uses(Some(left), predicate) || expr_uses(Some(right), predicate)
        }
        Some(QueryExpr::MnemonicDirect(_)) | None => false,
    }
}

/// Execute a structured query over a chunk with limit and cursor pagination.
pub fn execute_query(
    chunk: &Chunk,
    where_expr: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<QueryResponse, QueryError> {
    execute_query_with_total(chunk, where_expr, limit, cursor).map(|(resp, _)| resp)
}

/// Execute a structured query over a chunk, returning both the paginated QueryResponse and total match count.
pub fn execute_query_with_total(
    chunk: &Chunk,
    where_expr: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<(QueryResponse, usize), QueryError> {
    let parsed_ast = match where_expr {
        Some(expr) if !expr.trim().is_empty() => {
            let ast = QueryExpr::parse(expr)?;
            validate_expr(&ast, chunk)?;
            Some(ast)
        }
        _ => None,
    };

    const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
    let is_lua51 = LUA51_PROFILES.contains(&chunk.dialect.as_str());
    let callee_analysis = (is_lua51
        && expr_uses(parsed_ast.as_ref(), |field| {
            matches!(
                field,
                QueryField::CalleeStatus
                    | QueryField::CalleePath
                    | QueryField::CalleeLookupKind
                    | QueryField::CalleeLookupKey
                    | QueryField::CalleeReason
            )
        }))
    .then(|| crate::analyze_chunk_callees(chunk));
    let call_relation_analysis = (is_lua51
        && expr_uses(parsed_ast.as_ref(), |field| {
            matches!(field, QueryField::CallReason | QueryField::CallTarget)
        }))
    .then(|| crate::analyze_chunk_call_relations(chunk));
    let origin_analysis = (is_lua51
        && expr_uses(parsed_ast.as_ref(), |field| {
            matches!(
                field,
                QueryField::OriginKind | QueryField::OriginArgumentIndex
            )
        }))
    .then(|| crate::analyze_chunk_origins(chunk));
    let proto_identity_analysis = if is_lua51
        && expr_uses(parsed_ast.as_ref(), |field| {
            field == QueryField::PrototypeDigest
        }) {
        Some(
            crate::analyze_chunk_prototype_identities(chunk)
                .map_err(|error| QueryError::FactDerivation(error.to_string()))?,
        )
    } else {
        None
    };

    let mut callees = BTreeMap::new();
    if let Some(ca) = &callee_analysis {
        for proto in &ca.prototypes {
            for fact in &proto.calls {
                callees.insert(fact.call_id.clone(), fact);
            }
        }
    }

    let mut call_relations = BTreeMap::new();
    if let Some(cra) = &call_relation_analysis {
        for proto in &cra.prototypes {
            for fact in &proto.calls {
                call_relations.insert(fact.call_id.clone(), fact);
            }
        }
    }

    let mut origins = BTreeMap::new();
    if let Some(oa) = &origin_analysis {
        for proto in &oa.prototypes {
            for fact in &proto.calls {
                origins.insert(fact.call_id.clone(), fact);
            }
        }
    }

    let mut proto_identities = BTreeMap::new();
    if let Some(pia) = &proto_identity_analysis {
        for fact in &pia.prototypes {
            proto_identities.insert(fact.proto_id.clone(), fact);
        }
    }

    let ctx = QueryContext {
        dialect: &chunk.dialect,
        callees,
        call_relations,
        origins,
        proto_identities,
    };

    let mut all_matches = Vec::new();

    // 1. Chunk / interpretation entity
    if eval_interpretation(&chunk.dialect, parsed_ast.as_ref()) {
        all_matches.push(QueryMatch {
            id: StableId::Chunk,
            kind: "interpretation".to_string(),
            summary: format!("Interpretation profile {}", chunk.dialect),
        });
    }

    // 2. Prototype tree
    collect_proto_matches(
        &ctx,
        &chunk.main_proto,
        parsed_ast.as_ref(),
        &mut all_matches,
    );

    let total_matches = all_matches.len();

    let start_index = if let Some(c) = cursor {
        if let Some(rest) = c.strip_prefix("cur_") {
            let parts: Vec<&str> = rest.split('_').collect();
            if parts.len() == 2 {
                let sig_provided = parts[0];
                if let Ok(idx) = parts[1].parse::<usize>() {
                    let expected_sig = compute_cursor_context_checksum(chunk, where_expr, idx);
                    if sig_provided == expected_sig && idx <= total_matches {
                        idx
                    } else {
                        return Err(QueryError::InvalidCursor(c.to_string(), total_matches));
                    }
                } else {
                    return Err(QueryError::InvalidCursor(c.to_string(), total_matches));
                }
            } else {
                return Err(QueryError::InvalidCursor(c.to_string(), total_matches));
            }
        } else {
            return Err(QueryError::InvalidCursor(c.to_string(), total_matches));
        }
    } else {
        0
    };

    let page_items: Vec<QueryMatch> = all_matches
        .into_iter()
        .skip(start_index)
        .take(limit)
        .collect();

    let returned_count = page_items.len();
    let next_index = start_index + returned_count;
    let is_truncated = next_index < total_matches;
    let next_cursor = if is_truncated {
        let next_sig = compute_cursor_context_checksum(chunk, where_expr, next_index);
        Some(format!("cur_{next_sig}_{next_index}"))
    } else {
        None
    };

    Ok((
        QueryResponse {
            matches: page_items,
            count: returned_count,
            next_cursor,
            is_truncated,
        },
        total_matches,
    ))
}

fn collect_proto_matches(
    ctx: &QueryContext<'_>,
    proto: &Prototype,
    where_expr: Option<&QueryExpr>,
    results: &mut Vec<QueryMatch>,
) {
    let proto_id = StableId::proto(proto.path.clone());
    let proto_digest = ctx
        .proto_identities
        .get(&proto_id)
        .map(|f| f.digest.as_str());

    if eval_prototype(proto_digest, where_expr) {
        results.push(QueryMatch {
            id: proto_id,
            kind: "prototype".to_string(),
            summary: format!("Prototype {}", proto.path),
        });
    }

    let lifted = crate::lift_proto_for_dialect(ctx.dialect, proto);

    for sem in &lifted {
        let callee = ctx.callees.get(&sem.id).copied();
        let call_rel = ctx.call_relations.get(&sem.id).copied();
        let origin = ctx.origins.get(&sem.id).copied();

        if eval_instruction(sem, callee, call_rel, origin, where_expr) {
            results.push(QueryMatch {
                id: sem.id.clone(),
                kind: "instruction".to_string(),
                summary: format!("{:<12} {}", sem.mnemonic, sem.explanation),
            });
        }
    }

    for c in &proto.constants {
        if eval_constant(c, where_expr) {
            results.push(QueryMatch {
                id: c.id.clone(),
                kind: "constant".to_string(),
                summary: format!("Constant K[{}] = {:?}", c.index, c.value),
            });
        }
    }

    for child in &proto.protos {
        collect_proto_matches(ctx, child, where_expr, results);
    }
}

fn eval_interpretation(dialect: &str, expr: Option<&QueryExpr>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    eval_interpretation_expr(dialect, expr)
}

fn eval_interpretation_expr(dialect: &str, expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => match field {
            QueryField::InterpretationProfile => match op {
                QueryOp::Equals => dialect == value.as_str(),
                QueryOp::NotEquals => dialect != value.as_str(),
                QueryOp::Contains => false,
            },
            _ => false,
        },
        QueryExpr::MnemonicDirect(_) => false,
        QueryExpr::And(l, r) => {
            eval_interpretation_expr(dialect, l) && eval_interpretation_expr(dialect, r)
        }
        QueryExpr::Or(l, r) => {
            eval_interpretation_expr(dialect, l) || eval_interpretation_expr(dialect, r)
        }
    }
}

fn eval_prototype(digest: Option<&str>, expr: Option<&QueryExpr>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    eval_prototype_expr(digest, expr)
}

fn eval_prototype_expr(digest: Option<&str>, expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => match field {
            QueryField::PrototypeDigest => match op {
                QueryOp::Equals => digest == Some(value.as_str()),
                QueryOp::NotEquals => digest != Some(value.as_str()),
                QueryOp::Contains => false,
            },
            _ => false,
        },
        QueryExpr::MnemonicDirect(_) => false,
        QueryExpr::And(l, r) => eval_prototype_expr(digest, l) && eval_prototype_expr(digest, r),
        QueryExpr::Or(l, r) => eval_prototype_expr(digest, l) || eval_prototype_expr(digest, r),
    }
}

fn eval_instruction(
    sem: &SemanticInstruction,
    callee: Option<&CalleeFact>,
    call_relation: Option<&CallRelationFact>,
    origin: Option<&CallOriginFact>,
    expr: Option<&QueryExpr>,
) -> bool {
    let Some(expr) = expr else {
        return true;
    };
    eval_instruction_expr(sem, callee, call_relation, origin, expr)
}

fn eval_instruction_expr(
    sem: &SemanticInstruction,
    callee: Option<&CalleeFact>,
    call_relation: Option<&CallRelationFact>,
    origin: Option<&CallOriginFact>,
    expr: &QueryExpr,
) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => {
            match field {
                QueryField::Opcode | QueryField::Mnemonic => {
                    let target_upper = value.as_str().to_uppercase();
                    let clean_target = target_upper.strip_prefix("OP_").unwrap_or(&target_upper);
                    let current = sem.mnemonic.to_uppercase();
                    let clean_current = current.strip_prefix("OP_").unwrap_or(&current);
                    match op {
                        QueryOp::Equals => clean_current == clean_target,
                        QueryOp::NotEquals => clean_current != clean_target,
                        QueryOp::Contains => false,
                    }
                }
                QueryField::EffectWriteUpvalue => {
                    if let Ok(idx) = value.as_str().parse::<u8>() {
                        let has = sem.writes.iter().any(
                            |w| matches!(w, EffectTarget::Upvalue { index, .. } if *index == idx),
                        );
                        match op {
                            QueryOp::Equals => has,
                            QueryOp::NotEquals => !has,
                            QueryOp::Contains => false,
                        }
                    } else {
                        false
                    }
                }
                QueryField::EffectReadUpvalue => {
                    if let Ok(idx) = value.as_str().parse::<u8>() {
                        let has = sem.reads.iter().any(
                            |r| matches!(r, EffectTarget::Upvalue { index, .. } if *index == idx),
                        );
                        match op {
                            QueryOp::Equals => has,
                            QueryOp::NotEquals => !has,
                            QueryOp::Contains => false,
                        }
                    } else {
                        false
                    }
                }
                QueryField::EffectWriteRegister => {
                    if let Ok(reg) = value.as_str().parse::<u8>() {
                        let has = sem.writes.iter().any(
                            |w| matches!(w, EffectTarget::Register { index: r, .. } if *r == reg),
                        );
                        match op {
                            QueryOp::Equals => has,
                            QueryOp::NotEquals => !has,
                            QueryOp::Contains => false,
                        }
                    } else {
                        false
                    }
                }
                QueryField::EffectReadRegister => {
                    if let Ok(reg) = value.as_str().parse::<u8>() {
                        let has = sem.reads.iter().any(
                            |r| matches!(r, EffectTarget::Register { index: r, .. } if *r == reg),
                        );
                        match op {
                            QueryOp::Equals => has,
                            QueryOp::NotEquals => !has,
                            QueryOp::Contains => false,
                        }
                    } else {
                        false
                    }
                }
                QueryField::CalleeStatus => {
                    if let Some(cf) = callee {
                        let status = match &cf.resolution {
                            CalleeResolution::ResolvedPrototype { .. } => "resolved-prototype",
                            CalleeResolution::LookupLabel { .. } => "lookup-label",
                            CalleeResolution::ResolvedPath { .. } => "resolved-path",
                            CalleeResolution::Unresolved { .. } => "unresolved",
                        };
                        match op {
                            QueryOp::Equals => status == value.as_str(),
                            QueryOp::NotEquals => status != value.as_str(),
                            QueryOp::Contains => false,
                        }
                    } else {
                        false
                    }
                }
                QueryField::CalleePath => {
                    if let Some(cf) = callee {
                        if let CalleeResolution::ResolvedPath { segments, .. } = &cf.resolution {
                            let path = segments.join(".");
                            match op {
                                QueryOp::Equals => path == value.as_str(),
                                QueryOp::NotEquals => path != value.as_str(),
                                QueryOp::Contains => path.contains(value.as_str()),
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::CalleeLookupKind => {
                    if let Some(cf) = callee {
                        if let CalleeResolution::LookupLabel { lookup_kind, .. } = &cf.resolution {
                            let kind_str = match lookup_kind {
                                CalleeLookupKind::Gettable => "gettable",
                                CalleeLookupKind::SelfOp => "self",
                            };
                            match op {
                                QueryOp::Equals => kind_str == value.as_str(),
                                QueryOp::NotEquals => kind_str != value.as_str(),
                                QueryOp::Contains => false,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::CalleeLookupKey => {
                    if let Some(cf) = callee {
                        if let CalleeResolution::LookupLabel { key, .. } = &cf.resolution {
                            match_constant(key, *op, value)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::CalleeReason => {
                    if let Some(cf) = callee {
                        if let CalleeResolution::Unresolved { reason } = &cf.resolution {
                            let r_str = callee_reason_str(reason);
                            match op {
                                QueryOp::Equals => r_str == value.as_str(),
                                QueryOp::NotEquals => r_str != value.as_str(),
                                QueryOp::Contains => false,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::CallReason => {
                    if let Some(cr) = call_relation {
                        if let CallRelationResolution::Unresolved { reason, .. } = &cr.resolution {
                            let r_str = call_reason_str(reason);
                            match op {
                                QueryOp::Equals => r_str == value.as_str(),
                                QueryOp::NotEquals => r_str != value.as_str(),
                                QueryOp::Contains => false,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::CallTarget => {
                    if let Some(cr) = call_relation {
                        if let CallRelationResolution::Resolved { callee, .. } = &cr.resolution {
                            let target = format!("proto:{callee}");
                            match op {
                                QueryOp::Equals => target == value.as_str(),
                                QueryOp::NotEquals => target != value.as_str(),
                                QueryOp::Contains => false,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::OriginKind => {
                    if let Some(of) = origin {
                        if let CallArgumentWindow::Fixed { arguments } = &of.argument_window {
                            let has = arguments
                                .iter()
                                .any(|arg| origin_kind_str(&arg.origin.kind) == value.as_str());
                            match op {
                                QueryOp::Equals => has,
                                QueryOp::NotEquals => !has,
                                QueryOp::Contains => false,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                QueryField::OriginArgumentIndex => {
                    if let Some(of) = origin {
                        if let CallArgumentWindow::Fixed { arguments } = &of.argument_window {
                            if let Ok(idx) = value.as_str().parse::<usize>() {
                                let has = arguments.iter().any(|arg| arg.argument_index == idx);
                                match op {
                                    QueryOp::Equals => has,
                                    QueryOp::NotEquals => !has,
                                    QueryOp::Contains => false,
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
        QueryExpr::MnemonicDirect(target) => {
            let target_upper = target.to_uppercase();
            let clean_target = target_upper.strip_prefix("OP_").unwrap_or(&target_upper);
            let current = sem.mnemonic.to_uppercase();
            let clean_current = current.strip_prefix("OP_").unwrap_or(&current);
            clean_current == clean_target
        }
        QueryExpr::And(l, r) => {
            eval_instruction_expr(sem, callee, call_relation, origin, l)
                && eval_instruction_expr(sem, callee, call_relation, origin, r)
        }
        QueryExpr::Or(l, r) => {
            eval_instruction_expr(sem, callee, call_relation, origin, l)
                || eval_instruction_expr(sem, callee, call_relation, origin, r)
        }
    }
}

fn eval_constant(c: &Constant, expr: Option<&QueryExpr>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    eval_constant_expr(c, expr)
}

fn eval_constant_expr(c: &Constant, expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => match field {
            QueryField::ConstantType => {
                let type_str = match &c.value {
                    ConstantValue::Nil => "nil",
                    ConstantValue::Boolean(_) => "boolean",
                    ConstantValue::Integer { .. } => "integer",
                    ConstantValue::Float { .. } => "float",
                    ConstantValue::ShortString(_) => "short-string",
                    ConstantValue::LongString(_) => "long-string",
                };
                match op {
                    QueryOp::Equals => type_str == value.as_str(),
                    QueryOp::NotEquals => type_str != value.as_str(),
                    QueryOp::Contains => false,
                }
            }
            QueryField::Constant | QueryField::String => match_constant(&c.value, *op, value),
            _ => false,
        },
        QueryExpr::MnemonicDirect(_) => false,
        QueryExpr::And(l, r) => eval_constant_expr(c, l) && eval_constant_expr(c, r),
        QueryExpr::Or(l, r) => eval_constant_expr(c, l) || eval_constant_expr(c, r),
    }
}
