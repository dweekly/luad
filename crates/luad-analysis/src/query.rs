//! Safe, bounded structured query engine over bytecode instructions and artifacts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, SemanticInstruction};
use luad_core::model::{Chunk, ConstantValue, Prototype};

/// Query error conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    Malformed(String),
    UnknownField(String),
    InvalidOperator(String, String),
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
            Self::InvalidCursor(c, max) => write!(
                f,
                "Invalid cursor '{c}': cursor must be an integer between 0 and {max}"
            ),
            Self::MissingValue(op) => write!(f, "Missing query value after operator '{op}'"),
            Self::UnbalancedParentheses => write!(f, "Unbalanced parentheses in query expression"),
            Self::TrailingTokens(tokens) => write!(f, "Unexpected trailing tokens: '{tokens}'"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Result record returned by a query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueryMatch {
    /// Stable identifier of the matching artifact.
    pub id: StableId,
    /// Artifact category ("instruction", "constant", "prototype", "upvalue").
    pub kind: String,
    /// Human-readable match summary.
    pub summary: String,
}

/// Paginated query response document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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

/// Parsed Abstract Syntax Tree for a where expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryExpr {
    Comparison {
        field: QueryField,
        op: QueryOp,
        value: String,
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
        } else if c == '=' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::OpEquals);
            i += 2;
        } else if c == '!' && i + 1 < len && chars[i + 1] == '=' {
            tokens.push(Token::OpNotEquals);
            i += 2;
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
                    s.push(chars[i]);
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
            // Identifier or keyword
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

    // Comparison or direct token
    match &tokens[*cursor] {
        Token::Ident(name) => {
            let ident_str = name.clone();
            *cursor += 1;

            if *cursor < tokens.len() {
                match &tokens[*cursor] {
                    Token::OpEquals => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        let value = parse_value(tokens, cursor, "==")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::Equals,
                            value,
                        })
                    }
                    Token::OpNotEquals => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        let value = parse_value(tokens, cursor, "!=")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::NotEquals,
                            value,
                        })
                    }
                    Token::OpContains => {
                        *cursor += 1;
                        let field = QueryField::parse(&ident_str)?;
                        if field != QueryField::Constant && field != QueryField::String {
                            return Err(QueryError::InvalidOperator(
                                "contains".to_string(),
                                field.name().to_string(),
                            ));
                        }
                        let value = parse_value(tokens, cursor, "contains")?;
                        Ok(QueryExpr::Comparison {
                            field,
                            op: QueryOp::Contains,
                            value,
                        })
                    }
                    _ => {
                        // Direct mnemonic shortcut without operator, e.g. "CALL" or "CLOSURE"
                        Ok(QueryExpr::MnemonicDirect(ident_str))
                    }
                }
            } else {
                // Direct mnemonic shortcut
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

fn parse_value(tokens: &[Token], cursor: &mut usize, op_name: &str) -> Result<String, QueryError> {
    if *cursor >= tokens.len() {
        return Err(QueryError::MissingValue(op_name.to_string()));
    }
    match &tokens[*cursor] {
        Token::Ident(s) | Token::StringLiteral(s) => {
            let val = s.clone();
            *cursor += 1;
            Ok(val)
        }
        _ => Err(QueryError::MissingValue(op_name.to_string())),
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

/// Execute a structured query over a chunk with limit and cursor pagination.
pub fn execute_query(
    chunk: &Chunk,
    where_expr: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<QueryResponse, QueryError> {
    let parsed_ast = match where_expr {
        Some(expr) if !expr.trim().is_empty() => Some(QueryExpr::parse(expr)?),
        _ => None,
    };

    let mut all_matches = Vec::new();
    collect_proto_matches(
        &chunk.dialect,
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
        } else if let Ok(idx) = c.parse::<usize>() {
            if idx <= total_matches {
                idx
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

    Ok(QueryResponse {
        matches: page_items,
        count: returned_count,
        next_cursor,
        is_truncated,
    })
}

fn collect_proto_matches(
    dialect: &str,
    proto: &Prototype,
    where_expr: Option<&QueryExpr>,
    results: &mut Vec<QueryMatch>,
) {
    let lifted = crate::lift_proto_for_dialect(dialect, proto);

    for sem in &lifted {
        if matches_instruction(sem, where_expr) {
            results.push(QueryMatch {
                id: sem.id.clone(),
                kind: "instruction".to_string(),
                summary: format!("{:<12} {}", sem.mnemonic, sem.explanation),
            });
        }
    }

    for c in &proto.constants {
        if matches_constant(c, where_expr) {
            results.push(QueryMatch {
                id: c.id.clone(),
                kind: "constant".to_string(),
                summary: format!("Constant K[{}] = {:?}", c.index, c.value),
            });
        }
    }

    for child in &proto.protos {
        collect_proto_matches(dialect, child, where_expr, results);
    }
}

fn matches_instruction(sem: &SemanticInstruction, expr: Option<&QueryExpr>) -> bool {
    let Some(expr) = expr else {
        return true;
    };
    eval_instruction_expr(sem, expr)
}

fn eval_instruction_expr(sem: &SemanticInstruction, expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => {
            match field {
                QueryField::Opcode | QueryField::Mnemonic => {
                    let target_upper = value.to_uppercase();
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
                    if let Ok(idx) = value.parse::<u8>() {
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
                    if let Ok(idx) = value.parse::<u8>() {
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
                    if let Ok(reg) = value.parse::<u8>() {
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
                    if let Ok(reg) = value.parse::<u8>() {
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
                QueryField::Constant | QueryField::String => false,
            }
        }
        QueryExpr::MnemonicDirect(target) => {
            let target_upper = target.to_uppercase();
            let clean_target = target_upper.strip_prefix("OP_").unwrap_or(&target_upper);
            let current = sem.mnemonic.to_uppercase();
            let clean_current = current.strip_prefix("OP_").unwrap_or(&current);
            clean_current == clean_target
        }
        QueryExpr::And(l, r) => eval_instruction_expr(sem, l) && eval_instruction_expr(sem, r),
        QueryExpr::Or(l, r) => eval_instruction_expr(sem, l) || eval_instruction_expr(sem, r),
    }
}

fn matches_constant(c: &luad_core::model::Constant, expr: Option<&QueryExpr>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    eval_constant_expr(c, expr)
}

fn eval_constant_expr(c: &luad_core::model::Constant, expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Comparison { field, op, value } => match field {
            QueryField::Constant | QueryField::String => match &c.value {
                ConstantValue::ShortString(s) | ConstantValue::LongString(s) => match op {
                    QueryOp::Contains => s.display.contains(value),
                    QueryOp::Equals => s.display == *value,
                    QueryOp::NotEquals => s.display != *value,
                },
                ConstantValue::Integer { val, .. } => match op {
                    QueryOp::Equals => {
                        if let Ok(v) = value.parse::<i64>() {
                            *val == v
                        } else {
                            false
                        }
                    }
                    QueryOp::NotEquals => {
                        if let Ok(v) = value.parse::<i64>() {
                            *val != v
                        } else {
                            true
                        }
                    }
                    QueryOp::Contains => false,
                },
                _ => false,
            },
            _ => false,
        },
        QueryExpr::MnemonicDirect(_) => false,
        QueryExpr::And(l, r) => eval_constant_expr(c, l) && eval_constant_expr(c, r),
        QueryExpr::Or(l, r) => eval_constant_expr(c, l) || eval_constant_expr(c, r),
    }
}
