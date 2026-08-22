//! Deterministic stable identity taxonomy for chunks, prototypes, instructions,
//! blocks, constants, upvalues, locals, and diagnostics.

use std::fmt;
use std::str::FromStr;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Prototype structural path, representing nesting hierarchy (e.g. "0/2/1").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtoPath(pub Vec<usize>);

impl ProtoPath {
    /// Root prototype path "0".
    #[must_use]
    pub fn root() -> Self {
        Self(vec![0])
    }

    /// Create child path by appending child index.
    #[must_use]
    pub fn child(&self, index: usize) -> Self {
        let mut path = self.0.clone();
        path.push(index);
        Self(path)
    }

    /// Depth of prototype nesting (root = 0).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.len().saturating_sub(1)
    }
}

impl fmt::Display for ProtoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "0")
        } else {
            let parts: Vec<String> = self.0.iter().map(|n| n.to_string()).collect();
            write!(f, "{}", parts.join("/"))
        }
    }
}

impl Serialize for ProtoPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProtoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for ProtoPath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Empty prototype path".to_string());
        }
        let parts: Result<Vec<usize>, _> = s.split('/').map(|p| p.parse::<usize>()).collect();
        match parts {
            Ok(vec) if !vec.is_empty() => Ok(Self(vec)),
            Ok(_) => Err("Invalid empty prototype path".to_string()),
            Err(e) => Err(format!("Invalid prototype index in path '{s}': {e}")),
        }
    }
}

impl JsonSchema for ProtoPath {
    fn schema_name() -> String {
        "ProtoPath".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(gen)
    }
}

/// A stable, deterministic identifier for any element within an analyzed Lua chunk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StableId {
    /// The chunk itself.
    Chunk,
    /// A prototype by structural path: `proto:0/2/1`.
    Proto(ProtoPath),
    /// An instruction by prototype path and program counter: `proto:0/2:pc:37`.
    Instruction { proto: ProtoPath, pc: usize },
    /// A basic block by prototype path and block index: `proto:0/2:block:5`.
    Block { proto: ProtoPath, index: usize },
    /// A constant by prototype path and 0-indexed constant index: `proto:0/2:k:7`.
    Constant { proto: ProtoPath, index: usize },
    /// An upvalue by prototype path and 0-indexed upvalue index: `proto:0/2:upvalue:1`.
    Upvalue { proto: ProtoPath, index: usize },
    /// A local variable by prototype path and 0-indexed local variable index: `proto:0/2:local:0`.
    Local { proto: ProtoPath, index: usize },
    /// A diagnostic code attached to a target ID: `diagnostic:L54-JUMP-003:proto:0/2:pc:37`.
    Diagnostic { code: String, target: Box<StableId> },
}

impl StableId {
    /// Construct a prototype stable ID from a path.
    #[must_use]
    pub fn proto(path: ProtoPath) -> Self {
        Self::Proto(path)
    }

    /// Construct an instruction stable ID.
    #[must_use]
    pub fn instruction(proto: ProtoPath, pc: usize) -> Self {
        Self::Instruction { proto, pc }
    }

    /// Construct a basic block stable ID.
    #[must_use]
    pub fn block(proto: ProtoPath, index: usize) -> Self {
        Self::Block { proto, index }
    }

    /// Construct a constant stable ID.
    #[must_use]
    pub fn constant(proto: ProtoPath, index: usize) -> Self {
        Self::Constant { proto, index }
    }

    /// Construct an upvalue stable ID.
    #[must_use]
    pub fn upvalue(proto: ProtoPath, index: usize) -> Self {
        Self::Upvalue { proto, index }
    }

    /// Construct a local variable stable ID.
    #[must_use]
    pub fn local(proto: ProtoPath, index: usize) -> Self {
        Self::Local { proto, index }
    }

    /// Construct a diagnostic stable ID.
    #[must_use]
    pub fn diagnostic(code: impl Into<String>, target: StableId) -> Self {
        Self::Diagnostic {
            code: code.into(),
            target: Box::new(target),
        }
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunk => write!(f, "chunk"),
            Self::Proto(path) => write!(f, "proto:{path}"),
            Self::Instruction { proto, pc } => write!(f, "proto:{proto}:pc:{pc}"),
            Self::Block { proto, index } => write!(f, "proto:{proto}:block:{index}"),
            Self::Constant { proto, index } => write!(f, "proto:{proto}:k:{index}"),
            Self::Upvalue { proto, index } => write!(f, "proto:{proto}:upvalue:{index}"),
            Self::Local { proto, index } => write!(f, "proto:{proto}:local:{index}"),
            Self::Diagnostic { code, target } => write!(f, "diagnostic:{code}:{target}"),
        }
    }
}

impl FromStr for StableId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "chunk" {
            return Ok(Self::Chunk);
        }

        if let Some(rest) = s.strip_prefix("diagnostic:") {
            if let Some((code, target_str)) = rest.split_once(':') {
                let target = StableId::from_str(target_str)?;
                return Ok(Self::Diagnostic {
                    code: code.to_string(),
                    target: Box::new(target),
                });
            }
            return Err(format!("Invalid diagnostic stable ID: '{s}'"));
        }

        if let Some(rest) = s.strip_prefix("proto:") {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() == 1 {
                let path = ProtoPath::from_str(parts[0])?;
                return Ok(Self::Proto(path));
            } else if parts.len() == 3 {
                let path = ProtoPath::from_str(parts[0])?;
                let kind = parts[1];
                let idx = parts[2]
                    .parse::<usize>()
                    .map_err(|e| format!("Invalid index in ID '{s}': {e}"))?;
                return match kind {
                    "pc" => Ok(Self::Instruction { proto: path, pc: idx }),
                    "block" => Ok(Self::Block { proto: path, index: idx }),
                    "k" => Ok(Self::Constant { proto: path, index: idx }),
                    "upvalue" => Ok(Self::Upvalue { proto: path, index: idx }),
                    "local" => Ok(Self::Local { proto: path, index: idx }),
                    _ => Err(format!("Unknown artifact kind '{kind}' in ID: '{s}'")),
                };
            }
        }

        Err(format!("Unrecognized stable ID format: '{s}'"))
    }
}

impl Serialize for StableId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for StableId {
    fn schema_name() -> String {
        "StableId".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(gen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_id_round_trips() {
        let test_cases = vec![
            "chunk",
            "proto:0",
            "proto:0/2",
            "proto:0/2/1",
            "proto:0/2:pc:37",
            "proto:0/2:block:5",
            "proto:0/2:k:7",
            "proto:0/2:upvalue:1",
            "proto:0/2:local:0",
            "diagnostic:L54-JUMP-003:proto:0/2:pc:37",
        ];

        for s in test_cases {
            let id: StableId = s.parse().expect("failed to parse stable ID");
            assert_eq!(id.to_string(), s);
        }
    }
}
