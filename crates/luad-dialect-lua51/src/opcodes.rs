//! Lua 5.1 opcode definitions and bitfield decoder.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BITRK_51: u32 = 1 << 8; // 256

/// All 38 official Lua 5.1 opcodes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum Opcode51 {
    Move = 0,
    LoadK = 1,
    LoadBool = 2,
    LoadNil = 3,
    GetUpval = 4,
    GetGlobal = 5,
    GetTable = 6,
    SetGlobal = 7,
    SetUpval = 8,
    SetTable = 9,
    NewTable = 10,
    SelfOp = 11,
    Add = 12,
    Sub = 13,
    Mul = 14,
    Div = 15,
    Mod = 16,
    Pow = 17,
    Unm = 18,
    Not = 19,
    Len = 20,
    Concat = 21,
    Jmp = 22,
    Eq = 23,
    Lt = 24,
    Le = 25,
    Test = 26,
    TestSet = 27,
    Call = 28,
    TailCall = 29,
    Return = 30,
    ForLoop = 31,
    ForPrep = 32,
    TForLoop = 33,
    SetList = 34,
    Close = 35,
    Closure = 36,
    VarArg = 37,
}

impl Opcode51 {
    /// Safe construction of Lua 5.1 opcode without unsafe code.
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Move),
            1 => Some(Self::LoadK),
            2 => Some(Self::LoadBool),
            3 => Some(Self::LoadNil),
            4 => Some(Self::GetUpval),
            5 => Some(Self::GetGlobal),
            6 => Some(Self::GetTable),
            7 => Some(Self::SetGlobal),
            8 => Some(Self::SetUpval),
            9 => Some(Self::SetTable),
            10 => Some(Self::NewTable),
            11 => Some(Self::SelfOp),
            12 => Some(Self::Add),
            13 => Some(Self::Sub),
            14 => Some(Self::Mul),
            15 => Some(Self::Div),
            16 => Some(Self::Mod),
            17 => Some(Self::Pow),
            18 => Some(Self::Unm),
            19 => Some(Self::Not),
            20 => Some(Self::Len),
            21 => Some(Self::Concat),
            22 => Some(Self::Jmp),
            23 => Some(Self::Eq),
            24 => Some(Self::Lt),
            25 => Some(Self::Le),
            26 => Some(Self::Test),
            27 => Some(Self::TestSet),
            28 => Some(Self::Call),
            29 => Some(Self::TailCall),
            30 => Some(Self::Return),
            31 => Some(Self::ForLoop),
            32 => Some(Self::ForPrep),
            33 => Some(Self::TForLoop),
            34 => Some(Self::SetList),
            35 => Some(Self::Close),
            36 => Some(Self::Closure),
            37 => Some(Self::VarArg),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetGlobal => "GETGLOBAL",
            Self::GetTable => "GETTABLE",
            Self::SetGlobal => "SETGLOBAL",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::SelfOp => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Unm => "UNM",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
        }
    }

    #[must_use]
    pub fn mode(self) -> OpMode51 {
        match self {
            Self::Move
            | Self::LoadBool
            | Self::LoadNil
            | Self::GetUpval
            | Self::GetTable
            | Self::SetUpval
            | Self::SetTable
            | Self::NewTable
            | Self::SelfOp
            | Self::Add
            | Self::Sub
            | Self::Mul
            | Self::Div
            | Self::Mod
            | Self::Pow
            | Self::Unm
            | Self::Not
            | Self::Len
            | Self::Concat
            | Self::Eq
            | Self::Lt
            | Self::Le
            | Self::Test
            | Self::TestSet
            | Self::Call
            | Self::TailCall
            | Self::Return
            | Self::TForLoop
            | Self::SetList
            | Self::Close
            | Self::VarArg => OpMode51::IABC,
            Self::LoadK | Self::GetGlobal | Self::SetGlobal | Self::Closure => OpMode51::IABx,
            Self::Jmp | Self::ForLoop | Self::ForPrep => OpMode51::IAsBx,
        }
    }

    /// Returns `true` when executed semantics use `A` as a direct register.
    ///
    /// This is intentionally independent of the opcode mode's set-`A` flag: `TEST`
    /// reads `R(A)`, while comparison opcodes use `A` as a boolean. A `MOVE` or
    /// `GETUPVAL` word serving as a closure-binding descriptor is excluded by its
    /// contextual instruction role before register validation.
    #[must_use]
    pub const fn a_is_register(self) -> bool {
        !matches!(self, Self::Jmp | Self::Eq | Self::Lt | Self::Le)
    }

    /// Returns `true` if field `B` is used as an unconditional direct register bounded by `maxstacksize`.
    #[must_use]
    pub const fn b_is_fixed_register(self) -> bool {
        matches!(
            self,
            Self::Move
                | Self::LoadNil
                | Self::GetTable
                | Self::SelfOp
                | Self::Unm
                | Self::Not
                | Self::Len
                | Self::Concat
                | Self::TestSet
        )
    }

    /// Returns `true` if field `B` is a conditional RK operand (register or constant).
    #[must_use]
    pub const fn b_is_rk(self) -> bool {
        matches!(
            self,
            Self::SetTable
                | Self::Add
                | Self::Sub
                | Self::Mul
                | Self::Div
                | Self::Mod
                | Self::Pow
                | Self::Eq
                | Self::Lt
                | Self::Le
        )
    }

    /// Returns `true` if field `C` is used as an unconditional direct register bounded by `maxstacksize`.
    #[must_use]
    pub const fn c_is_fixed_register(self) -> bool {
        matches!(self, Self::Concat)
    }

    /// Returns `true` if field `C` is a conditional RK operand (register or constant).
    #[must_use]
    pub const fn c_is_rk(self) -> bool {
        matches!(
            self,
            Self::GetTable
                | Self::SetTable
                | Self::SelfOp
                | Self::Add
                | Self::Sub
                | Self::Mul
                | Self::Div
                | Self::Mod
                | Self::Pow
                | Self::Eq
                | Self::Lt
                | Self::Le
        )
    }
}

/// Lua 5.1 instruction format modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode51 {
    IABC,
    IABx,
    IAsBx,
}

/// Decoded raw bitfields from a 32-bit Lua 5.1 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction51 {
    pub raw: u32,
    pub opcode_num: u8,
    pub opcode: Option<Opcode51>,
    pub a: u8,
    pub b: u16,
    pub c: u16,
    pub bx: u32,
    pub sbx: i32,
}

impl RawInstruction51 {
    pub const OFFSET_SBX: i32 = 131071;

    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x3f) as u8;
        let opcode = Opcode51::from_u8(opcode_num);
        let a = ((raw >> 6) & 0xff) as u8;
        let c = ((raw >> 14) & 0x1ff) as u16;
        let b = ((raw >> 23) & 0x1ff) as u16;
        let bx = (raw >> 14) & 0x3ffff;
        let sbx = (bx as i32) - Self::OFFSET_SBX;

        Self {
            raw,
            opcode_num,
            opcode,
            a,
            b,
            c,
            bx,
            sbx,
        }
    }

    #[must_use]
    pub fn encode_iabc(opcode: Opcode51, a: u8, b: u16, c: u16) -> u32 {
        ((opcode as u32) & 0x3F)
            | (((a as u32) & 0xFF) << 6)
            | (((c as u32) & 0x1FF) << 14)
            | (((b as u32) & 0x1FF) << 23)
    }

    #[must_use]
    pub fn encode_iabx(opcode: Opcode51, a: u8, bx: u32) -> u32 {
        ((opcode as u32) & 0x3F) | (((a as u32) & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)
    }

    #[must_use]
    pub fn encode_iasbx(opcode: Opcode51, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + Self::OFFSET_SBX) as u32;
        Self::encode_iabx(opcode, a, bx)
    }

    #[must_use]
    pub fn encode(self) -> Option<u32> {
        let op = self.opcode?;
        let word = match op.mode() {
            OpMode51::IABC => Self::encode_iabc(op, self.a, self.b, self.c),
            OpMode51::IABx => Self::encode_iabx(op, self.a, self.bx),
            OpMode51::IAsBx => Self::encode_iasbx(op, self.a, self.sbx),
        };
        Some(word)
    }

    #[must_use]
    pub fn is_b_k(&self) -> bool {
        (self.b as u32 & BITRK_51) != 0
    }

    #[must_use]
    pub fn is_c_k(&self) -> bool {
        (self.c as u32 & BITRK_51) != 0
    }

    #[must_use]
    pub fn b_index_k(&self) -> usize {
        (self.b as u32 & !BITRK_51) as usize
    }

    #[must_use]
    pub fn c_index_k(&self) -> usize {
        (self.c as u32 & !BITRK_51) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_38_opcodes_from_u8() {
        for op in 0..=37 {
            let opcode = Opcode51::from_u8(op);
            assert!(opcode.is_some(), "Opcode {op} must be recognized");
            assert_eq!(opcode.unwrap() as u8, op);
        }
        assert!(Opcode51::from_u8(38).is_none());
    }

    #[test]
    fn test_round_trip_property_all_opmodes() {
        for op in [Opcode51::Move, Opcode51::Add, Opcode51::Eq] {
            let word = RawInstruction51::encode_iabc(op, 42, 100, 200);
            let decoded = RawInstruction51::decode(word);
            assert_eq!(decoded.opcode, Some(op));
            assert_eq!(decoded.encode(), Some(word));
        }

        let word_bx = RawInstruction51::encode_iabx(Opcode51::LoadK, 5, 12345);
        let dec_bx = RawInstruction51::decode(word_bx);
        assert_eq!(dec_bx.opcode, Some(Opcode51::LoadK));
        assert_eq!(dec_bx.bx, 12345);
        assert_eq!(dec_bx.encode(), Some(word_bx));

        let word_sbx = RawInstruction51::encode_iasbx(Opcode51::Jmp, 0, -500);
        let dec_sbx = RawInstruction51::decode(word_sbx);
        assert_eq!(dec_sbx.opcode, Some(Opcode51::Jmp));
        assert_eq!(dec_sbx.sbx, -500);
        assert_eq!(dec_sbx.encode(), Some(word_sbx));
    }

    #[test]
    fn test_a_is_register_matches_authority() {
        let non_reg = [Opcode51::Jmp, Opcode51::Eq, Opcode51::Lt, Opcode51::Le];
        for op in 0..=37 {
            let opcode = Opcode51::from_u8(op).unwrap();
            if non_reg.contains(&opcode) {
                assert!(
                    !opcode.a_is_register(),
                    "{:?} should not use A as register",
                    opcode
                );
            } else {
                assert!(
                    opcode.a_is_register(),
                    "{:?} should use A as register",
                    opcode
                );
            }
        }
    }

    #[test]
    fn test_b_is_fixed_register_matches_authority() {
        let fixed_reg = [
            Opcode51::Move,
            Opcode51::LoadNil,
            Opcode51::GetTable,
            Opcode51::SelfOp,
            Opcode51::Unm,
            Opcode51::Not,
            Opcode51::Len,
            Opcode51::Concat,
            Opcode51::TestSet,
        ];
        for op in 0..=37 {
            let opcode = Opcode51::from_u8(op).unwrap();
            if fixed_reg.contains(&opcode) {
                assert!(
                    opcode.b_is_fixed_register(),
                    "{:?} should use fixed register B",
                    opcode
                );
            } else {
                assert!(
                    !opcode.b_is_fixed_register(),
                    "{:?} should not use fixed register B",
                    opcode
                );
            }
        }
    }

    #[test]
    fn test_c_is_fixed_register_matches_authority() {
        for op in 0..=37 {
            let opcode = Opcode51::from_u8(op).unwrap();
            if opcode == Opcode51::Concat {
                assert!(
                    opcode.c_is_fixed_register(),
                    "{:?} should use fixed register C",
                    opcode
                );
            } else {
                assert!(
                    !opcode.c_is_fixed_register(),
                    "{:?} should not use fixed register C",
                    opcode
                );
            }
        }
    }

    #[test]
    fn test_c_is_rk_matches_authority() {
        let rk_c = [
            Opcode51::GetTable,
            Opcode51::SetTable,
            Opcode51::SelfOp,
            Opcode51::Add,
            Opcode51::Sub,
            Opcode51::Mul,
            Opcode51::Div,
            Opcode51::Mod,
            Opcode51::Pow,
            Opcode51::Eq,
            Opcode51::Lt,
            Opcode51::Le,
        ];
        for op in 0..=37 {
            let opcode = Opcode51::from_u8(op).unwrap();
            if rk_c.contains(&opcode) {
                assert!(opcode.c_is_rk(), "{:?} should be RK C", opcode);
            } else {
                assert!(!opcode.c_is_rk(), "{:?} should not be RK C", opcode);
            }
        }
    }
}
