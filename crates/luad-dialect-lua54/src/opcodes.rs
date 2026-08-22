//! Lua 5.4 instruction formats, bitfield decoding, and opcode definitions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Instruction encoding mode in Lua 5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode54 {
    /// Standard 3-register/operand format: A (8 bits), B (8 bits), C (8 bits), k (1 bit).
    IABC,
    /// Unsigned 17-bit immediate/constant format: A (8 bits), Bx (17 bits).
    IABx,
    /// Signed 17-bit immediate/constant format: A (8 bits), sBx (17 bits).
    IAsBx,
    /// Unsigned 25-bit extra argument format: Ax (25 bits).
    IAx,
    /// Signed 25-bit jump offset format: sJ (25 bits).
    IsJ,
}

/// Enumeration of all 83 Lua 5.4 opcodes (Lua 5.4.0 through 5.4.8).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum Opcode54 {
    Move = 0,
    Loadi = 1,
    Loadf = 2,
    Loadk = 3,
    Loadkx = 4,
    Loadfalse = 5,
    Lfalseskip = 6,
    Loadtrue = 7,
    Loadnil = 8,
    Getupval = 9,
    Setupval = 10,
    Gettabup = 11,
    Gettable = 12,
    Geti = 13,
    Getfield = 14,
    Settabup = 15,
    Settable = 16,
    Seti = 17,
    Setfield = 18,
    Newtable = 19,
    SelfOp = 20,
    Addi = 21,
    Addk = 22,
    Subk = 23,
    Mulk = 24,
    Modk = 25,
    Powk = 26,
    Divk = 27,
    Idivk = 28,
    Bandk = 29,
    Bork = 30,
    Bxork = 31,
    Shri = 32,
    Shli = 33,
    Add = 34,
    Sub = 35,
    Mul = 36,
    Mod = 37,
    Pow = 38,
    Div = 39,
    Idiv = 40,
    Band = 41,
    Bor = 42,
    Bxor = 43,
    Shl = 44,
    Shr = 45,
    Mmbin = 46,
    Mmbini = 47,
    Mmbink = 48,
    Unm = 49,
    Bnot = 50,
    Not = 51,
    Len = 52,
    Concat = 53,
    Close = 54,
    Tbc = 55,
    Jmp = 56,
    Eq = 57,
    Lt = 58,
    Le = 59,
    Eqk = 60,
    Eqi = 61,
    Lti = 62,
    Lei = 63,
    Gti = 64,
    Gei = 65,
    Test = 66,
    Testset = 67,
    Call = 68,
    Tailcall = 69,
    Return = 70,
    Return0 = 71,
    Return1 = 72,
    Forloop = 73,
    Forprep = 74,
    Tforprep = 75,
    Tforcall = 76,
    Tforloop = 77,
    Setlist = 78,
    Closure = 79,
    Vararg = 80,
    Varargprep = 81,
    Extraarg = 82,
}

impl Opcode54 {
    /// Try to construct an opcode from a 7-bit opcode index.
    #[must_use]
    pub fn from_u8(op: u8) -> Option<Self> {
        if op <= 82 {
            // Safety: All values 0..=82 correspond to Opcode54 variants.
            Some(unsafe { std::mem::transmute::<u8, Opcode54>(op) })
        } else {
            None
        }
    }

    /// Official mnemonic name (e.g. "MOVE", "LOADI", "GETTABUP").
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::Loadi => "LOADI",
            Self::Loadf => "LOADF",
            Self::Loadk => "LOADK",
            Self::Loadkx => "LOADKX",
            Self::Loadfalse => "LOADFALSE",
            Self::Lfalseskip => "LFALSESKIP",
            Self::Loadtrue => "LOADTRUE",
            Self::Loadnil => "LOADNIL",
            Self::Getupval => "GETUPVAL",
            Self::Setupval => "SETUPVAL",
            Self::Gettabup => "GETTABUP",
            Self::Gettable => "GETTABLE",
            Self::Geti => "GETI",
            Self::Getfield => "GETFIELD",
            Self::Settabup => "SETTABUP",
            Self::Settable => "SETTABLE",
            Self::Seti => "SETI",
            Self::Setfield => "SETFIELD",
            Self::Newtable => "NEWTABLE",
            Self::SelfOp => "SELF",
            Self::Addi => "ADDI",
            Self::Addk => "ADDK",
            Self::Subk => "SUBK",
            Self::Mulk => "MULK",
            Self::Modk => "MODK",
            Self::Powk => "POWK",
            Self::Divk => "DIVK",
            Self::Idivk => "IDIVK",
            Self::Bandk => "BANDK",
            Self::Bork => "BORK",
            Self::Bxork => "BXORK",
            Self::Shri => "SHRI",
            Self::Shli => "SHLI",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Div => "DIV",
            Self::Idiv => "IDIV",
            Self::Band => "BAND",
            Self::Bor => "BOR",
            Self::Bxor => "BXOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Mmbin => "MMBIN",
            Self::Mmbini => "MMBINI",
            Self::Mmbink => "MMBINK",
            Self::Unm => "UNM",
            Self::Bnot => "BNOT",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Close => "CLOSE",
            Self::Tbc => "TBC",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Eqk => "EQK",
            Self::Eqi => "EQI",
            Self::Lti => "LTI",
            Self::Lei => "LEI",
            Self::Gti => "GTI",
            Self::Gei => "GEI",
            Self::Test => "TEST",
            Self::Testset => "TESTSET",
            Self::Call => "CALL",
            Self::Tailcall => "TAILCALL",
            Self::Return => "RETURN",
            Self::Return0 => "RETURN0",
            Self::Return1 => "RETURN1",
            Self::Forloop => "FORLOOP",
            Self::Forprep => "FORPREP",
            Self::Tforprep => "TFORPREP",
            Self::Tforcall => "TFORCALL",
            Self::Tforloop => "TFORLOOP",
            Self::Setlist => "SETLIST",
            Self::Closure => "CLOSURE",
            Self::Vararg => "VARARG",
            Self::Varargprep => "VARARGPREP",
            Self::Extraarg => "EXTRAARG",
        }
    }

    /// Primary instruction encoding format.
    #[must_use]
    pub fn mode(self) -> OpMode54 {
        match self {
            Self::Move => OpMode54::IABC,
            Self::Loadi => OpMode54::IAsBx,
            Self::Loadf => OpMode54::IAsBx,
            Self::Loadk => OpMode54::IABx,
            Self::Loadkx => OpMode54::IABx,
            Self::Loadfalse => OpMode54::IABC,
            Self::Lfalseskip => OpMode54::IABC,
            Self::Loadtrue => OpMode54::IABC,
            Self::Loadnil => OpMode54::IABC,
            Self::Getupval => OpMode54::IABC,
            Self::Setupval => OpMode54::IABC,
            Self::Gettabup => OpMode54::IABC,
            Self::Gettable => OpMode54::IABC,
            Self::Geti => OpMode54::IABC,
            Self::Getfield => OpMode54::IABC,
            Self::Settabup => OpMode54::IABC,
            Self::Settable => OpMode54::IABC,
            Self::Seti => OpMode54::IABC,
            Self::Setfield => OpMode54::IABC,
            Self::Newtable => OpMode54::IABC,
            Self::SelfOp => OpMode54::IABC,
            Self::Addi => OpMode54::IABC,
            Self::Addk => OpMode54::IABC,
            Self::Subk => OpMode54::IABC,
            Self::Mulk => OpMode54::IABC,
            Self::Modk => OpMode54::IABC,
            Self::Powk => OpMode54::IABC,
            Self::Divk => OpMode54::IABC,
            Self::Idivk => OpMode54::IABC,
            Self::Bandk => OpMode54::IABC,
            Self::Bork => OpMode54::IABC,
            Self::Bxork => OpMode54::IABC,
            Self::Shri => OpMode54::IABC,
            Self::Shli => OpMode54::IABC,
            Self::Add => OpMode54::IABC,
            Self::Sub => OpMode54::IABC,
            Self::Mul => OpMode54::IABC,
            Self::Mod => OpMode54::IABC,
            Self::Pow => OpMode54::IABC,
            Self::Div => OpMode54::IABC,
            Self::Idiv => OpMode54::IABC,
            Self::Band => OpMode54::IABC,
            Self::Bor => OpMode54::IABC,
            Self::Bxor => OpMode54::IABC,
            Self::Shl => OpMode54::IABC,
            Self::Shr => OpMode54::IABC,
            Self::Mmbin => OpMode54::IABC,
            Self::Mmbini => OpMode54::IABC,
            Self::Mmbink => OpMode54::IABC,
            Self::Unm => OpMode54::IABC,
            Self::Bnot => OpMode54::IABC,
            Self::Not => OpMode54::IABC,
            Self::Len => OpMode54::IABC,
            Self::Concat => OpMode54::IABC,
            Self::Close => OpMode54::IABC,
            Self::Tbc => OpMode54::IABC,
            Self::Jmp => OpMode54::IsJ,
            Self::Eq => OpMode54::IABC,
            Self::Lt => OpMode54::IABC,
            Self::Le => OpMode54::IABC,
            Self::Eqk => OpMode54::IABC,
            Self::Eqi => OpMode54::IAsBx,
            Self::Lti => OpMode54::IAsBx,
            Self::Lei => OpMode54::IAsBx,
            Self::Gti => OpMode54::IAsBx,
            Self::Gei => OpMode54::IAsBx,
            Self::Test => OpMode54::IABC,
            Self::Testset => OpMode54::IABC,
            Self::Call => OpMode54::IABC,
            Self::Tailcall => OpMode54::IABC,
            Self::Return => OpMode54::IABC,
            Self::Return0 => OpMode54::IABC,
            Self::Return1 => OpMode54::IABC,
            Self::Forloop => OpMode54::IABx,
            Self::Forprep => OpMode54::IABx,
            Self::Tforprep => OpMode54::IABx,
            Self::Tforcall => OpMode54::IABC,
            Self::Tforloop => OpMode54::IABx,
            Self::Setlist => OpMode54::IABC,
            Self::Closure => OpMode54::IABx,
            Self::Vararg => OpMode54::IABC,
            Self::Varargprep => OpMode54::IABC,
            Self::Extraarg => OpMode54::IAx,
        }
    }
}

/// Decoded raw bitfields from a 32-bit Lua 5.4 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction54 {
    /// 7-bit opcode number (0..=82).
    pub opcode_num: u8,
    /// Identified opcode variant if valid.
    pub opcode: Option<Opcode54>,
    /// 8-bit A operand (bits 7..14).
    pub a: u8,
    /// 8-bit B operand (bits 15..22).
    pub b: u8,
    /// 8-bit C operand (bits 23..30).
    pub c: u8,
    /// 1-bit k flag (bit 31).
    pub k: u8,
    /// 17-bit unsigned Bx operand (bits 15..31).
    pub bx: u32,
    /// 17-bit signed sBx operand (Bx - 65535).
    pub sbx: i32,
    /// 25-bit unsigned Ax operand (bits 7..31).
    pub ax: u32,
    /// 25-bit signed sJ jump offset (bits 7..31 minus bias 16777215).
    pub sj: i32,
}

impl RawInstruction54 {
    /// Bias constant for 17-bit signed sBx field (`(1 << 16) - 1` = 65535).
    pub const OFFSET_SBX: i32 = (1 << 16) - 1;
    /// Bias constant for 25-bit signed sJ field (`(1 << 24) - 1` = 16777215).
    pub const OFFSET_SJ: i32 = (1 << 24) - 1;

    /// Decode raw 32-bit instruction word into bitfields.
    #[must_use]
    pub fn decode(word: u32) -> Self {
        let opcode_num = (word & 0x7F) as u8;
        let opcode = Opcode54::from_u8(opcode_num);
        let a = ((word >> 7) & 0xFF) as u8;
        let b = ((word >> 15) & 0xFF) as u8;
        let c = ((word >> 23) & 0xFF) as u8;
        let k = ((word >> 31) & 0x1) as u8;
        let bx = (word >> 15) & 0x1FFFF;
        let sbx = (bx as i32) - Self::OFFSET_SBX;
        let ax = (word >> 7) & 0x1FFFFFF;
        let sj = ((word >> 7) & 0x1FFFFFF) as i32 - Self::OFFSET_SJ;

        Self {
            opcode_num,
            opcode,
            a,
            b,
            c,
            k,
            bx,
            sbx,
            ax,
            sj,
        }
    }
}
