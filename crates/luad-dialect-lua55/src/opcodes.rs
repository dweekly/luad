//! Lua 5.5 Opcode table, instruction formats, and bitfield decoder.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Instruction layout mode for Lua 5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OpMode55 {
    /// Standard 3-register/constant format: A(8), k(1), B(8), C(8)
    IABC,
    /// Variant 3-operand format: A(8), k(1), vB(6), vC(10)
    IvABC,
    /// 1-register, 17-bit unsigned constant/proto: A(8), Bx(17)
    IABx,
    /// 1-register, 17-bit signed immediate integer: A(8), sBx(17)
    IAsBx,
    /// 25-bit unsigned extra argument: Ax(25)
    IAx,
    /// 25-bit signed jump offset: sJ(25)
    IsJ,
}

/// Enumeration of all 85 opcodes supported in Lua 5.5.0 - 5.5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[repr(u8)]
pub enum Opcode55 {
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
    Shli = 32,
    Shri = 33,
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
    Getvarg = 81,
    Errnnil = 82,
    Varargprep = 83,
    Extraarg = 84,
}

impl Opcode55 {
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        if val <= 84 {
            // SAFETY: Validated <= 84 matching contiguous repr(u8) enum range 0..=84
            Some(unsafe { std::mem::transmute::<u8, Self>(val) })
        } else {
            None
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
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
            Self::Shli => "SHLI",
            Self::Shri => "SHRI",
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
            Self::Getvarg => "GETVARG",
            Self::Errnnil => "ERRNNIL",
            Self::Varargprep => "VARARGPREP",
            Self::Extraarg => "EXTRAARG",
        }
    }

    #[must_use]
    pub const fn mode(self) -> OpMode55 {
        match self {
            Self::Move => OpMode55::IABC,
            Self::Loadi | Self::Loadf => OpMode55::IAsBx,
            Self::Loadk | Self::Loadkx => OpMode55::IABx,
            Self::Loadfalse
            | Self::Lfalseskip
            | Self::Loadtrue
            | Self::Loadnil
            | Self::Getupval
            | Self::Setupval
            | Self::Gettabup
            | Self::Gettable
            | Self::Geti
            | Self::Getfield
            | Self::Settabup
            | Self::Settable
            | Self::Seti
            | Self::Setfield => OpMode55::IABC,
            Self::Newtable => OpMode55::IvABC,
            Self::SelfOp
            | Self::Addi
            | Self::Addk
            | Self::Subk
            | Self::Mulk
            | Self::Modk
            | Self::Powk
            | Self::Divk
            | Self::Idivk
            | Self::Bandk
            | Self::Bork
            | Self::Bxork
            | Self::Shli
            | Self::Shri
            | Self::Add
            | Self::Sub
            | Self::Mul
            | Self::Mod
            | Self::Pow
            | Self::Div
            | Self::Idiv
            | Self::Band
            | Self::Bor
            | Self::Bxor
            | Self::Shl
            | Self::Shr
            | Self::Mmbin
            | Self::Mmbini
            | Self::Mmbink
            | Self::Unm
            | Self::Bnot
            | Self::Not
            | Self::Len
            | Self::Concat
            | Self::Close
            | Self::Tbc => OpMode55::IABC,
            Self::Jmp => OpMode55::IsJ,
            Self::Eq
            | Self::Lt
            | Self::Le
            | Self::Eqk
            | Self::Eqi
            | Self::Lti
            | Self::Lei
            | Self::Gti
            | Self::Gei
            | Self::Test
            | Self::Testset
            | Self::Call
            | Self::Tailcall
            | Self::Return
            | Self::Return0
            | Self::Return1 => OpMode55::IABC,
            Self::Forloop | Self::Forprep | Self::Tforprep => OpMode55::IABx,
            Self::Tforcall => OpMode55::IABC,
            Self::Tforloop => OpMode55::IABx,
            Self::Setlist => OpMode55::IvABC,
            Self::Closure => OpMode55::IABx,
            Self::Vararg | Self::Getvarg => OpMode55::IABC,
            Self::Errnnil => OpMode55::IABx,
            Self::Varargprep => OpMode55::IABC,
            Self::Extraarg => OpMode55::IAx,
        }
    }
}

/// Decoded bitfields of a 32-bit physical Lua 5.5 instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawInstruction55 {
    pub raw: u32,
    pub opcode_num: u8,
    pub opcode: Option<Opcode55>,
    pub a: u8,
    pub b: u8,
    pub vb: u8,
    pub c: u8,
    pub vc: u16,
    pub k: u8,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub sj: i32,
}

impl RawInstruction55 {
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x7F) as u8;
        let opcode = Opcode55::from_u8(opcode_num);
        let a = ((raw >> 7) & 0xFF) as u8;
        let k = ((raw >> 15) & 1) as u8;
        let b = ((raw >> 16) & 0xFF) as u8;
        let c = ((raw >> 24) & 0xFF) as u8;

        // ivABC layout
        let vb = ((raw >> 16) & 0x3F) as u8;       // 6 bits (16..21)
        let vc = ((raw >> 22) & 0x3FF) as u16;     // 10 bits (22..31)

        // iABx layout (17 bits from bit 15)
        let bx = raw >> 15;
        let sbx = (bx as i32) - 65535;

        // iAx layout (25 bits from bit 7)
        let ax = raw >> 7;

        // isJ layout (25 bits signed from bit 7 with bias 16777215)
        let sj = (ax as i32) - 16777215;

        Self {
            raw,
            opcode_num,
            opcode,
            a,
            b,
            vb,
            c,
            vc,
            k,
            bx,
            sbx,
            ax,
            sj,
        }
    }
}
