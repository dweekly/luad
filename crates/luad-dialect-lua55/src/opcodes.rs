//! Lua 5.5 Opcode table, Lua 5.5 instruction format, opcodes, and bitfield decoding.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Instruction encoding format in Lua 5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode55 {
    /// 3-register/operand format: A (8 bits), k (1 bit), B (8 bits), C (8 bits).
    IABC,
    /// Variable 2-register format with extended C: A (8 bits), vB (6 bits), vC (10 bits).
    IvABC,
    /// 17-bit unsigned Bx format: A (8 bits), Bx (17 bits).
    IABx,
    /// 17-bit signed sBx format: A (8 bits), sBx (17 bits).
    IAsBx,
    /// 25-bit unsigned Ax format: Ax (25 bits).
    IAx,
    /// 25-bit signed jump offset format: sJ (25 bits).
    IsJ,
}

/// Enumeration of all 85 Lua 5.5 opcodes (Lua 5.5.0 through 5.5.1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
    Getvarg = 81,
    Errnnil = 82,
    Varargprep = 83,
    Extraarg = 84,
}

impl Opcode55 {
    /// Safe construction of Lua 5.5 opcode without unsafe code.
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Move),
            1 => Some(Self::Loadi),
            2 => Some(Self::Loadf),
            3 => Some(Self::Loadk),
            4 => Some(Self::Loadkx),
            5 => Some(Self::Loadfalse),
            6 => Some(Self::Lfalseskip),
            7 => Some(Self::Loadtrue),
            8 => Some(Self::Loadnil),
            9 => Some(Self::Getupval),
            10 => Some(Self::Setupval),
            11 => Some(Self::Gettabup),
            12 => Some(Self::Gettable),
            13 => Some(Self::Geti),
            14 => Some(Self::Getfield),
            15 => Some(Self::Settabup),
            16 => Some(Self::Settable),
            17 => Some(Self::Seti),
            18 => Some(Self::Setfield),
            19 => Some(Self::Newtable),
            20 => Some(Self::SelfOp),
            21 => Some(Self::Addi),
            22 => Some(Self::Addk),
            23 => Some(Self::Subk),
            24 => Some(Self::Mulk),
            25 => Some(Self::Modk),
            26 => Some(Self::Powk),
            27 => Some(Self::Divk),
            28 => Some(Self::Idivk),
            29 => Some(Self::Bandk),
            30 => Some(Self::Bork),
            31 => Some(Self::Bxork),
            32 => Some(Self::Shri),
            33 => Some(Self::Shli),
            34 => Some(Self::Add),
            35 => Some(Self::Sub),
            36 => Some(Self::Mul),
            37 => Some(Self::Mod),
            38 => Some(Self::Pow),
            39 => Some(Self::Div),
            40 => Some(Self::Idiv),
            41 => Some(Self::Band),
            42 => Some(Self::Bor),
            43 => Some(Self::Bxor),
            44 => Some(Self::Shl),
            45 => Some(Self::Shr),
            46 => Some(Self::Mmbin),
            47 => Some(Self::Mmbini),
            48 => Some(Self::Mmbink),
            49 => Some(Self::Unm),
            50 => Some(Self::Bnot),
            51 => Some(Self::Not),
            52 => Some(Self::Len),
            53 => Some(Self::Concat),
            54 => Some(Self::Close),
            55 => Some(Self::Tbc),
            56 => Some(Self::Jmp),
            57 => Some(Self::Eq),
            58 => Some(Self::Lt),
            59 => Some(Self::Le),
            60 => Some(Self::Eqk),
            61 => Some(Self::Eqi),
            62 => Some(Self::Lti),
            63 => Some(Self::Lei),
            64 => Some(Self::Gti),
            65 => Some(Self::Gei),
            66 => Some(Self::Test),
            67 => Some(Self::Testset),
            68 => Some(Self::Call),
            69 => Some(Self::Tailcall),
            70 => Some(Self::Return),
            71 => Some(Self::Return0),
            72 => Some(Self::Return1),
            73 => Some(Self::Forloop),
            74 => Some(Self::Forprep),
            75 => Some(Self::Tforprep),
            76 => Some(Self::Tforcall),
            77 => Some(Self::Tforloop),
            78 => Some(Self::Setlist),
            79 => Some(Self::Closure),
            80 => Some(Self::Vararg),
            81 => Some(Self::Getvarg),
            82 => Some(Self::Errnnil),
            83 => Some(Self::Varargprep),
            84 => Some(Self::Extraarg),
            _ => None,
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
            Self::Loadi => OpMode55::IAsBx,
            Self::Loadf => OpMode55::IAsBx,
            Self::Loadk => OpMode55::IABx,
            Self::Loadkx => OpMode55::IABx,
            Self::Loadfalse => OpMode55::IABC,
            Self::Lfalseskip => OpMode55::IABC,
            Self::Loadtrue => OpMode55::IABC,
            Self::Loadnil => OpMode55::IABC,
            Self::Getupval => OpMode55::IABC,
            Self::Setupval => OpMode55::IABC,
            Self::Gettabup => OpMode55::IABC,
            Self::Gettable => OpMode55::IABC,
            Self::Geti => OpMode55::IABC,
            Self::Getfield => OpMode55::IABC,
            Self::Settabup => OpMode55::IABC,
            Self::Settable => OpMode55::IABC,
            Self::Seti => OpMode55::IABC,
            Self::Setfield => OpMode55::IABC,
            Self::Newtable => OpMode55::IABC,
            Self::SelfOp => OpMode55::IABC,
            Self::Addi => OpMode55::IABC,
            Self::Addk => OpMode55::IABC,
            Self::Subk => OpMode55::IABC,
            Self::Mulk => OpMode55::IABC,
            Self::Modk => OpMode55::IABC,
            Self::Powk => OpMode55::IABC,
            Self::Divk => OpMode55::IABC,
            Self::Idivk => OpMode55::IABC,
            Self::Bandk => OpMode55::IABC,
            Self::Bork => OpMode55::IABC,
            Self::Bxork => OpMode55::IABC,
            Self::Shri => OpMode55::IABC,
            Self::Shli => OpMode55::IABC,
            Self::Add
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction55 {
    pub raw: u32,
    pub opcode_num: u8,
    pub opcode: Option<Opcode55>,
    pub a: u8,
    pub b: u8,
    pub sb: i32,
    pub vb: u8,
    pub c: u8,
    pub sc: i32,
    pub vc: u16,
    pub k: u8,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub sj: i32,
}

impl RawInstruction55 {
    pub const OFFSET_SB: i32 = 127;
    pub const OFFSET_SC: i32 = 127;
    pub const OFFSET_SBX: i32 = 65535;
    pub const OFFSET_SJ: i32 = 16777215;

    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let opcode_num = (raw & 0x7F) as u8;
        let opcode = Opcode55::from_u8(opcode_num);
        let a = ((raw >> 7) & 0xFF) as u8;
        let k = ((raw >> 15) & 1) as u8;
        let b = ((raw >> 16) & 0xFF) as u8;
        let sb = (b as i32) - Self::OFFSET_SB;
        let c = ((raw >> 24) & 0xFF) as u8;
        let sc = (c as i32) - Self::OFFSET_SC;

        // ivABC layout
        let vb = ((raw >> 16) & 0x3F) as u8; // 6 bits (16..21)
        let vc = ((raw >> 22) & 0x3FF) as u16; // 10 bits (22..31)

        // iABx layout (17 bits from bit 15)
        let bx = raw >> 15;
        let sbx = (bx as i32) - Self::OFFSET_SBX;

        // iAx layout (25 bits from bit 7)
        let ax = raw >> 7;

        // isJ layout (25 bits signed from bit 7 with bias 16777215)
        let sj = (ax as i32) - Self::OFFSET_SJ;

        Self {
            raw,
            opcode_num,
            opcode,
            a,
            b,
            sb,
            vb,
            c,
            sc,
            vc,
            k,
            bx,
            sbx,
            ax,
            sj,
        }
    }

    #[must_use]
    pub fn encode_iabc(opcode: Opcode55, a: u8, b: u8, c: u8, k: u8) -> u32 {
        ((opcode as u32) & 0x7F)
            | (((a as u32) & 0xFF) << 7)
            | (((k as u32) & 0x1) << 15)
            | (((b as u32) & 0xFF) << 16)
            | (((c as u32) & 0xFF) << 24)
    }

    #[must_use]
    pub fn encode_ivabc(opcode: Opcode55, a: u8, vb: u8, vc: u16, k: u8) -> u32 {
        ((opcode as u32) & 0x7F)
            | (((a as u32) & 0xFF) << 7)
            | (((k as u32) & 0x1) << 15)
            | (((vb as u32) & 0x3F) << 16)
            | (((vc as u32) & 0x3FF) << 22)
    }

    #[must_use]
    pub fn encode_iabx(opcode: Opcode55, a: u8, bx: u32) -> u32 {
        ((opcode as u32) & 0x7F) | (((a as u32) & 0xFF) << 7) | ((bx & 0x1FFFF) << 15)
    }

    #[must_use]
    pub fn encode_iasbx(opcode: Opcode55, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + Self::OFFSET_SBX) as u32;
        Self::encode_iabx(opcode, a, bx)
    }

    #[must_use]
    pub fn encode_iax(opcode: Opcode55, ax: u32) -> u32 {
        ((opcode as u32) & 0x7F) | ((ax & 0x1FFFFFF) << 7)
    }

    #[must_use]
    pub fn encode_isj(opcode: Opcode55, sj: i32) -> u32 {
        let uj = (sj + Self::OFFSET_SJ) as u32;
        ((opcode as u32) & 0x7F) | ((uj & 0x1FFFFFF) << 7)
    }

    #[must_use]
    pub fn encode(self) -> Option<u32> {
        let op = self.opcode?;
        let word = match op.mode() {
            OpMode55::IABC => Self::encode_iabc(op, self.a, self.b, self.c, self.k),
            OpMode55::IvABC => Self::encode_ivabc(op, self.a, self.vb, self.vc, self.k),
            OpMode55::IABx => Self::encode_iabx(op, self.a, self.bx),
            OpMode55::IAsBx => Self::encode_iasbx(op, self.a, self.sbx),
            OpMode55::IAx => Self::encode_iax(op, self.ax),
            OpMode55::IsJ => Self::encode_isj(op, self.sj),
        };
        Some(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_85_opcodes_from_u8() {
        for op in 0..=84 {
            let opcode = Opcode55::from_u8(op);
            assert!(opcode.is_some(), "Opcode {op} must be recognized");
            assert_eq!(opcode.unwrap() as u8, op);
        }
        assert!(Opcode55::from_u8(85).is_none());
    }

    #[test]
    fn test_round_trip_property_all_opmodes() {
        for op in [Opcode55::Move, Opcode55::Add, Opcode55::Eqi] {
            let word = RawInstruction55::encode_iabc(op, 42, 100, 200, 1);
            let decoded = RawInstruction55::decode(word);
            assert_eq!(decoded.opcode, Some(op));
            assert_eq!(decoded.encode(), Some(word));
        }

        let word_iv = RawInstruction55::encode_ivabc(Opcode55::Setlist, 5, 20, 500, 0);
        let dec_iv = RawInstruction55::decode(word_iv);
        assert_eq!(dec_iv.opcode, Some(Opcode55::Setlist));
        assert_eq!(dec_iv.vb, 20);
        assert_eq!(dec_iv.vc, 500);
        assert_eq!(dec_iv.encode(), Some(word_iv));
    }
}
