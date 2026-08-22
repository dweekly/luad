//! Lua 5.4 instruction formats, bitfield decoding, and opcode definitions.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Instruction encoding mode in Lua 5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpMode54 {
    /// Standard 3-register/operand format: A (8 bits), k (1 bit), B (8 bits), C (8 bits).
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
    /// Safe construction of an opcode from a 7-bit opcode index without unsafe code.
    #[must_use]
    pub fn from_u8(op: u8) -> Option<Self> {
        match op {
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
            81 => Some(Self::Varargprep),
            82 => Some(Self::Extraarg),
            _ => None,
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
            Self::Eqi => OpMode54::IABC,
            Self::Lti => OpMode54::IABC,
            Self::Lei => OpMode54::IABC,
            Self::Gti => OpMode54::IABC,
            Self::Gei => OpMode54::IABC,
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
///
/// Lua 5.4 official bit layout (lopcodes.h):
/// - `iABC`:   `[ C(8): 31..24 | B(8): 23..16 | k(1): 15 | A(8): 14..7 | Op(7): 6..0 ]`
/// - `iABx`:   `[ Bx(17): 31..15 | A(8): 14..7 | Op(7): 6..0 ]`
/// - `iAsBx`:  `[ sBx(17): 31..15 | A(8): 14..7 | Op(7): 6..0 ]`
/// - `iAx`:    `[ Ax(25): 31..7 | Op(7): 6..0 ]`
/// - `isJ`:    `[ sJ(25): 31..7 | Op(7): 6..0 ]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawInstruction54 {
    /// 7-bit opcode number (bits 0..=6).
    pub opcode_num: u8,
    /// Identified opcode variant if valid.
    pub opcode: Option<Opcode54>,
    /// 8-bit A operand (bits 7..=14).
    pub a: u8,
    /// 1-bit k flag (bit 15).
    pub k: u8,
    /// 8-bit B operand (bits 16..=23).
    pub b: u8,
    /// Signed 8-bit sB operand (`b as i32 - 127`).
    pub sb: i32,
    /// 8-bit C operand (bits 24..=31).
    pub c: u8,
    /// Signed 8-bit sC operand (`c as i32 - 127`).
    pub sc: i32,
    /// 17-bit unsigned Bx operand (bits 15..=31).
    pub bx: u32,
    /// 17-bit signed sBx operand (`bx as i32 - 65535`).
    pub sbx: i32,
    /// 25-bit unsigned Ax operand (bits 7..=31).
    pub ax: u32,
    /// 25-bit signed sJ jump offset (bits 7..=31 minus bias 16777215).
    pub sj: i32,
}

impl RawInstruction54 {
    /// Bias constant for 8-bit signed sB field (`(1 << 7) - 1` = 127).
    pub const OFFSET_SB: i32 = (1 << 7) - 1;
    /// Bias constant for 8-bit signed sC field (`(1 << 7) - 1` = 127).
    pub const OFFSET_SC: i32 = (1 << 7) - 1;
    /// Bias constant for 17-bit signed sBx field (`(1 << 16) - 1` = 65535).
    pub const OFFSET_SBX: i32 = (1 << 16) - 1;
    /// Bias constant for 25-bit signed sJ field (`(1 << 24) - 1` = 16777215).
    pub const OFFSET_SJ: i32 = (1 << 24) - 1;

    /// Decode raw 32-bit instruction word into bitfields according to official Lua 5.4 specifications.
    #[must_use]
    pub fn decode(word: u32) -> Self {
        let opcode_num = (word & 0x7F) as u8;
        let opcode = Opcode54::from_u8(opcode_num);
        let a = ((word >> 7) & 0xFF) as u8;
        let k = ((word >> 15) & 0x1) as u8;
        let b = ((word >> 16) & 0xFF) as u8;
        let sb = (b as i32) - Self::OFFSET_SB;
        let c = ((word >> 24) & 0xFF) as u8;
        let sc = (c as i32) - Self::OFFSET_SC;
        let bx = (word >> 15) & 0x1FFFF;
        let sbx = (bx as i32) - Self::OFFSET_SBX;
        let ax = (word >> 7) & 0x1FFFFFF;
        let sj = ((word >> 7) & 0x1FFFFFF) as i32 - Self::OFFSET_SJ;

        Self {
            opcode_num,
            opcode,
            a,
            k,
            b,
            sb,
            c,
            sc,
            bx,
            sbx,
            ax,
            sj,
        }
    }

    /// Encode an iABC format instruction into a 32-bit word.
    #[must_use]
    pub fn encode_iabc(opcode: Opcode54, a: u8, b: u8, c: u8, k: u8) -> u32 {
        ((opcode as u32) & 0x7F)
            | (((a as u32) & 0xFF) << 7)
            | (((k as u32) & 0x1) << 15)
            | (((b as u32) & 0xFF) << 16)
            | (((c as u32) & 0xFF) << 24)
    }

    /// Encode an iABx format instruction into a 32-bit word.
    #[must_use]
    pub fn encode_iabx(opcode: Opcode54, a: u8, bx: u32) -> u32 {
        ((opcode as u32) & 0x7F) | (((a as u32) & 0xFF) << 7) | ((bx & 0x1FFFF) << 15)
    }

    /// Encode an iAsBx format instruction into a 32-bit word.
    #[must_use]
    pub fn encode_iasbx(opcode: Opcode54, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + Self::OFFSET_SBX) as u32;
        Self::encode_iabx(opcode, a, bx)
    }

    /// Encode an iAx format instruction into a 32-bit word.
    #[must_use]
    pub fn encode_iax(opcode: Opcode54, ax: u32) -> u32 {
        ((opcode as u32) & 0x7F) | ((ax & 0x1FFFFFF) << 7)
    }

    /// Encode an isJ format instruction into a 32-bit word.
    #[must_use]
    pub fn encode_isj(opcode: Opcode54, sj: i32) -> u32 {
        let uj = (sj + Self::OFFSET_SJ) as u32;
        ((opcode as u32) & 0x7F) | ((uj & 0x1FFFFFF) << 7)
    }

    /// Encode the raw instruction back into its 32-bit word representation according to its opcode mode.
    #[must_use]
    pub fn encode(self) -> Option<u32> {
        let op = self.opcode?;
        let word = match op.mode() {
            OpMode54::IABC => Self::encode_iabc(op, self.a, self.b, self.c, self.k),
            OpMode54::IABx => Self::encode_iabx(op, self.a, self.bx),
            OpMode54::IAsBx => Self::encode_iasbx(op, self.a, self.sbx),
            OpMode54::IAx => Self::encode_iax(op, self.ax),
            OpMode54::IsJ => Self::encode_isj(op, self.sj),
        };
        Some(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_83_opcodes_from_u8() {
        for op in 0..=82 {
            let opcode = Opcode54::from_u8(op);
            assert!(opcode.is_some(), "Opcode {op} must be recognized");
            assert_eq!(opcode.unwrap() as u8, op);
        }
        assert!(Opcode54::from_u8(83).is_none());
        assert!(Opcode54::from_u8(255).is_none());
    }

    #[test]
    fn test_iabc_bitfield_layout() {
        // Opcode = 0 (MOVE), A = 1, k = 1, B = 2, C = 3
        // Op(7): 0
        // A(8): 1 -> 1 << 7 = 0x80
        // k(1): 1 -> 1 << 15 = 0x8000
        // B(8): 2 -> 2 << 16 = 0x20000
        // C(8): 3 -> 3 << 24 = 0x3000000
        // Total word = 0x03028080
        let word = RawInstruction54::encode_iabc(Opcode54::Move, 1, 2, 3, 1);
        assert_eq!(word, 0x03028080);

        let decoded = RawInstruction54::decode(word);
        assert_eq!(decoded.opcode, Some(Opcode54::Move));
        assert_eq!(decoded.a, 1);
        assert_eq!(decoded.k, 1);
        assert_eq!(decoded.b, 2);
        assert_eq!(decoded.sb, 2 - 127);
        assert_eq!(decoded.c, 3);
        assert_eq!(decoded.sc, 3 - 127);
    }

    #[test]
    fn test_round_trip_property_all_opmodes() {
        // Test iABC round trip
        for op in [
            Opcode54::Move,
            Opcode54::Add,
            Opcode54::Eqi,
            Opcode54::Mmbini,
        ] {
            let word = RawInstruction54::encode_iabc(op, 42, 100, 200, 1);
            let decoded = RawInstruction54::decode(word);
            assert_eq!(decoded.opcode, Some(op));
            assert_eq!(decoded.encode(), Some(word));
        }

        // Test iABx round trip
        let word_abx = RawInstruction54::encode_iabx(Opcode54::Loadk, 15, 12345);
        let dec_abx = RawInstruction54::decode(word_abx);
        assert_eq!(dec_abx.opcode, Some(Opcode54::Loadk));
        assert_eq!(dec_abx.a, 15);
        assert_eq!(dec_abx.bx, 12345);
        assert_eq!(dec_abx.encode(), Some(word_abx));

        // Test iAsBx round trip
        let word_asbx = RawInstruction54::encode_iasbx(Opcode54::Loadi, 7, -100);
        let dec_asbx = RawInstruction54::decode(word_asbx);
        assert_eq!(dec_asbx.opcode, Some(Opcode54::Loadi));
        assert_eq!(dec_asbx.a, 7);
        assert_eq!(dec_asbx.sbx, -100);
        assert_eq!(dec_asbx.encode(), Some(word_asbx));

        // Test isJ round trip
        let word_sj = RawInstruction54::encode_isj(Opcode54::Jmp, -42);
        let dec_sj = RawInstruction54::decode(word_sj);
        assert_eq!(dec_sj.opcode, Some(Opcode54::Jmp));
        assert_eq!(dec_sj.sj, -42);
        assert_eq!(dec_sj.encode(), Some(word_sj));

        // Test iAx round trip
        let word_ax = RawInstruction54::encode_iax(Opcode54::Extraarg, 999999);
        let dec_ax = RawInstruction54::decode(word_ax);
        assert_eq!(dec_ax.opcode, Some(Opcode54::Extraarg));
        assert_eq!(dec_ax.ax, 999999);
        assert_eq!(dec_ax.encode(), Some(word_ax));
    }
}
