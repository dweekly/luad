//! Independent clean-room Lua 5.1 reference decoder and opcode specification.
//!
//! Conforms directly to official Lua 5.1.5 source (`lopcodes.h` / `lopcodes.c` / `luac.c`).
//! This module is completely independent from `luad_dialect_lua51` to guarantee
//! non-circular differential oracle verification.

/// Lua 5.1 Opcode Mode classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentOpMode51 {
    IABC,
    IABx,
    IAsBx,
}

/// Official Lua 5.1 38 Opcode enumeration (0..=37).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum IndependentOpcode51 {
    Move = 0,
    Loadk = 1,
    Loadbool = 2,
    Loadnil = 3,
    Getupval = 4,
    Getglobal = 5,
    Gettable = 6,
    Setglobal = 7,
    Setupval = 8,
    Settable = 9,
    Newtable = 10,
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
    Testset = 27,
    Call = 28,
    Tailcall = 29,
    Return = 30,
    Forloop = 31,
    Forprep = 32,
    Tforloop = 33,
    Setlist = 34,
    Close = 35,
    Closure = 36,
    Vararg = 37,
}

impl IndependentOpcode51 {
    pub const BITRK: u32 = 1 << 8; // 256
    pub const MAXINDEXRK: u32 = (1 << 8) - 1; // 255
    pub const MAXARG_S_BX: i32 = (1 << 17) - 1; // 131071

    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Move),
            1 => Some(Self::Loadk),
            2 => Some(Self::Loadbool),
            3 => Some(Self::Loadnil),
            4 => Some(Self::Getupval),
            5 => Some(Self::Getglobal),
            6 => Some(Self::Gettable),
            7 => Some(Self::Setglobal),
            8 => Some(Self::Setupval),
            9 => Some(Self::Settable),
            10 => Some(Self::Newtable),
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
            27 => Some(Self::Testset),
            28 => Some(Self::Call),
            29 => Some(Self::Tailcall),
            30 => Some(Self::Return),
            31 => Some(Self::Forloop),
            32 => Some(Self::Forprep),
            33 => Some(Self::Tforloop),
            34 => Some(Self::Setlist),
            35 => Some(Self::Close),
            36 => Some(Self::Closure),
            37 => Some(Self::Vararg),
            _ => None,
        }
    }

    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::Loadk => "LOADK",
            Self::Loadbool => "LOADBOOL",
            Self::Loadnil => "LOADNIL",
            Self::Getupval => "GETUPVAL",
            Self::Getglobal => "GETGLOBAL",
            Self::Gettable => "GETTABLE",
            Self::Setglobal => "SETGLOBAL",
            Self::Setupval => "SETUPVAL",
            Self::Settable => "SETTABLE",
            Self::Newtable => "NEWTABLE",
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
            Self::Testset => "TESTSET",
            Self::Call => "CALL",
            Self::Tailcall => "TAILCALL",
            Self::Return => "RETURN",
            Self::Forloop => "FORLOOP",
            Self::Forprep => "FORPREP",
            Self::Tforloop => "TFORLOOP",
            Self::Setlist => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::Vararg => "VARARG",
        }
    }

    #[must_use]
    pub fn mode(self) -> IndependentOpMode51 {
        match self {
            Self::Loadk | Self::Getglobal | Self::Setglobal | Self::Closure => {
                IndependentOpMode51::IABx
            }
            Self::Jmp | Self::Forloop | Self::Forprep => IndependentOpMode51::IAsBx,
            _ => IndependentOpMode51::IABC,
        }
    }
}

/// Decoded independent instruction record for Lua 5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentInstruction51 {
    pub pc: usize,
    pub raw_word: u32,
    pub opcode: Option<IndependentOpcode51>,
    pub opcode_num: u8,
    pub a: u8,
    pub b: u32,
    pub c: u32,
    pub bx: u32,
    pub sbx: i32,
    pub is_b_k: bool,
    pub is_c_k: bool,
    pub b_k_index: u32,
    pub c_k_index: u32,
}

impl IndependentInstruction51 {
    /// Decode a 32-bit instruction word using the official Lua 5.1 bit layout.
    #[must_use]
    pub fn decode(pc: usize, raw_word: u32) -> Self {
        // POS_OP = 0, SIZE_OP = 6
        let opcode_num = (raw_word & 0x3F) as u8;
        let opcode = IndependentOpcode51::from_u8(opcode_num);

        // POS_A = 6, SIZE_A = 8
        let a = ((raw_word >> 6) & 0xFF) as u8;

        // POS_C = 14, SIZE_C = 9
        let c = (raw_word >> 14) & 0x1FF;

        // POS_B = 23, SIZE_B = 9
        let b = (raw_word >> 23) & 0x1FF;

        // POS_Bx = 14, SIZE_Bx = 18
        let bx = (raw_word >> 14) & 0x3FFFF;
        let sbx = (bx as i32) - IndependentOpcode51::MAXARG_S_BX;

        let is_b_k = (b & IndependentOpcode51::BITRK) != 0;
        let is_c_k = (c & IndependentOpcode51::BITRK) != 0;
        let b_k_index = b & !IndependentOpcode51::BITRK;
        let c_k_index = c & !IndependentOpcode51::BITRK;

        Self {
            pc,
            raw_word,
            opcode,
            opcode_num,
            a,
            b,
            c,
            bx,
            sbx,
            is_b_k,
            is_c_k,
            b_k_index,
            c_k_index,
        }
    }
}
