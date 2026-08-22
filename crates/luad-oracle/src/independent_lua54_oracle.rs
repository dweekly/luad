//! Independently transcribed Lua 5.4.8 reference decoder and opcode specification.
//!
//! Conforms directly to official Lua 5.4.8 source (`lopcodes.h` / `lopcodes.c` / `luac.c`).
//! This module is completely independent from `luad_dialect_lua54` to guarantee non-circular oracle verification.

/// Lua 5.4.8 Opcode Mode classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentOpMode54 {
    IABC,
    IABx,
    IAsBx,
    IAx,
    IsJ,
}

/// Official Lua 5.4.8 83 Opcode enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum IndependentOpcode54 {
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

impl IndependentOpcode54 {
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 82 {
            // Safe independent table lookup without unsafe
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
                81 => Some(Self::Varargprep),
                82 => Some(Self::Extraarg),
                _ => None,
            }
        } else {
            None
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
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

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        for op_idx in 0..=82 {
            if let Some(op) = Self::from_u8(op_idx) {
                if op.name().eq_ignore_ascii_case(name) {
                    return Some(op);
                }
            }
        }
        None
    }

    #[must_use]
    pub const fn mode(&self) -> IndependentOpMode54 {
        match self {
            Self::Move
            | Self::Loadfalse
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
            | Self::Setfield
            | Self::Newtable
            | Self::SelfOp
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
            | Self::Shri
            | Self::Shli
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
            | Self::Tbc
            | Self::Eq
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
            | Self::Return1
            | Self::Tforcall
            | Self::Setlist
            | Self::Vararg
            | Self::Varargprep => IndependentOpMode54::IABC,

            Self::Loadk
            | Self::Loadkx
            | Self::Forloop
            | Self::Forprep
            | Self::Tforprep
            | Self::Tforloop
            | Self::Closure => IndependentOpMode54::IABx,

            Self::Loadi | Self::Loadf => IndependentOpMode54::IAsBx,

            Self::Extraarg => IndependentOpMode54::IAx,

            Self::Jmp => IndependentOpMode54::IsJ,
        }
    }
}

/// Independently decoded 32-bit Lua 5.4 instruction fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndependentInstruction54 {
    pub raw_word: u32,
    pub opcode: Option<IndependentOpcode54>,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub k: u8,
    pub sb: i32,
    pub sc: i32,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub sj: i32,
}

impl IndependentInstruction54 {
    /// Decodes instruction fields using pure independent bit shifts according to Lua 5.4 lopcodes.h.
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let op_raw = (raw & 0x7F) as u8;
        let a = ((raw >> 7) & 0xFF) as u8;
        let k = ((raw >> 15) & 0x1) as u8;
        let b = ((raw >> 16) & 0xFF) as u8;
        let c = ((raw >> 24) & 0xFF) as u8;

        let sb = b as i32 - 127;
        let sc = c as i32 - 127;

        let bx = (raw >> 15) & 0x1FFFF;
        let sbx = bx as i32 - 65535;

        let ax = (raw >> 7) & 0x1FFFFFF;
        let raw_sj = (raw >> 7) & 0x1FFFFFF;
        let sj = raw_sj as i32 - 16777215;

        Self {
            raw_word: raw,
            opcode: IndependentOpcode54::from_u8(op_raw),
            a,
            b,
            c,
            k,
            sb,
            sc,
            bx,
            sbx,
            ax,
            sj,
        }
    }
}
