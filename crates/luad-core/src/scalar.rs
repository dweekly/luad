//! Canonical, platform-independent rendering of preserved scalar values.
//!
//! This module is the only rendering authority used by the exact Lua 5.1.5 and
//! Lua 5.4.8 disassembly paths. Rendering depends only on the preserved value;
//! it does not inspect a dialect, host layout, locale, or target width.

use std::fmt::Write as _;

use crate::model::ConstantValue;

/// Maximum number of raw string bytes included in a human-facing scalar preview.
///
/// Truncation is measured only in input bytes. The complete byte sequence remains
/// available in [`crate::model::LuaString::raw_bytes`].
pub const BYTE_STRING_PREVIEW_BYTES: usize = 64;

/// Escape every byte using the canonical byte-string policy, without quotes or
/// truncation.
///
/// Printable ASCII is emitted literally except for `"` and `\`. Common ASCII
/// controls use their short escapes; every other non-printable or non-ASCII byte
/// uses a two-digit, lowercase `\xNN` escape.
#[must_use]
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => rendered.push_str(r"\\"),
            b'"' => rendered.push_str(r#"\""#),
            b'\n' => rendered.push_str(r"\n"),
            b'\r' => rendered.push_str(r"\r"),
            b'\t' => rendered.push_str(r"\t"),
            0x20..=0x7e => rendered.push(char::from(byte)),
            _ => write!(rendered, r"\x{byte:02x}").expect("writing to a String cannot fail"),
        }
    }
    rendered
}

/// Render a quoted, bounded byte-string preview from its exact bytes.
#[must_use]
pub fn render_byte_string(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(BYTE_STRING_PREVIEW_BYTES);
    let escaped = escape_bytes(&bytes[..preview_len]);
    if bytes.len() > BYTE_STRING_PREVIEW_BYTES {
        format!(r#""{escaped}...""#)
    } else {
        format!(r#""{escaped}""#)
    }
}

/// Render a signed integer canonically across its complete 64-bit domain.
#[must_use]
pub fn render_integer(value: i64) -> String {
    value.to_string()
}

/// Render an IEEE-754 binary64 value canonically and independently of its NaN
/// payload.
///
/// Every finite spelling round-trips through Rust's binary64 parser to the same
/// bits. Integral-valued floats retain a decimal point so their scalar kind stays
/// visible.
#[must_use]
pub fn render_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value == f64::INFINITY {
        return "inf".to_string();
    }
    if value == f64::NEG_INFINITY {
        return "-inf".to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }

    let rendered = format!("{value:?}");
    if rendered.contains(['.', 'e', 'E']) {
        rendered
    } else {
        format!("{rendered}.0")
    }
}

/// Render one preserved Lua constant using the canonical scalar policy.
#[must_use]
pub fn render_constant(value: &ConstantValue) -> String {
    match value {
        ConstantValue::Nil => "nil".to_string(),
        ConstantValue::Boolean(value) => value.to_string(),
        ConstantValue::Integer { val, .. } => render_integer(*val),
        ConstantValue::Float { val, .. } => render_float(*val),
        ConstantValue::ShortString(value) | ConstantValue::LongString(value) => {
            render_byte_string(&value.raw_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LuaString;

    #[test]
    fn integer_boundaries_have_canonical_goldens() {
        assert_eq!(render_integer(i64::MIN), "-9223372036854775808");
        assert_eq!(render_integer(i64::MAX), "9223372036854775807");
        assert_eq!(render_integer(0), "0");
    }

    #[test]
    fn byte_string_escape_and_quote_policy_has_a_byte_exact_golden() {
        let bytes = [
            0x00, b'\n', b'\r', b'\t', b' ', b'"', b'\\', b'~', 0x7f, 0x80, 0xff,
        ];
        assert_eq!(
            render_byte_string(&bytes),
            r#""\x00\n\r\t \"\\~\x7f\x80\xff""#
        );
    }

    #[test]
    fn every_non_printable_byte_has_one_defined_escape() {
        for byte in u8::MIN..=u8::MAX {
            let rendered = escape_bytes(&[byte]);
            match byte {
                b'\\' => assert_eq!(rendered, r"\\"),
                b'"' => assert_eq!(rendered, r#"\""#),
                b'\n' => assert_eq!(rendered, r"\n"),
                b'\r' => assert_eq!(rendered, r"\r"),
                b'\t' => assert_eq!(rendered, r"\t"),
                0x20..=0x7e => assert_eq!(rendered.as_bytes(), &[byte]),
                _ => assert_eq!(rendered, format!(r"\x{byte:02x}")),
            }
        }
    }

    #[test]
    fn byte_string_truncation_is_measured_in_raw_bytes_and_is_reversible() {
        let raw_bytes = vec![0xff; BYTE_STRING_PREVIEW_BYTES + 1];
        let value = LuaString::from_bytes(&raw_bytes);
        let expected = format!(r#""{}...""#, r"\xff".repeat(BYTE_STRING_PREVIEW_BYTES));

        assert_eq!(render_byte_string(&value.raw_bytes), expected);
        assert_eq!(value.raw_bytes, raw_bytes);
        assert_eq!(value.display, r"\xff".repeat(BYTE_STRING_PREVIEW_BYTES + 1));
    }

    #[test]
    fn finite_float_goldens_round_trip_to_identical_bits() {
        assert_eq!(render_float(f64::from_bits(1)), "5e-324");
        assert_eq!(render_float(1.0), "1.0");
        assert_eq!(render_float(-42.0), "-42.0");
        assert_eq!(render_float(std::f64::consts::PI), "3.141592653589793");
        assert_eq!(render_float(1.2345e-12), "1.2345e-12");
        assert_eq!(render_float(f64::MAX), "1.7976931348623157e308");

        for bits in [
            0x0000_0000_0000_0001,
            1.0_f64.to_bits(),
            (-42.0_f64).to_bits(),
            std::f64::consts::PI.to_bits(),
            1.2345e-12_f64.to_bits(),
            f64::MAX.to_bits(),
        ] {
            let value = f64::from_bits(bits);
            let rendered = render_float(value);
            let reparsed: f64 = rendered
                .parse()
                .expect("finite rendering must parse as f64");
            assert_eq!(reparsed.to_bits(), bits, "rendering {rendered}");
        }
    }

    #[test]
    fn signed_zero_infinities_and_nan_have_canonical_goldens() {
        assert_eq!(render_float(0.0), "0.0");
        assert_eq!(render_float(-0.0), "-0.0");
        assert_eq!(render_float(f64::INFINITY), "inf");
        assert_eq!(render_float(f64::NEG_INFINITY), "-inf");
        assert_eq!(render_float(f64::from_bits(0x7ff8_0000_0000_0001)), "nan");
        assert_eq!(render_float(f64::from_bits(0xfff0_0000_0000_0001)), "nan");
    }

    #[test]
    fn scalar_mutation_controls_change_the_canonical_golden() {
        let canonical = [
            render_float(-0.0),
            render_float(f64::NAN),
            render_float(1.0),
            render_byte_string(b"\""),
        ]
        .join("\n");

        for corrupted in [
            canonical.replacen("-0.0", "0.0", 1),
            canonical.replacen("nan", "NaN", 1),
            canonical.replacen("1.0", "1", 1),
            canonical.replacen(r#"\""#, "\"", 1),
        ] {
            assert_ne!(corrupted, canonical);
        }
    }
}
