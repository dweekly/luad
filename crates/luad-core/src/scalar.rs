//! Canonical, platform-independent rendering of preserved scalar values.
//!
//! This module is the only rendering authority for scalar values that reach a
//! user, on every dialect and through both the text listing and the typed
//! machine facts. Rendering depends only on the preserved value; it does not
//! inspect a dialect, host layout, locale, or target width.
//!
//! Float spellings come from Rust's `f64: Debug`, which formats in `core` rather
//! than through the host C library. The output is therefore identical on every
//! target for a given toolchain; the workspace pins that toolchain in
//! `rust-toolchain.toml`.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::model::ConstantValue;

/// Maximum number of raw string bytes included in a human-facing scalar preview.
///
/// Truncation is measured only in input bytes. The complete byte sequence remains
/// available in [`crate::model::LuaString::raw_bytes`], and in the text surface
/// through the untruncated renderers.
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

/// Render a quoted byte-string preview bounded to [`BYTE_STRING_PREVIEW_BYTES`]
/// input bytes.
///
/// A truncated preview always carries the total input length, so a preview that
/// ends in a literal `...` is never confused with an elision.
#[must_use]
pub fn render_byte_string(bytes: &[u8]) -> String {
    if bytes.len() > BYTE_STRING_PREVIEW_BYTES {
        let escaped = escape_bytes(&bytes[..BYTE_STRING_PREVIEW_BYTES]);
        format!(r#""{escaped}..." ({} bytes)"#, bytes.len())
    } else {
        render_byte_string_full(bytes)
    }
}

/// Render a quoted byte string from every input byte, without a preview bound.
#[must_use]
pub fn render_byte_string_full(bytes: &[u8]) -> String {
    format!(r#""{}""#, escape_bytes(bytes))
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
/// bits, and stays visibly a float by carrying a decimal point or an exponent.
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
        // Defensive: `f64: Debug` emits a decimal point or an exponent for every
        // finite value, so this arm is unreachable today. It holds the "integral
        // floats stay visibly floats" guarantee independently of that impl.
        // `finite_debug_spelling_is_always_visibly_a_float` fails if the
        // guarantee ever starts depending on this arm.
        format!("{rendered}.0")
    }
}

/// Render one preserved Lua constant using the canonical scalar policy, bounding
/// byte strings to a preview.
#[must_use]
pub fn render_constant(value: &ConstantValue) -> String {
    render_constant_with(value, render_byte_string)
}

/// Render one preserved Lua constant using the canonical scalar policy, emitting
/// byte strings in full.
#[must_use]
pub fn render_constant_full(value: &ConstantValue) -> String {
    render_constant_with(value, render_byte_string_full)
}

/// Render a bounded comparison preview with exact representation metadata.
///
/// The canonical scalar spelling stays readable; type, float bits, raw numeric
/// encoding, and a digest of complete string bytes distinguish representations
/// that can share that spelling. Digests are display evidence, never equality
/// predicates. Raw hex is itself bounded because callers can construct models.
#[must_use]
pub fn render_constant_evidence(value: &ConstantValue) -> String {
    let scalar = render_constant(value);
    let detail = match value {
        ConstantValue::Nil => "nil".into(),
        ConstantValue::Boolean(_) => "boolean".into(),
        ConstantValue::Integer { raw_hex, .. } => {
            format!("integer raw={}", render_byte_string(raw_hex.as_bytes()))
        }
        ConstantValue::Float {
            val,
            raw_hex,
            is_nan,
            is_inf,
        } => {
            format!(
                "float bits={:016x} nan={is_nan} inf={is_inf} raw={}",
                val.to_bits(),
                render_byte_string(raw_hex.as_bytes())
            )
        }
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
            let kind = if matches!(value, ConstantValue::ShortString(_)) {
                "short-string"
            } else {
                "long-string"
            };
            format!(
                "{kind} len={} sha256={:x}",
                s.raw_bytes.len(),
                Sha256::digest(&s.raw_bytes)
            )
        }
    };
    format!("{detail} {scalar}")
}

fn render_constant_with(value: &ConstantValue, render_string: fn(&[u8]) -> String) -> String {
    match value {
        ConstantValue::Nil => "nil".to_string(),
        ConstantValue::Boolean(value) => value.to_string(),
        ConstantValue::Integer { val, .. } => render_integer(*val),
        ConstantValue::Float { val, .. } => render_float(*val),
        ConstantValue::ShortString(value) | ConstantValue::LongString(value) => {
            render_string(&value.raw_bytes)
        }
    }
}

/// Serde/schema policy for decoded machine floats. Exact source bits live separately.
pub(crate) mod json_float {
    use schemars::schema::{InstanceType, Schema, SchemaObject, SubschemaValidation};
    use schemars::{r#gen::SchemaGenerator, JsonSchema};
    use serde::{de, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
        if value.is_finite() {
            serializer.serialize_f64(*value)
        } else {
            // NaN payloads after float-width conversion need not be portable.
            // The canonical class is portable; raw_hex retains the source bits.
            serializer.serialize_str(&super::render_float(*value))
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
        struct FloatVisitor;
        impl de::Visitor<'_> for FloatVisitor {
            type Value = f64;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a finite number or the exact string nan, inf, or -inf")
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<f64, E> {
                if value.is_finite() {
                    Ok(value)
                } else {
                    Err(E::custom(
                        "nonfinite machine floats require a canonical string",
                    ))
                }
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<f64, E> {
                Ok(value as f64)
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<f64, E> {
                Ok(value as f64)
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<f64, E> {
                match value {
                    "nan" => Ok(f64::NAN),
                    "inf" => Ok(f64::INFINITY),
                    "-inf" => Ok(f64::NEG_INFINITY),
                    _ => Err(E::custom("unknown machine float string")),
                }
            }
        }
        // Serde forwards owned and borrowed strings to visit_str, including its
        // buffered internally/adjacently tagged-enum deserializers.
        deserializer.deserialize_any(FloatVisitor)
    }

    pub fn schema(generator: &mut SchemaGenerator) -> Schema {
        let classes = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY]
            .into_iter()
            .map(|value| serde_json::Value::String(super::render_float(value)))
            .collect();
        SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    f64::json_schema(generator),
                    SchemaObject {
                        instance_type: Some(InstanceType::String.into()),
                        enum_values: Some(classes),
                        ..Default::default()
                    }
                    .into(),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LuaString;

    #[test]
    fn comparison_evidence_is_bounded_and_preserves_scalar_spelling() {
        let string = ConstantValue::LongString(LuaString::from_bytes(&vec![0xff; 4096]));
        let rendered = render_constant_evidence(&string);
        assert!(rendered.len() < 400);
        assert!(rendered.ends_with(&render_constant(&string)));
        let integer = ConstantValue::Integer {
            val: 42,
            raw_hex: "f".repeat(4096),
        };
        assert!(render_constant_evidence(&integer).len() < 400);
        let nan = |bits| ConstantValue::Float {
            val: f64::from_bits(bits),
            raw_hex: format!("{bits:016x}"),
            is_nan: true,
            is_inf: false,
        };
        let a = nan(0x7ff8_0000_0000_0001);
        let b = nan(0x7ff8_0000_0000_0002);
        assert_eq!(render_constant(&a), render_constant(&b));
        assert_ne!(render_constant_evidence(&a), render_constant_evidence(&b));
    }

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
        let expected = format!(
            r#""{}..." ({} bytes)"#,
            r"\xff".repeat(BYTE_STRING_PREVIEW_BYTES),
            BYTE_STRING_PREVIEW_BYTES + 1
        );

        assert_eq!(render_byte_string(&value.raw_bytes), expected);
        assert_eq!(
            render_byte_string_full(&value.raw_bytes),
            format!(r#""{}""#, r"\xff".repeat(BYTE_STRING_PREVIEW_BYTES + 1))
        );
        assert_eq!(value.raw_bytes, raw_bytes);
        assert_eq!(value.display, r"\xff".repeat(BYTE_STRING_PREVIEW_BYTES + 1));
    }

    #[test]
    fn a_bounded_preview_is_never_ambiguous_with_a_literal_ellipsis() {
        let mut ends_in_ellipsis = vec![b'a'; BYTE_STRING_PREVIEW_BYTES - 3];
        ends_in_ellipsis.extend_from_slice(b"...");
        assert_eq!(ends_in_ellipsis.len(), BYTE_STRING_PREVIEW_BYTES);

        let untruncated = render_byte_string(&ends_in_ellipsis);
        assert!(untruncated.ends_with(r#"...""#));
        assert!(!untruncated.contains(" bytes)"));

        let mut truncated_source = ends_in_ellipsis.clone();
        truncated_source.push(b'a');
        let truncated = render_byte_string(&truncated_source);
        assert!(truncated.ends_with(&format!("({} bytes)", BYTE_STRING_PREVIEW_BYTES + 1)));
        assert_ne!(truncated, untruncated);
    }

    #[test]
    fn preview_and_full_renderings_agree_at_or_below_the_bound() {
        for len in [
            0,
            1,
            BYTE_STRING_PREVIEW_BYTES - 1,
            BYTE_STRING_PREVIEW_BYTES,
        ] {
            let bytes = vec![b'z'; len];
            assert_eq!(
                render_byte_string(&bytes),
                render_byte_string_full(&bytes),
                "length {len} must not be bounded"
            );
        }
    }

    /// `render_float` appends `.0` only if `f64: Debug` ever omits both a decimal
    /// point and an exponent for a finite value. Today it never does, so that arm
    /// is unreachable and this test says so out loud. If Rust's formatting ever
    /// changes, this fails first and points at the defensive arm rather than
    /// letting a golden shift silently.
    #[test]
    fn finite_debug_spelling_is_always_visibly_a_float() {
        let mut state: u64 = 0x243f_6a88_85a3_08d3;
        let mut finite_checked = 0u32;
        let mut relied_on_defensive_arm = 0u32;

        let check = |value: f64, finite_checked: &mut u32, relied: &mut u32| {
            if !value.is_finite() || value == 0.0 {
                return;
            }
            *finite_checked += 1;
            let debug_spelling = format!("{value:?}");
            if !debug_spelling.contains(['.', 'e', 'E']) {
                *relied += 1;
            }
            let rendered = render_float(value);
            assert!(
                rendered.contains(['.', 'e', 'E']),
                "{rendered} is not visibly a float"
            );
            let reparsed: f64 = rendered
                .parse()
                .expect("finite rendering must parse as f64");
            assert_eq!(reparsed.to_bits(), value.to_bits(), "rendering {rendered}");
        };

        for value in [
            f64::MIN,
            f64::MAX,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            1.0,
            -1.0,
            1e15,
            1e16,
            1e21,
            1e22,
            123_456_789_012_345_680.0,
            std::f64::consts::PI,
        ] {
            check(value, &mut finite_checked, &mut relied_on_defensive_arm);
        }

        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            check(
                f64::from_bits(state),
                &mut finite_checked,
                &mut relied_on_defensive_arm,
            );
        }

        assert!(
            finite_checked > 1_000,
            "sample was too small to be evidence"
        );
        assert_eq!(
            relied_on_defensive_arm, 0,
            "f64: Debug now omits the decimal point; the defensive arm in render_float is live"
        );
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
    fn json_finite_float_roundtrips_are_exact() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut values = vec![
            f64::from_bits(0xce63_36ec_9377_1f1d),
            0.0,
            -0.0,
            f64::MIN,
            f64::MAX,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            f64::from_bits(0x000f_ffff_ffff_ffff),
            1.2345678901234567,
            2.2250738585072014e-308,
            9007199254740992.0,
        ];
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = f64::from_bits(state);
            if value.is_finite() {
                values.push(value);
            }
        }
        for value in values {
            let original = ConstantValue::Float {
                val: value,
                raw_hex: hex::encode(value.to_le_bytes()),
                is_nan: false,
                is_inf: false,
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ConstantValue = serde_json::from_str(&json).unwrap();
            let ConstantValue::Float { val, raw_hex, .. } = decoded else {
                panic!("float")
            };
            assert_eq!(
                val.to_bits(),
                value.to_bits(),
                "finite JSON lost bits for {json}"
            );
            assert_eq!(raw_hex, hex::encode(value.to_le_bytes()));
        }
    }
}
