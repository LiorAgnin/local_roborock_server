//! JSON serialization byte-identical to Python's
//! `json.dumps(obj, separators=(",", ":"))` with the default `ensure_ascii=True`.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter, Serializer};

/// Serialize `value` exactly like `json.dumps(value, separators=(",", ":"))`.
///
/// Panics only if `T`'s `Serialize` impl fails (e.g. non-string map keys),
/// which cannot happen for the fixed payload types used here.
pub fn dumps<T: Serialize + ?Sized>(value: &T) -> String {
    let mut out = Vec::new();
    let mut ser = Serializer::with_formatter(&mut out, AsciiFormatter);
    value
        .serialize(&mut ser)
        .expect("payload types always serialize");
    // AsciiFormatter only ever emits ASCII.
    String::from_utf8(out).expect("ASCII output")
}

/// Compact formatter that additionally escapes everything outside printable
/// ASCII (`' '..='~'`) as `\uXXXX`, like CPython's `ensure_ascii`.
struct AsciiFormatter;

impl Formatter for AsciiFormatter {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // serde_json already escaped '"', '\\' and C0 controls; the fragment
        // holds everything else.
        let mut start = 0;
        for (idx, ch) in fragment.char_indices() {
            if (' '..='~').contains(&ch) {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..idx])?;
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = idx + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn begin_array_value<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        CompactFormatter.begin_array_value(w, first)
    }

    fn begin_object_key<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        CompactFormatter.begin_object_key(w, first)
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        CompactFormatter.begin_object_value(w)
    }
}

#[cfg(test)]
mod tests {
    use super::dumps;
    use serde::Serialize;
    use serde_json::json;

    #[test]
    fn ascii_passes_through_and_slash_is_not_escaped() {
        assert_eq!(dumps(&json!({"a": "x/y"})), r#"{"a":"x/y"}"#);
    }

    #[test]
    fn uses_compact_separators() {
        assert_eq!(dumps(&json!([1, {"b": true}])), r#"[1,{"b":true}]"#);
    }

    /// Python-style escape for one UTF-16 unit, e.g. `esc("00e9")`.
    fn esc(unit: &str) -> String {
        format!("\\u{unit}")
    }

    #[test]
    fn escapes_non_ascii_as_lowercase_utf16_units() {
        let expected = format!("\"{}{}\"", esc("00e9"), esc("2615"));
        assert_eq!(dumps("\u{e9}\u{2615}"), expected);
    }

    #[test]
    fn escapes_astral_chars_as_surrogate_pairs() {
        let expected = format!("\"{}{}\"", esc("d83d"), esc("de00"));
        assert_eq!(dumps("\u{1f600}"), expected);
    }

    #[test]
    fn escapes_control_chars_like_python() {
        assert_eq!(
            dumps("\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f}"),
            r#""\"\\\n\r\t\b\f\u0001\u007f""#
        );
    }

    #[test]
    fn keeps_struct_field_order() {
        #[derive(Serialize)]
        struct Body {
            z: u8,
            a: &'static str,
        }
        let expected = format!(r#"{{"z":1,"a":"{}"}}"#, esc("00e9"));
        assert_eq!(dumps(&Body { z: 1, a: "\u{e9}" }), expected);
    }
}
