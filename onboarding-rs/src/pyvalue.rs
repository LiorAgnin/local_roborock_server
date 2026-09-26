//! Python-style coercions over loosely typed server JSON, so status handling
//! matches the original `bool(x)`, `int(x or 0)` and `str(x or default)`.

use serde_json::{Map, Value};

pub type Json = Map<String, Value>;

/// Python `bool(value)`; a missing key is falsy.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Python `int(value or 0)`. Numeric strings parse; anything else that
/// Python would reject (e.g. `"abc"`) counts as 0 instead of raising.
pub fn int_or_zero(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(b)) => i64::from(*b),
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f.trunc() as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Python `str(a or b or ... or default)` over the given values.
pub fn first_str(values: &[Option<&Value>], default: &str) -> String {
    values
        .iter()
        .find(|value| truthy(**value))
        .and_then(|value| value.map(py_str))
        .unwrap_or_else(|| default.to_owned())
}

/// Python `dict(value or {})`; non-objects count as empty.
pub fn object(value: Option<&Value>) -> Json {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => Json::new(),
    }
}

/// Python `str(value)` for a JSON scalar (containers fall back to JSON text).
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truthiness_follows_python() {
        for falsy in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(!truthy(Some(&falsy)), "{falsy}");
        }
        for truthy_value in [
            json!(true),
            json!(1),
            json!(-2.5),
            json!("x"),
            json!([0]),
            json!({"a": 1}),
        ] {
            assert!(truthy(Some(&truthy_value)), "{truthy_value}");
        }
        assert!(!truthy(None));
    }

    #[test]
    fn int_or_zero_follows_python() {
        assert_eq!(int_or_zero(None), 0);
        assert_eq!(int_or_zero(Some(&json!(null))), 0);
        assert_eq!(int_or_zero(Some(&json!(3))), 3);
        assert_eq!(int_or_zero(Some(&json!(2.9))), 2);
        assert_eq!(int_or_zero(Some(&json!(true))), 1);
        assert_eq!(int_or_zero(Some(&json!(" 7 "))), 7);
        assert_eq!(int_or_zero(Some(&json!("abc"))), 0);
    }

    #[test]
    fn first_str_picks_first_truthy_value() {
        let name = json!("");
        let duid = json!("duid-1");
        assert_eq!(first_str(&[Some(&name), Some(&duid)], "Unknown"), "duid-1");
        assert_eq!(first_str(&[None, Some(&json!(null))], "Unknown"), "Unknown");
        assert_eq!(first_str(&[Some(&json!(42))], "Unknown"), "42");
    }

    #[test]
    fn py_str_matches_python_scalars() {
        assert_eq!(py_str(&json!("a")), "a");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&json!(false)), "False");
        assert_eq!(py_str(&json!(null)), "None");
        assert_eq!(py_str(&json!(5)), "5");
    }

    #[test]
    fn object_coerces_non_objects_to_empty() {
        assert_eq!(object(Some(&json!({"a": 1})))["a"], json!(1));
        assert!(object(Some(&json!([1]))).is_empty());
        assert!(object(None).is_empty());
    }
}
