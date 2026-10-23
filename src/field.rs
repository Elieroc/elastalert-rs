//! Dotted field lookup with ElastAlert's resolution rules:
//! longest literal key wins (`a.b` as one key beats `a` -> `b`), `name[3]` indexes a list,
//! and a path that runs past a leaf value returns the leaf (so `user.keyword` finds `user`).

use serde_json::{Map, Value};

enum Seg {
    Key(String),
    Idx(usize),
}

/// `foo[3]rest` -> ("foo", 3, "rest"). Only a single digit, like upstream.
fn split_index(root: &str) -> Option<(&str, usize, &str)> {
    let b = root.as_bytes();
    (1..b.len().saturating_sub(2)).find_map(|i| {
        (b[i] == b'[' && b[i + 1].is_ascii_digit() && b[i + 2] == b']')
            .then(|| (&root[..i], (b[i + 1] - b'0') as usize, &root[i + 3..]))
    })
}

fn resolve(map: &Map<String, Value>, term: &str, path: &mut Vec<Seg>) -> bool {
    let subkeys: Vec<&str> = term.split('.').collect();
    for i in (1..=subkeys.len()).rev() {
        let joined = subkeys[..i].join(".");
        let (root, idx, tail) = match split_index(&joined) {
            Some((r, n, t)) => (r, Some(n), t),
            None => (joined.as_str(), None, ""),
        };
        let Some(val) = map.get(root) else { continue };
        let mut child_parts: Vec<&str> = Vec::new();
        if !tail.is_empty() {
            child_parts.push(tail);
        }
        child_parts.extend(&subkeys[i..]);
        let child = child_parts.join(".");
        path.push(Seg::Key(root.to_string()));
        if let Some(n) = idx {
            let Some(item) = val.as_array().and_then(|a| a.get(n)) else { return false };
            path.push(Seg::Idx(n));
            if child.is_empty() {
                return true;
            }
            if let Value::Object(m) = item {
                return resolve(m, &child, path);
            }
            path.pop();
        }
        return match val {
            Value::Object(m) if !child.is_empty() => resolve(m, &child, path),
            _ => true,
        };
    }
    false
}

pub fn lookup<'a>(doc: &'a Map<String, Value>, term: &str) -> Option<&'a Value> {
    let mut path = Vec::new();
    if !resolve(doc, term, &mut path) {
        return None;
    }
    let mut segs = path.iter();
    let Some(Seg::Key(k)) = segs.next() else { return None };
    let mut cur = doc.get(k)?;
    for s in segs {
        cur = match s {
            Seg::Key(k) => cur.get(k)?,
            Seg::Idx(n) => cur.get(*n)?,
        };
    }
    Some(cur)
}

/// Python truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

/// Sets the value at the location `lookup` would read. Returns false when the term does not resolve.
pub fn set(doc: &mut Map<String, Value>, term: &str, value: Value) -> bool {
    let mut path = Vec::new();
    if !resolve(doc, term, &mut path) {
        return false;
    }
    let mut segs = path.iter();
    let Some(Seg::Key(k)) = segs.next() else { return false };
    let mut cur = match doc.get_mut(k) {
        Some(v) => v,
        None => return false,
    };
    for s in segs {
        cur = match s {
            Seg::Key(k) => match cur.get_mut(k) {
                Some(v) => v,
                None => return false,
            },
            Seg::Idx(n) => match cur.get_mut(*n) {
                Some(v) => v,
                None => return false,
            },
        };
    }
    *cur = value;
    true
}

/// Python `str()` of a scalar, used wherever ElastAlert stringifies a field value.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => py_float(n.as_f64().unwrap_or_default()),
        Value::Number(n) => n.to_string(),
        // Python would print the repr of a list/dict here; JSON is close enough and readable.
        other => other.to_string(),
    }
}

fn py_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        return format!("{f:.1}");
    }
    let shortest = f.to_string();
    // With 17 digits Rust breaks exact ties upwards where Python's repr rounds to even
    // (a float32 widened to f64 ends in ...5 at the 18th digit); the exact-mode format agrees with Python.
    let digits = shortest.bytes().filter(u8::is_ascii_digit).skip_while(|b| *b == b'0').count();
    if digits < 17 || !f.is_finite() {
        return shortest;
    }
    let exact = format!("{f:.16e}");
    let (mantissa, exp) = exact.split_once('e').expect("exponent form");
    let exp: i32 = exp.parse().expect("exponent");
    if exact.parse::<f64>() != Ok(f) || !(-5..16).contains(&exp) {
        return shortest;
    }
    let (sign, mantissa) = mantissa.strip_prefix('-').map_or(("", mantissa), |m| ("-", m));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let plain = if exp >= 0 {
        let int = (exp + 1) as usize;
        format!("{}.{}", &digits[..int], &digits[int..])
    } else {
        format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
    };
    format!("{sign}{}", plain.trim_end_matches('0').trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn m(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn lookup_rules() {
        let d = m(json!({"a": {"b": {"c": 1}}, "x.y": 2, "user": "bob", "l": [{"k": 5}, 7]}));
        assert_eq!(lookup(&d, "a.b.c"), Some(&json!(1)));
        assert_eq!(lookup(&d, "x.y"), Some(&json!(2)));
        assert_eq!(lookup(&d, "user.keyword"), Some(&json!("bob")));
        assert_eq!(lookup(&d, "l[0]"), Some(&json!({"k": 5})));
        assert_eq!(lookup(&d, "l[1]"), Some(&json!(7)));
        assert_eq!(lookup(&d, "a.b.missing"), None);
        assert_eq!(lookup(&d, "nope"), None);
    }

    #[test]
    fn set_follows_lookup() {
        let mut d = m(json!({"a": {"b": 1}}));
        assert!(set(&mut d, "a.b", json!(2)));
        assert_eq!(lookup(&d, "a.b"), Some(&json!(2)));
        assert!(!set(&mut d, "zz", json!(1)));
    }

    #[test]
    fn python_float_repr_ties() {
        assert_eq!(py_str(&serde_json::json!(2.6110000610351562)), "2.6110000610351562");
        assert_eq!(py_str(&serde_json::json!(-0.30000000000000004)), "-0.30000000000000004");
        assert_eq!(py_str(&serde_json::json!(0.1)), "0.1");
        assert_eq!(py_str(&serde_json::json!(12.0)), "12.0");
    }

    #[test]
    fn python_str() {
        assert_eq!(py_str(&json!(1.0)), "1.0");
        assert_eq!(py_str(&json!(2)), "2");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&json!(null)), "None");
    }
}
