//! The CBOR subset the identity objects use, with deterministic encoding.
//!
//! Identity objects are maps of text keys to unsigned integers, byte
//! strings, text strings, arrays and nested maps — five major types. That is
//! small enough that a purpose-built codec is shorter than the glue around a
//! general one, and it lets the crate own the property that matters most:
//! every object has exactly one valid encoding (RFC 8949 §4.2.1), so a
//! signature over "the bytes" is unambiguous.
//!
//! Canonical form is enforced on the way in by decode-then-re-encode:
//! [`decode_canonical`] rejects any input whose re-encoding differs from the
//! input. Shortest integer heads, definite lengths, sorted map keys and the
//! absence of duplicates all fall out of that one comparison.

use std::fmt;

/// A decoded CBOR value from the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in encoded order. [`encode`] sorts them; [`decode_canonical`]
    /// guarantees they arrived sorted.
    Map(Vec<(Value, Value)>),
}

/// Why a byte string failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Input ended inside an item.
    Truncated,
    /// Trailing bytes after the top-level item.
    Trailing,
    /// A major type or additional-information value outside the subset
    /// (negative integers, floats, tags, indefinite lengths, simple values).
    Unsupported(u8),
    /// A text string that wasn't UTF-8.
    Utf8,
    /// Nesting deeper than the codec is willing to follow.
    TooDeep,
    /// The input was well-formed but not the deterministic encoding.
    NotCanonical,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "truncated CBOR"),
            CborError::Trailing => write!(f, "trailing bytes after CBOR item"),
            CborError::Unsupported(b) => write!(f, "unsupported CBOR head byte 0x{b:02x}"),
            CborError::Utf8 => write!(f, "CBOR text string is not UTF-8"),
            CborError::TooDeep => write!(f, "CBOR nesting too deep"),
            CborError::NotCanonical => write!(f, "CBOR is not in deterministic encoding"),
        }
    }
}

impl std::error::Error for CborError {}

const MAX_DEPTH: usize = 8;

fn put_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | n as u8);
    } else if n <= 0xff {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => put_head(out, 0, *n),
        Value::Bytes(b) => {
            put_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            put_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            put_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            // Sort by the encoded key bytes — the §4.2.1 rule. Keys are
            // encoded once here and reused, so sorting doesn't re-encode.
            let mut encoded: Vec<(Vec<u8>, &Value)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut kb = Vec::new();
                    encode_into(k, &mut kb);
                    (kb, v)
                })
                .collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            put_head(out, 5, encoded.len() as u64);
            for (kb, v) in encoded {
                out.extend_from_slice(&kb);
                encode_into(v, out);
            }
        }
    }
}

/// Encode a value in deterministic form.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let b = self.byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        let n = match ai {
            0..=23 => ai as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(CborError::Unsupported(b)),
        };
        Ok((major, n))
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let start = self.pos;
        let (major, n) = self.head()?;
        let len = |n: u64| usize::try_from(n).map_err(|_| CborError::Truncated);
        match major {
            0 => Ok(Value::Uint(n)),
            2 => Ok(Value::Bytes(self.take(len(n)?)?.to_vec())),
            3 => {
                let s = std::str::from_utf8(self.take(len(n)?)?).map_err(|_| CborError::Utf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let count = len(n)?;
                // A count larger than the remaining input can't be honest;
                // refuse before allocating.
                if count > self.buf.len() - self.pos {
                    return Err(CborError::Truncated);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = len(n)?;
                if count > (self.buf.len() - self.pos) / 2 {
                    return Err(CborError::Truncated);
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let k = self.item(depth + 1)?;
                    let v = self.item(depth + 1)?;
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CborError::Unsupported(self.buf[start])),
        }
    }
}

/// Decode one item, requiring the input to be exactly its deterministic
/// encoding. This is the only decoder the crate exposes: an object that
/// isn't canonical has no signature worth checking.
pub fn decode_canonical(bytes: &[u8]) -> Result<Value, CborError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let v = r.item(0)?;
    if r.pos != bytes.len() {
        return Err(CborError::Trailing);
    }
    if encode(&v) != bytes {
        return Err(CborError::NotCanonical);
    }
    if has_duplicate_keys(&v) {
        return Err(CborError::NotCanonical);
    }
    Ok(v)
}

/// Sorted maps put duplicates side by side, so one pass over each map's
/// adjacent key pairs finds them. Re-encoding alone can't: a duplicated
/// key re-encodes to the same duplicated bytes.
fn has_duplicate_keys(v: &Value) -> bool {
    match v {
        Value::Map(entries) => {
            entries.windows(2).any(|w| w[0].0 == w[1].0)
                || entries
                    .iter()
                    .any(|(k, v)| has_duplicate_keys(k) || has_duplicate_keys(v))
        }
        Value::Array(items) => items.iter().any(has_duplicate_keys),
        _ => false,
    }
}

impl Value {
    /// Look up a text key in a map. `None` for a missing key *or* a
    /// non-map; callers treat both as "field absent".
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The same map with one text key removed. Used to produce the
    /// signed bytes (the object without its `sig`).
    pub fn without(&self, key: &str) -> Value {
        match self {
            Value::Map(entries) => Value::Map(
                entries
                    .iter()
                    .filter(|(k, _)| !matches!(k, Value::Text(t) if t == key))
                    .cloned()
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

/// Build a map value from text keys. `None` values are omitted, which is
/// how optional fields stay out of the encoding.
pub fn map(entries: Vec<(&str, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::Text(k.to_owned()), v)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_are_shortest() {
        assert_eq!(encode(&Value::Uint(0)), [0x00]);
        assert_eq!(encode(&Value::Uint(23)), [0x17]);
        assert_eq!(encode(&Value::Uint(24)), [0x18, 0x18]);
        assert_eq!(encode(&Value::Uint(256)), [0x19, 0x01, 0x00]);
        assert_eq!(
            encode(&Value::Uint(1 << 32)),
            [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn map_keys_sort_by_encoded_bytes() {
        // Length-first: "z" (0x61 'z') sorts before "aa" (0x62 'a' 'a').
        let v = map(vec![
            ("aa", Some(Value::Uint(1))),
            ("z", Some(Value::Uint(2))),
        ]);
        assert_eq!(encode(&v), [0xa2, 0x61, b'z', 0x02, 0x62, b'a', b'a', 0x01]);
    }

    #[test]
    fn non_canonical_is_rejected() {
        // uint 1 encoded with a one-byte argument.
        assert_eq!(
            decode_canonical(&[0x18, 0x01]),
            Err(CborError::NotCanonical)
        );
        // Map with keys out of order.
        assert_eq!(
            decode_canonical(&[0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'z', 0x02]),
            Err(CborError::NotCanonical)
        );
        // Duplicate keys re-encode to the same bytes, so they need their
        // own guard.
        assert_eq!(
            decode_canonical(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
            Err(CborError::NotCanonical)
        );
    }

    #[test]
    fn unsupported_types_are_rejected() {
        assert_eq!(decode_canonical(&[0x20]), Err(CborError::Unsupported(0x20))); // -1
        assert_eq!(decode_canonical(&[0xf5]), Err(CborError::Unsupported(0xf5))); // true
        assert_eq!(
            decode_canonical(&[0x5f, 0xff]),
            Err(CborError::Unsupported(0x5f))
        ); // indefinite
        assert_eq!(
            decode_canonical(&[0xc0, 0x00]),
            Err(CborError::Unsupported(0xc0))
        ); // tag
    }

    #[test]
    fn round_trip() {
        let v = map(vec![
            ("v", Some(Value::Uint(1))),
            ("b", Some(Value::Bytes(vec![1, 2, 3]))),
            ("t", Some(Value::Text("hi".into()))),
            (
                "a",
                Some(Value::Array(vec![
                    Value::Uint(7),
                    map(vec![("x", Some(Value::Uint(0)))]),
                ])),
            ),
            ("skip", None),
        ]);
        let bytes = encode(&v);
        let back = decode_canonical(&bytes).unwrap();
        assert_eq!(encode(&back), bytes);
        assert_eq!(back.get("t"), Some(&Value::Text("hi".into())));
        assert!(back.get("skip").is_none());
        assert!(back.without("v").get("v").is_none());
    }
}
