use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum SexpNode {
    Atom(Vec<u8>),
    List(Vec<SexpNode>),
}

impl SexpNode {
    pub fn to_canonical(&self) -> Vec<u8> {
        match self {
            SexpNode::Atom(data) => {
                let len_str = data.len().to_string();
                let mut result = Vec::with_capacity(len_str.len() + 1 + data.len());
                result.extend_from_slice(len_str.as_bytes());
                result.push(b':');
                result.extend_from_slice(data);
                result
            }
            SexpNode::List(items) => {
                let mut result = Vec::new();
                result.push(b'(');
                for item in items {
                    result.extend(item.to_canonical());
                }
                result.push(b')');
                result
            }
        }
    }

    pub fn as_atom(&self) -> Option<&[u8]> {
        match self {
            SexpNode::Atom(data) => Some(data),
            SexpNode::List(_) => None,
        }
    }

    pub fn as_list(&self) -> Option<&[SexpNode]> {
        match self {
            SexpNode::Atom(_) => None,
            SexpNode::List(items) => Some(items),
        }
    }

    pub fn find_named(&self, name: &str) -> Option<&SexpNode> {
        let items = self.as_list()?;
        for item in items {
            if let SexpNode::List(sub) = item {
                if let Some(SexpNode::Atom(first)) = sub.first() {
                    if first == name.as_bytes() {
                        return Some(item);
                    }
                }
            }
        }
        None
    }

    pub fn get_value(&self, name: &str) -> Option<&[u8]> {
        let items = self.as_list()?;
        for item in items {
            if let SexpNode::List(sub) = item {
                if let Some(SexpNode::Atom(first)) = sub.first() {
                    if first == name.as_bytes() {
                        if let Some(SexpNode::Atom(value)) = sub.get(1) {
                            return Some(value);
                        }
                    }
                }
            }
        }
        None
    }
}

impl SexpNode {
    /// The leading atom of a list, e.g. `enc-val` in `(enc-val ...)`.
    pub fn name(&self) -> Option<&[u8]> {
        self.as_list()?.first()?.as_atom()
    }
}

/// Parse a canonical S-expression (`(3:foo2:ab)`), the form used on the
/// wire and inside protected key blobs.
pub fn parse_canonical(data: &[u8]) -> Result<SexpNode> {
    let mut parser = CanonicalParser::new(data);
    let node = parse_canonical_node(&mut parser)?;
    if !parser.remaining().is_empty() {
        return Err(Error::SexpParse("trailing data after S-expression".into()));
    }
    Ok(node)
}

/// Length of the canonical S-expression at the start of `data`, ignoring
/// anything after it (gpg pads wrapped keys to a multiple of 8 bytes).
pub fn canonical_len(data: &[u8]) -> Result<usize> {
    CanonicalParser::new(data).skip_sexp()
}

fn parse_canonical_node(parser: &mut CanonicalParser) -> Result<SexpNode> {
    if !parser.peek_is_list() {
        return Ok(SexpNode::Atom(parser.read_atom()?.to_vec()));
    }
    parser.expect_list_start()?;
    let mut items = Vec::new();
    while !parser.peek_is_list_end() {
        if parser.remaining().is_empty() {
            return Err(Error::SexpParse("unclosed list".into()));
        }
        items.push(parse_canonical_node(parser)?);
    }
    parser.expect_list_end()?;
    Ok(SexpNode::List(items))
}

/// Render in GnuPG's advanced format, as written to `Key:` in key files:
/// plain tokens where libgcrypt allows them, quoted printable strings, and
/// `#hex#` for everything else.
pub fn render_advanced(node: &SexpNode) -> String {
    let mut out = String::new();
    render_into(node, &mut out);
    out
}

fn render_into(node: &SexpNode, out: &mut String) {
    match node {
        SexpNode::List(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 && matches!(item, SexpNode::Atom(_)) {
                    out.push(' ');
                }
                render_into(item, out);
            }
            out.push(')');
        }
        SexpNode::Atom(data) => {
            let token = data.first().is_some_and(u8::is_ascii_alphabetic)
                && data
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(b));
            let printable = !data.is_empty()
                && data
                    .iter()
                    .all(|b| (0x20..0x7f).contains(b) && *b != b'"' && *b != b'\\');
            if token {
                out.push_str(std::str::from_utf8(data).unwrap_or_default());
            } else if printable {
                out.push('"');
                out.push_str(std::str::from_utf8(data).unwrap_or_default());
                out.push('"');
            } else {
                out.push('#');
                out.push_str(&hex::encode_upper(data));
                out.push('#');
            }
        }
    }
}

/// Append a canonical atom (`<len>:<bytes>`).
pub fn push_atom(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(data);
}

/// Append a canonical `(<name><value>)` pair, e.g. `(1:q33:...)`.
pub fn push_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b'(');
    push_atom(out, name);
    push_atom(out, value);
    out.push(b')');
}

pub fn parse_gpg_sexp(input: &str) -> Result<SexpNode> {
    let mut chars = input.chars().peekable();
    skip_whitespace(&mut chars);
    parse_node(&mut chars)
}

fn parse_node(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    skip_whitespace(chars);

    match chars.peek().copied() {
        Some('(') => parse_list(chars),
        Some('#') => parse_hex_atom(chars),
        Some('"') => parse_quoted_atom(chars),
        Some(c) if c.is_ascii_digit() && is_length_prefixed(chars) => parse_length_prefixed(chars),
        Some(c) if c.is_alphanumeric() || c == '-' || c == '_' => parse_token(chars),
        Some(c) => Err(Error::SexpParse(format!("unexpected char: {}", c))),
        None => Err(Error::SexpParse("unexpected end of input".to_string())),
    }
}

fn parse_list(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    chars.next();
    let mut items = Vec::new();

    loop {
        skip_whitespace(chars);
        match chars.peek() {
            Some(')') => {
                chars.next();
                return Ok(SexpNode::List(items));
            }
            Some(_) => items.push(parse_node(chars)?),
            None => return Err(Error::SexpParse("unclosed list".to_string())),
        }
    }
}

fn parse_hex_atom(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    chars.next();
    let mut hex_chars = String::new();

    loop {
        match chars.peek() {
            Some('#') => {
                chars.next();
                break;
            }
            Some(c) if c.is_ascii_hexdigit() => {
                hex_chars.push(*c);
                chars.next();
            }
            Some(c) if c.is_whitespace() => {
                chars.next();
            }
            Some(c) => return Err(Error::SexpParse(format!("invalid hex char: {}", c))),
            None => return Err(Error::SexpParse("unclosed hex string".to_string())),
        }
    }

    let data = hex::decode(&hex_chars).map_err(Error::HexDecode)?;
    Ok(SexpNode::Atom(data))
}

fn parse_quoted_atom(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    chars.next();
    let mut data = Vec::new();

    loop {
        match chars.next() {
            Some('"') => return Ok(SexpNode::Atom(data)),
            Some('\\') => match chars.next() {
                Some('n') => data.push(b'\n'),
                Some('r') => data.push(b'\r'),
                Some('t') => data.push(b'\t'),
                Some('\\') => data.push(b'\\'),
                Some('"') => data.push(b'"'),
                Some(c) => {
                    data.push(b'\\');
                    let mut buf = [0u8; 4];
                    data.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                None => return Err(Error::SexpParse("unclosed string".to_string())),
            },
            Some(c) => {
                let mut buf = [0u8; 4];
                data.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            None => return Err(Error::SexpParse("unclosed string".to_string())),
        }
    }
}

/// Whether the input continues with `<digits>:`, libgcrypt's length-prefixed
/// atom, which may appear inside the advanced form (gpg sends
/// `(genkey(ecc(curve 7:Ed25519)))`).
fn is_length_prefixed(chars: &std::iter::Peekable<std::str::Chars>) -> bool {
    let mut look = chars.clone();
    let mut digits = 0;
    while look.peek().is_some_and(char::is_ascii_digit) {
        look.next();
        digits += 1;
    }
    digits > 0 && look.peek() == Some(&':')
}

fn parse_length_prefixed(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    let mut len = 0usize;
    while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
        len = len
            .checked_mul(10)
            .and_then(|v| v.checked_add(d as usize))
            .ok_or_else(|| Error::SexpParse("length overflow".into()))?;
        chars.next();
    }
    chars.next(); // ':'
    let mut data = Vec::with_capacity(len.min(4096));
    while data.len() < len {
        let c = chars
            .next()
            .ok_or_else(|| Error::SexpParse("atom length out of bounds".into()))?;
        let mut buf = [0u8; 4];
        data.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    if data.len() != len {
        return Err(Error::SexpParse("atom length splits a character".into()));
    }
    Ok(SexpNode::Atom(data))
}

fn parse_token(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<SexpNode> {
    let mut token = String::new();

    while let Some(&c) = chars.peek() {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.' {
            token.push(c);
            chars.next();
        } else {
            break;
        }
    }

    Ok(SexpNode::Atom(token.into_bytes()))
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

pub struct CanonicalParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CanonicalParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub fn skip_sexp(&mut self) -> Result<usize> {
        let start = self.pos;
        self.skip_sexp_internal()?;
        Ok(self.pos - start)
    }

    fn skip_sexp_internal(&mut self) -> Result<()> {
        if self.pos >= self.data.len() {
            return Err(Error::SexpParse("unexpected end".to_string()));
        }

        if self.data[self.pos] == b'(' {
            self.pos += 1;
            while self.pos < self.data.len() && self.data[self.pos] != b')' {
                self.skip_sexp_internal()?;
            }
            if self.pos >= self.data.len() {
                return Err(Error::SexpParse("unclosed list".to_string()));
            }
            self.pos += 1;
        } else {
            let len = self.read_length()?;
            if self.pos >= self.data.len() || self.data[self.pos] != b':' {
                return Err(Error::SexpParse("expected ':'".to_string()));
            }
            self.pos += 1;
            // Advance past the atom body, rejecting a length that runs past the
            // end of the buffer instead of leaving `pos` in an invalid state.
            let end = self
                .pos
                .checked_add(len)
                .filter(|&e| e <= self.data.len())
                .ok_or_else(|| Error::SexpParse("atom length out of bounds".to_string()))?;
            self.pos = end;
        }
        Ok(())
    }

    fn read_length(&mut self) -> Result<usize> {
        let mut len = 0usize;
        let mut saw_digit = false;
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
            // Reject overflowing length prefixes rather than wrapping/panicking.
            len = len
                .checked_mul(10)
                .and_then(|v| v.checked_add((self.data[self.pos] - b'0') as usize))
                .ok_or_else(|| Error::SexpParse("length overflow".to_string()))?;
            saw_digit = true;
            self.pos += 1;
        }
        if !saw_digit {
            return Err(Error::SexpParse("expected length prefix".to_string()));
        }
        Ok(len)
    }

    pub fn expect_list_start(&mut self) -> Result<()> {
        if self.pos >= self.data.len() || self.data[self.pos] != b'(' {
            return Err(Error::SexpParse("expected '('".to_string()));
        }
        self.pos += 1;
        Ok(())
    }

    pub fn expect_list_end(&mut self) -> Result<()> {
        if self.pos >= self.data.len() || self.data[self.pos] != b')' {
            return Err(Error::SexpParse("expected ')'".to_string()));
        }
        self.pos += 1;
        Ok(())
    }

    pub fn read_atom(&mut self) -> Result<&'a [u8]> {
        let len = self.read_length()?;
        if self.pos >= self.data.len() || self.data[self.pos] != b':' {
            return Err(Error::SexpParse("expected ':'".to_string()));
        }
        self.pos += 1;
        let end = self
            .pos
            .checked_add(len)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| Error::SexpParse("atom length out of bounds".to_string()))?;
        let atom = &self.data[self.pos..end];
        self.pos = end;
        Ok(atom)
    }

    pub fn peek_is_list(&self) -> bool {
        self.pos < self.data.len() && self.data[self.pos] == b'('
    }

    pub fn peek_is_list_end(&self) -> bool {
        self.pos < self.data.len() && self.data[self.pos] == b')'
    }

    pub fn find_named_in_current_list(&mut self, name: &[u8]) -> Result<Option<usize>> {
        while !self.peek_is_list_end() {
            let item_start = self.pos;
            if self.peek_is_list() {
                self.expect_list_start()?;
                if !self.peek_is_list_end() && !self.peek_is_list() {
                    let atom = self.read_atom()?;
                    if atom == name {
                        self.pos = item_start;
                        return Ok(Some(item_start));
                    }
                }
                while !self.peek_is_list_end() {
                    self.skip_sexp_internal()?;
                }
                self.expect_list_end()?;
            } else {
                self.skip_sexp_internal()?;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let sexp = parse_gpg_sexp("(foo bar)").unwrap();
        let canon = sexp.to_canonical();
        assert_eq!(canon, b"(3:foo3:bar)");
    }

    #[test]
    fn test_parse_hex() {
        let sexp = parse_gpg_sexp("(data #CAFE#)").unwrap();
        let canon = sexp.to_canonical();
        assert_eq!(canon, b"(4:data2:\xca\xfe)");
    }

    #[test]
    fn test_parse_quoted() {
        let sexp = parse_gpg_sexp("(count \"12345\")").unwrap();
        let canon = sexp.to_canonical();
        assert_eq!(canon, b"(5:count5:12345)");
    }

    #[test]
    fn canonical_roundtrip_and_padding() {
        let canon = b"(3:foo(1:q3:\x40\x01\x02)5:bar.z)";
        let node = parse_canonical(canon).unwrap();
        assert_eq!(node.to_canonical(), canon);
        assert_eq!(node.name(), Some(&b"foo"[..]));
        let mut padded = canon.to_vec();
        padded.extend_from_slice(&[0; 5]);
        assert_eq!(canonical_len(&padded).unwrap(), canon.len());
        assert!(parse_canonical(&padded).is_err());
    }

    #[test]
    fn advanced_render_parses_back_to_same_canonical() {
        let canon = b"(21:protected-private-key(3:ecc(5:curve10:NIST P-256)(5:flags5:eddsa)(1:q3:\x40\xff\x00)(12:protected-at15:20261107T052202)))";
        let node = parse_canonical(canon).unwrap();
        let text = render_advanced(&node);
        assert!(text.contains("(curve \"NIST P-256\")"), "{text}");
        assert!(
            text.contains("(protected-at \"20261107T052202\")"),
            "{text}"
        );
        assert_eq!(parse_gpg_sexp(&text).unwrap().to_canonical(), canon);
    }

    #[test]
    fn advanced_form_accepts_length_prefixed_atoms() {
        let node = parse_gpg_sexp("(genkey(ecc(curve 10:NIST P-256)(flags nocomp)))").unwrap();
        assert_eq!(
            node.to_canonical(),
            b"(6:genkey(3:ecc(5:curve10:NIST P-256)(5:flags6:nocomp)))"
        );
        let rsa = parse_gpg_sexp("(genkey(rsa(nbits 4:2048)))").unwrap();
        assert_eq!(rsa.to_canonical(), b"(6:genkey(3:rsa(5:nbits4:2048)))");
    }

    #[test]
    fn test_canonical_parser() {
        let canon = b"(3:foo(3:bar5:hello))";
        let mut parser = CanonicalParser::new(canon);
        parser.expect_list_start().unwrap();
        let atom = parser.read_atom().unwrap();
        assert_eq!(atom, b"foo");
        parser.expect_list_start().unwrap();
        let atom = parser.read_atom().unwrap();
        assert_eq!(atom, b"bar");
        let atom = parser.read_atom().unwrap();
        assert_eq!(atom, b"hello");
    }

    #[test]
    fn read_atom_rejects_length_past_end() {
        // Claims a 99-byte atom but only 3 bytes follow the colon.
        let mut parser = CanonicalParser::new(b"99:abc");
        assert!(parser.read_atom().is_err());
    }

    #[test]
    fn read_atom_rejects_overflowing_length() {
        // Length prefix overflows usize; must error, not wrap or panic.
        let mut parser = CanonicalParser::new(b"99999999999999999999999999:x");
        assert!(parser.read_atom().is_err());
    }

    #[test]
    fn read_atom_rejects_missing_colon() {
        let mut parser = CanonicalParser::new(b"3abc");
        assert!(parser.read_atom().is_err());
    }

    #[test]
    fn read_atom_rejects_missing_length() {
        let mut parser = CanonicalParser::new(b":abc");
        assert!(parser.read_atom().is_err());
    }

    #[test]
    fn read_atom_length_at_exact_end_truncated() {
        // "5:ab" — declares 5 bytes, only 2 present.
        let mut parser = CanonicalParser::new(b"5:ab");
        assert!(parser.read_atom().is_err());
    }

    #[test]
    fn skip_sexp_rejects_truncated_atom() {
        // Inside a list, an atom claims more bytes than remain.
        let mut parser = CanonicalParser::new(b"(10:ab)");
        parser.expect_list_start().unwrap();
        assert!(parser.skip_sexp().is_err());
    }

    #[test]
    fn skip_sexp_rejects_unclosed_list() {
        let mut parser = CanonicalParser::new(b"(3:foo");
        assert!(parser.skip_sexp().is_err());
    }

    #[test]
    fn extract_params_does_not_panic_on_garbage() {
        // Fuzz-style: a pile of malformed canonical inputs must all return
        // Err rather than panic.
        let garbage: &[&[u8]] = &[
            b"(",
            b")",
            b"(((",
            b"(99999:",
            b"(0:",
            b"(3:ab",
            b"(2:ab3:cd",
            b"\xff\xff\xff",
            b"(1:a(1:b",
        ];
        for g in garbage {
            let mut parser = CanonicalParser::new(g);
            // Drive it the way extract_canonical_params would; any Err is fine,
            // a panic would fail the test.
            let _ = parser.expect_list_start();
            let _ = parser.read_atom();
            let _ = parser.skip_sexp();
        }
    }
}
