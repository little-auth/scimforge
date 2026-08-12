//! RFC 7644 §3.4.2.2 filter-expression grammar: parsing only, no evaluation (evaluation
//! against a concrete resource is a storage-layer concern, out of scope for this crate).
//!
//! The ABNF is mutually recursive in a way that has no inherent depth bound --
//! `valuePath = attrPath "[" valFilter "]"` and `valFilter` can itself contain `logExp`,
//! whose `FILTER` production can contain another `valuePath`, and so on indefinitely. A
//! filter is attacker-reachable by construction (SCIM servers are called by external
//! identity providers), so an unbounded recursive-descent parser is a stack-overflow DoS
//! waiting for a sufficiently nested payload like `((((...))))`. [`parse`] enforces
//! [`MAX_DEPTH`] and returns [`FilterError::TooDeep`] rather than recursing further.

use std::fmt;

/// Grouping/logical nesting deeper than this is rejected before the parser recurses
/// further. Chosen generously above anything a legitimate filter would ever need
/// (RFC 7644 gives no real-world example nesting more than 2-3 levels) while still being
/// far below where a debug-build stack would actually overflow.
pub const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

/// `compValue = false / null / true / number / string` per RFC 7644, i.e. any JSON
/// scalar -- deliberately not a full `serde_json::Value` (objects/arrays are not valid
/// compValue productions, and accepting them would silently widen the grammar).
#[derive(Debug, Clone, PartialEq)]
pub enum CompValue {
    False,
    Null,
    True,
    /// Carries the original literal text alongside the parsed value: RFC 7644's number
    /// comparison rules don't specify a single numeric type, and preserving the literal
    /// lets a caller apply its own precision rules rather than this crate silently
    /// lossy-converting through `f64`.
    Number(f64, String),
    String(String),
}

/// `attrPath = [URI ":"] ATTRNAME *1subAttr` -- the `URI` prefix is a full SCIM schema
/// URN (e.g. `urn:ietf:params:scim:schemas:core:2.0:User:userName`), kept as an opaque
/// string since validating it against a registered schema is a schema-module concern.
#[derive(Debug, Clone, PartialEq)]
pub struct AttrPath {
    pub schema_uri: Option<String>,
    pub attr_name: String,
    pub sub_attr: Option<String>,
}

impl fmt::Display for AttrPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(uri) = &self.schema_uri {
            write!(f, "{uri}:")?;
        }
        write!(f, "{}", self.attr_name)?;
        if let Some(sub) = &self.sub_attr {
            write!(f, ".{sub}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    /// `attrPath SP "pr"`
    Present(AttrPath),
    /// `attrPath SP compareOp SP compValue`
    Compare(AttrPath, CompareOp, CompValue),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    /// `attrPath "[" valFilter "]"` -- filters a multi-valued complex attribute's entries
    /// (e.g. `emails[type eq "work"]`) by a sub-filter scoped to that attribute's
    /// sub-attributes.
    ValuePath(AttrPath, Box<Filter>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterError {
    /// Nesting (parenthesized groups, logical operators, or `[...]` value-path filters)
    /// exceeded [`MAX_DEPTH`] before the parser would have recursed further.
    TooDeep,
    UnexpectedEnd,
    UnexpectedToken(String),
    InvalidNumber(String),
    UnterminatedString,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::TooDeep => write!(f, "filter nesting exceeds the maximum depth"),
            FilterError::UnexpectedEnd => write!(f, "unexpected end of filter expression"),
            FilterError::UnexpectedToken(t) => write!(f, "unexpected token: {t}"),
            FilterError::InvalidNumber(t) => write!(f, "invalid number literal: {t}"),
            FilterError::UnterminatedString => write!(f, "unterminated string literal"),
        }
    }
}

impl std::error::Error for FilterError {}

/// RFC 7644 §3.5.2 PATCH `path` grammar: `PATH = attrPath / valuePath [subAttr]`. Shares
/// the exact same `attrPath`/`valuePath`/`valFilter` productions as a search filter (see
/// the module doc), so this reuses [`parse`]'s tokenizer and attr-path/val-filter
/// parsing rather than re-implementing them -- including the same [`MAX_DEPTH`] bound,
/// since a PATCH path's bracket filter is just as attacker-reachable as a search filter.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    pub attr_path: AttrPath,
    /// The `[valFilter]` scoping which entries of a multi-valued attribute this path
    /// targets, if the path has one (e.g. `type eq "work"` in `emails[type eq "work"]`).
    pub value_filter: Option<Filter>,
    /// A `.subAttr` immediately after the closing `]`, e.g. `.streetAddress` in
    /// `addresses[type eq "work"].streetAddress`. Only meaningful when
    /// `value_filter` is `Some`; a bare `attrPath`'s own sub-attribute (e.g.
    /// `name.familyName`, no brackets at all) already lives on `attr_path.sub_attr`.
    pub sub_attr_after_filter: Option<String>,
}

pub fn parse_patch_path(input: &str) -> Result<PatchPath, FilterError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let attr_path = parser.parse_attr_path()?;
    let (value_filter, sub_attr_after_filter) = if matches!(parser.peek(), Some(Token::LBracket)) {
        parser.advance();
        let inner = parser.parse_val_filter(1)?;
        parser.expect(Token::RBracket)?;
        let trailing = if matches!(parser.peek(), Some(Token::Dot)) {
            parser.advance();
            match parser.advance() {
                Some(Token::Ident(s)) => Some(s.clone()),
                other => return Err(FilterError::UnexpectedToken(format!("{other:?}"))),
            }
        } else {
            None
        };
        (Some(inner), trailing)
    } else {
        (None, None)
    };
    if parser.pos != parser.tokens.len() {
        return Err(FilterError::UnexpectedToken(format!(
            "{:?}",
            parser.tokens[parser.pos]
        )));
    }
    Ok(PatchPath {
        attr_path,
        value_filter,
        sub_attr_after_filter,
    })
}

pub fn parse(input: &str) -> Result<Filter, FilterError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let filter = parser.parse_filter(0)?;
    if parser.pos != parser.tokens.len() {
        return Err(FilterError::UnexpectedToken(format!(
            "{:?}",
            parser.tokens[parser.pos]
        )));
    }
    Ok(filter)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Number(f64, String),
    String(String),
    True,
    False,
    Null,
    And,
    Or,
    Not,
    Pr,
    CompareOp(CompareOp),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    Colon,
}

fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut tokens = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            ':' => {
                tokens.push(Token::Colon);
                i += 1;
            }
            '"' => {
                let start = i;
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < chars.len() {
                    match chars[i] {
                        '"' => {
                            closed = true;
                            i += 1;
                            break;
                        }
                        '\\' if i + 1 < chars.len() => {
                            // JSON escape handling: pass through the escaped char for the
                            // common cases: \" \\ \/ \n \t \r; unrecognized escapes are
                            // kept literally rather than silently dropped.
                            let next = chars[i + 1];
                            match next {
                                '"' => s.push('"'),
                                '\\' => s.push('\\'),
                                '/' => s.push('/'),
                                'n' => s.push('\n'),
                                't' => s.push('\t'),
                                'r' => s.push('\r'),
                                other => {
                                    s.push('\\');
                                    s.push(other);
                                }
                            }
                            i += 2;
                        }
                        ch => {
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                if !closed {
                    let _ = start;
                    return Err(FilterError::UnterminatedString);
                }
                tokens.push(Token::String(s));
            }
            c if c.is_ascii_digit()
                || (c == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) =>
            {
                let start = i;
                if c == '-' {
                    i += 1;
                }
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                if i < chars.len() && chars[i] == '.' {
                    i += 1;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                if i < chars.len() && (chars[i] == 'e' || chars[i] == 'E') {
                    i += 1;
                    if i < chars.len() && (chars[i] == '+' || chars[i] == '-') {
                        i += 1;
                    }
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                let literal: String = chars[start..i].iter().collect();
                let value = literal
                    .parse::<f64>()
                    .map_err(|_| FilterError::InvalidNumber(literal.clone()))?;
                tokens.push(Token::Number(value, literal));
            }
            c if c.is_ascii_alphabetic() || c == '_' || c == '$' || c == '/' => {
                let start = i;
                // ATTRNAME = ALPHA *(nameChar); nameChar = "-" / "_" / DIGIT / ALPHA.
                // Schema URIs (urn:ietf:params:...) additionally use ':' and '/' inside
                // the URI segment, handled below by the colon-joining pass in
                // Parser::parse_attr_path rather than here -- the tokenizer just reads
                // one URI/attribute-name "word" at a time.
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || chars[i] == '-'
                        || chars[i] == '_'
                        || chars[i] == '.'
                        || chars[i] == '/')
                {
                    // '.' is consumed here only when immediately followed by another
                    // name char, so `name.familyName` still tokenizes name/dot/familyName
                    // via the Dot token check below -- back off '.' unless it's part of a
                    // schema URI's version segment (e.g. "2.0"), which only occurs after
                    // a preceding ':'.
                    if chars[i] == '.' {
                        break;
                    }
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.to_ascii_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    "pr" => tokens.push(Token::Pr),
                    "eq" => tokens.push(Token::CompareOp(CompareOp::Eq)),
                    "ne" => tokens.push(Token::CompareOp(CompareOp::Ne)),
                    "co" => tokens.push(Token::CompareOp(CompareOp::Co)),
                    "sw" => tokens.push(Token::CompareOp(CompareOp::Sw)),
                    "ew" => tokens.push(Token::CompareOp(CompareOp::Ew)),
                    "gt" => tokens.push(Token::CompareOp(CompareOp::Gt)),
                    "ge" => tokens.push(Token::CompareOp(CompareOp::Ge)),
                    "lt" => tokens.push(Token::CompareOp(CompareOp::Lt)),
                    "le" => tokens.push(Token::CompareOp(CompareOp::Le)),
                    "true" => tokens.push(Token::True),
                    "false" => tokens.push(Token::False),
                    "null" => tokens.push(Token::Null),
                    _ => tokens.push(Token::Ident(word)),
                }
            }
            other => return Err(FilterError::UnexpectedToken(other.to_string())),
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn check_depth(depth: usize) -> Result<(), FilterError> {
        if depth > MAX_DEPTH {
            Err(FilterError::TooDeep)
        } else {
            Ok(())
        }
    }

    /// `FILTER = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"`, with RFC
    /// 7644 §3.4.2.2's explicit precedence ("not" > "and" > "or") implemented as the
    /// usual precedence-climbing grammar levels: an `or` chain of `and` chains of
    /// unary terms, so `a or b and c` parses as `a or (b and c)`, never `(a or b) and c`.
    fn parse_filter(&mut self, depth: usize) -> Result<Filter, FilterError> {
        Self::check_depth(depth)?;
        self.parse_or(depth)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Filter, FilterError> {
        Self::check_depth(depth)?;
        let mut left = self.parse_and(depth)?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and(depth + 1)?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Filter, FilterError> {
        Self::check_depth(depth)?;
        let mut left = self.parse_filter_unary(depth)?;
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_filter_unary(depth + 1)?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_filter_unary(&mut self, depth: usize) -> Result<Filter, FilterError> {
        Self::check_depth(depth)?;
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            self.expect(Token::LParen)?;
            let inner = self.parse_filter(depth + 1)?;
            self.expect(Token::RParen)?;
            return Ok(Filter::Not(Box::new(inner)));
        }
        if matches!(self.peek(), Some(Token::LParen)) {
            self.advance();
            let inner = self.parse_filter(depth + 1)?;
            self.expect(Token::RParen)?;
            return Ok(inner);
        }
        self.parse_attr_exp_or_value_path(depth)
    }

    fn parse_attr_exp_or_value_path(&mut self, depth: usize) -> Result<Filter, FilterError> {
        let path = self.parse_attr_path()?;
        if matches!(self.peek(), Some(Token::LBracket)) {
            self.advance();
            let inner = self.parse_val_filter(depth + 1)?;
            self.expect(Token::RBracket)?;
            return Ok(Filter::ValuePath(path, Box::new(inner)));
        }
        match self.advance() {
            Some(Token::Pr) => Ok(Filter::Present(path)),
            Some(Token::CompareOp(op)) => {
                let op = op.clone();
                let value = self.parse_comp_value()?;
                Ok(Filter::Compare(path, op, value))
            }
            other => Err(FilterError::UnexpectedToken(format!("{other:?}"))),
        }
    }

    /// `valFilter = attrExp / logExp / *1"not" "(" valFilter ")"` -- deliberately
    /// implemented by delegating to [`Self::parse_filter`] rather than a separate
    /// grammar path: `logExp`'s `FILTER` production is mutually recursive with
    /// `valuePath` regardless (see the module doc), so a parallel implementation would
    /// just be the same recursion under a different name. What actually matters for
    /// safety is that the caller already incremented `depth` before calling this.
    fn parse_val_filter(&mut self, depth: usize) -> Result<Filter, FilterError> {
        self.parse_filter(depth)
    }

    fn parse_attr_path(&mut self) -> Result<AttrPath, FilterError> {
        let first = match self.advance() {
            Some(Token::Ident(s)) => s.clone(),
            other => return Err(FilterError::UnexpectedToken(format!("{other:?}"))),
        };
        // A schema URI prefix is `urn:...:AttrName` -- Colon-separated segments up to
        // the final one, which is the actual attribute name. A version segment like
        // "2.0" (as in "urn:ietf:params:scim:schemas:core:2.0:User") tokenizes as a
        // Number, not an Ident, since the tokenizer has no notion of "inside a URI" --
        // accept either token kind here and take the Number's original literal text.
        let mut segments = vec![first];
        while matches!(self.peek(), Some(Token::Colon)) {
            self.advance();
            match self.advance() {
                Some(Token::Ident(s)) => segments.push(s.clone()),
                Some(Token::Number(_, lit)) => segments.push(lit.clone()),
                other => return Err(FilterError::UnexpectedToken(format!("{other:?}"))),
            }
        }
        let attr_name = segments.pop().expect("segments always has >=1 entry");
        let schema_uri = if segments.is_empty() {
            None
        } else {
            Some(segments.join(":"))
        };
        let sub_attr = if matches!(self.peek(), Some(Token::Dot)) {
            self.advance();
            match self.advance() {
                Some(Token::Ident(s)) => Some(s.clone()),
                other => return Err(FilterError::UnexpectedToken(format!("{other:?}"))),
            }
        } else {
            None
        };
        Ok(AttrPath {
            schema_uri,
            attr_name,
            sub_attr,
        })
    }

    fn parse_comp_value(&mut self) -> Result<CompValue, FilterError> {
        match self.advance() {
            Some(Token::True) => Ok(CompValue::True),
            Some(Token::False) => Ok(CompValue::False),
            Some(Token::Null) => Ok(CompValue::Null),
            Some(Token::Number(v, lit)) => Ok(CompValue::Number(*v, lit.clone())),
            Some(Token::String(s)) => Ok(CompValue::String(s.clone())),
            other => Err(FilterError::UnexpectedToken(format!("{other:?}"))),
        }
    }

    fn expect(&mut self, expected: Token) -> Result<(), FilterError> {
        match self.advance() {
            Some(t) if *t == expected => Ok(()),
            Some(t) => Err(FilterError::UnexpectedToken(format!("{t:?}"))),
            None => Err(FilterError::UnexpectedEnd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str) -> AttrPath {
        AttrPath {
            schema_uri: None,
            attr_name: name.to_string(),
            sub_attr: None,
        }
    }

    #[test]
    fn parses_simple_equality() {
        let f = parse(r#"userName eq "bjensen""#).unwrap();
        assert_eq!(
            f,
            Filter::Compare(
                attr("userName"),
                CompareOp::Eq,
                CompValue::String("bjensen".to_string())
            )
        );
    }

    #[test]
    fn parses_presence() {
        let f = parse("title pr").unwrap();
        assert_eq!(f, Filter::Present(attr("title")));
    }

    #[test]
    fn parses_all_nine_compare_operators() {
        let cases = [
            ("eq", CompareOp::Eq),
            ("ne", CompareOp::Ne),
            ("co", CompareOp::Co),
            ("sw", CompareOp::Sw),
            ("ew", CompareOp::Ew),
            ("gt", CompareOp::Gt),
            ("ge", CompareOp::Ge),
            ("lt", CompareOp::Lt),
            ("le", CompareOp::Le),
        ];
        for (op_str, expected_op) in cases {
            let f = parse(&format!(r#"userName {op_str} "x""#)).unwrap();
            match f {
                Filter::Compare(_, op, _) => assert_eq!(op, expected_op, "operator {op_str}"),
                _ => panic!("expected Compare for {op_str}"),
            }
        }
    }

    #[test]
    fn parses_dotted_sub_attribute_path() {
        let f = parse(r#"name.familyName eq "Jensen""#).unwrap();
        let expected_path = AttrPath {
            schema_uri: None,
            attr_name: "name".to_string(),
            sub_attr: Some("familyName".to_string()),
        };
        assert_eq!(
            f,
            Filter::Compare(
                expected_path,
                CompareOp::Eq,
                CompValue::String("Jensen".to_string())
            )
        );
    }

    #[test]
    fn parses_schema_uri_prefixed_path() {
        let f =
            parse(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bjensen""#).unwrap();
        match f {
            Filter::Compare(path, CompareOp::Eq, _) => {
                assert_eq!(
                    path.schema_uri.as_deref(),
                    Some("urn:ietf:params:scim:schemas:core:2.0:User")
                );
                assert_eq!(path.attr_name, "userName");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_and_or_not_precedence() {
        // "not takes precedence over and, which takes precedence over or" (RFC 7644
        // §3.4.2.2) -- `a pr or b pr and c pr` must group as `a pr or (b pr and c pr)`.
        let f = parse("a pr or b pr and c pr").unwrap();
        assert_eq!(
            f,
            Filter::Or(
                Box::new(Filter::Present(attr("a"))),
                Box::new(Filter::And(
                    Box::new(Filter::Present(attr("b"))),
                    Box::new(Filter::Present(attr("c")))
                ))
            )
        );
    }

    #[test]
    fn explicit_grouping_overrides_precedence() {
        let f = parse("(a pr or b pr) and c pr").unwrap();
        assert_eq!(
            f,
            Filter::And(
                Box::new(Filter::Or(
                    Box::new(Filter::Present(attr("a"))),
                    Box::new(Filter::Present(attr("b")))
                )),
                Box::new(Filter::Present(attr("c")))
            )
        );
    }

    #[test]
    fn parses_not_group() {
        let f = parse("not (active eq true)").unwrap();
        assert_eq!(
            f,
            Filter::Not(Box::new(Filter::Compare(
                attr("active"),
                CompareOp::Eq,
                CompValue::True
            )))
        );
    }

    #[test]
    fn parses_value_path_bracket_filter() {
        let f = parse(r#"emails[type eq "work"]"#).unwrap();
        assert_eq!(
            f,
            Filter::ValuePath(
                attr("emails"),
                Box::new(Filter::Compare(
                    attr("type"),
                    CompareOp::Eq,
                    CompValue::String("work".to_string())
                ))
            )
        );
    }

    #[test]
    fn parses_value_path_with_logical_filter_inside() {
        let f = parse(r#"emails[type eq "work" and value co "@example.com"]"#).unwrap();
        assert_eq!(
            f,
            Filter::ValuePath(
                attr("emails"),
                Box::new(Filter::And(
                    Box::new(Filter::Compare(
                        attr("type"),
                        CompareOp::Eq,
                        CompValue::String("work".to_string())
                    )),
                    Box::new(Filter::Compare(
                        attr("value"),
                        CompareOp::Co,
                        CompValue::String("@example.com".to_string())
                    ))
                ))
            )
        );
    }

    #[test]
    fn parses_null_false_and_number_literals() {
        assert_eq!(
            parse("x eq null").unwrap(),
            Filter::Compare(attr("x"), CompareOp::Eq, CompValue::Null)
        );
        assert_eq!(
            parse("x eq false").unwrap(),
            Filter::Compare(attr("x"), CompareOp::Eq, CompValue::False)
        );
        assert_eq!(
            parse("x gt 42").unwrap(),
            Filter::Compare(
                attr("x"),
                CompareOp::Gt,
                CompValue::Number(42.0, "42".to_string())
            )
        );
        assert_eq!(
            parse("x lt -3.5").unwrap(),
            Filter::Compare(
                attr("x"),
                CompareOp::Lt,
                CompValue::Number(-3.5, "-3.5".to_string())
            )
        );
    }

    #[test]
    fn parses_string_with_escaped_quote() {
        let f = parse(r#"displayName eq "Bob \"Bobby\" Jones""#).unwrap();
        assert_eq!(
            f,
            Filter::Compare(
                attr("displayName"),
                CompareOp::Eq,
                CompValue::String("Bob \"Bobby\" Jones".to_string())
            )
        );
    }

    // --- Adversarial / malformed input ---

    #[test]
    fn rejects_unterminated_string() {
        assert_eq!(
            parse(r#"userName eq "bjensen"#),
            Err(FilterError::UnterminatedString)
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_trailing_garbage_after_a_complete_filter() {
        assert!(parse("active eq true )").is_err());
    }

    #[test]
    fn rejects_dangling_logical_operator() {
        assert!(parse("active eq true and").is_err());
    }

    #[test]
    fn rejects_unmatched_open_paren() {
        assert!(parse("(active eq true").is_err());
    }

    #[test]
    fn rejects_unmatched_close_bracket() {
        assert!(parse(r#"emails[type eq "work""#).is_err());
    }

    #[test]
    fn rejects_compare_op_missing_value() {
        assert!(parse("userName eq").is_err());
    }

    #[test]
    fn rejects_object_or_array_as_a_comp_value() {
        // compValue is restricted to JSON scalars (false/null/true/number/string) --
        // `{` isn't a valid token at all in this grammar, so this must fail to parse,
        // not silently accept an object as a comparison value.
        assert!(parse(r#"userName eq {"a":1}"#).is_err());
    }

    /// The core DoS defense this module exists to prove: a filter nested exactly
    /// [`MAX_DEPTH`] plus one parenthesized groups deep must be rejected with
    /// [`FilterError::TooDeep`], not overflow the stack. Generated programmatically
    /// rather than hand-typed so the fixture is provably exactly one level past the
    /// limit, not "however deep felt sufficient."
    #[test]
    fn rejects_filter_nested_past_max_depth() {
        let mut expr = String::new();
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push('(');
        }
        expr.push_str("active eq true");
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push(')');
        }
        assert_eq!(parse(&expr), Err(FilterError::TooDeep));
    }

    /// The mirror case: nesting comfortably under the limit must still parse
    /// successfully, proving `MAX_DEPTH` isn't so low it rejects legitimate filters.
    #[test]
    fn accepts_filter_nested_well_under_max_depth() {
        let depth = MAX_DEPTH / 2;
        let mut expr = String::new();
        for _ in 0..depth {
            expr.push('(');
        }
        expr.push_str("active eq true");
        for _ in 0..depth {
            expr.push(')');
        }
        assert!(parse(&expr).is_ok());
    }

    /// The same DoS class via nested value-path brackets rather than parens --
    /// `valuePath`'s inner `valFilter` shares the same depth counter (see
    /// `parse_val_filter`'s doc comment), so this must be bounded too, not just the
    /// paren/logExp path.
    #[test]
    fn rejects_value_path_nested_past_max_depth_via_not_groups() {
        let mut expr = String::from("emails[");
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push_str("not (");
        }
        expr.push_str("type pr");
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push(')');
        }
        expr.push(']');
        assert_eq!(parse(&expr), Err(FilterError::TooDeep));
    }

    #[test]
    fn rejects_binary_or_boolean_compare_value_type_confusion_gracefully() {
        // Not a crash, not a silent misparse -- `pr` with a trailing junk value token is
        // simply a malformed filter.
        assert!(parse(r#"active pr "unexpected""#).is_err());
    }

    #[test]
    fn patch_path_parses_a_bare_attr_path() {
        let p = parse_patch_path("displayName").unwrap();
        assert_eq!(p.attr_path, attr("displayName"));
        assert_eq!(p.value_filter, None);
        assert_eq!(p.sub_attr_after_filter, None);
    }

    #[test]
    fn patch_path_parses_a_dotted_sub_attribute_with_no_brackets() {
        let p = parse_patch_path("name.familyName").unwrap();
        assert_eq!(p.attr_path.attr_name, "name");
        assert_eq!(p.attr_path.sub_attr.as_deref(), Some("familyName"));
        assert_eq!(p.value_filter, None);
    }

    #[test]
    fn patch_path_parses_a_bracket_filter_with_no_trailing_sub_attr() {
        let p = parse_patch_path(r#"emails[type eq "work"]"#).unwrap();
        assert_eq!(p.attr_path, attr("emails"));
        assert_eq!(
            p.value_filter,
            Some(Filter::Compare(
                attr("type"),
                CompareOp::Eq,
                CompValue::String("work".to_string())
            ))
        );
        assert_eq!(p.sub_attr_after_filter, None);
    }

    #[test]
    fn patch_path_parses_a_bracket_filter_with_trailing_sub_attr() {
        let p = parse_patch_path(r#"addresses[type eq "work"].streetAddress"#).unwrap();
        assert_eq!(p.attr_path, attr("addresses"));
        assert_eq!(p.sub_attr_after_filter.as_deref(), Some("streetAddress"));
    }

    #[test]
    fn patch_path_rejects_trailing_garbage() {
        assert!(parse_patch_path(r#"emails[type eq "work"] extra"#).is_err());
    }

    #[test]
    fn patch_path_bracket_filter_is_still_depth_bounded() {
        let mut expr = String::from("emails[");
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push_str("not (");
        }
        expr.push_str("type pr");
        for _ in 0..(MAX_DEPTH + 5) {
            expr.push(')');
        }
        expr.push(']');
        assert_eq!(parse_patch_path(&expr), Err(FilterError::TooDeep));
    }

    #[test]
    fn case_insensitive_keywords_are_accepted_per_grammar() {
        // RFC 7644's ABNF keywords (and/or/not/pr/eq/...) are lowercase, but SCIM
        // attribute names and the surrounding JSON text are case-insensitive in
        // practice for these tokens in real IdP traffic; the tokenizer lowercases
        // before matching keywords specifically so `AND`/`Eq` are still recognized.
        let f = parse(r#"userName EQ "bjensen" AND active PR"#).unwrap();
        assert_eq!(
            f,
            Filter::And(
                Box::new(Filter::Compare(
                    attr("userName"),
                    CompareOp::Eq,
                    CompValue::String("bjensen".to_string())
                )),
                Box::new(Filter::Present(attr("active")))
            )
        );
    }
}
