//! SCIM filter parser (RFC 7644 §3.4.2.2).
//!
//! Supports a practical subset: attribute eq/co/sw/pr/gt/ge/lt/le value,
//! logical and/or/not, and grouping. For complex filters, falls back to
//! server-side filtering.

use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("Unexpected end of input")]
    UnexpectedEof,
    #[error("Unexpected character: {0}")]
    UnexpectedChar(char),
    #[error("Expected attribute name")]
    ExpectedAttribute,
    #[error("Expected operator")]
    ExpectedOperator,
    #[error("Expected value")]
    ExpectedValue,
    #[error("Unterminated string")]
    UnterminatedString,
    #[error("Invalid filter: {0}")]
    Invalid(String),
}

/// SCIM comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComparisonOp {
    Eq,   // equals
    Ne,   // not equals
    Co,   // contains
    Sw,   // starts with
    Ew,   // ends with
    Pr,   // present
    Gt,   // greater than
    Ge,   // greater than or equal
    Lt,   // less than
    Le,   // less than or equal
}

impl ComparisonOp {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "co" => Some(Self::Co),
            "sw" => Some(Self::Sw),
            "ew" => Some(Self::Ew),
            "pr" => Some(Self::Pr),
            "gt" => Some(Self::Gt),
            "ge" => Some(Self::Ge),
            "lt" => Some(Self::Lt),
            "le" => Some(Self::Le),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Co => "co",
            Self::Sw => "sw",
            Self::Ew => "ew",
            Self::Pr => "pr",
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

/// Filter value (string, number, boolean).
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Bool(bool),
}

impl FilterValue {
    pub fn to_query_string(&self) -> String {
        match self {
            Self::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            Self::Number(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
        }
    }
}

/// SCIM filter expression (simplified AST).
#[derive(Debug, Clone, PartialEq)]
pub enum ScimFilter {
    /// Attribute comparison: attr operator value
    Comparison {
        attribute: String,
        operator: ComparisonOp,
        value: FilterValue,
    },
    /// Logical AND
    And(Box<ScimFilter>, Box<ScimFilter>),
    /// Logical OR
    Or(Box<ScimFilter>, Box<ScimFilter>),
    /// Logical NOT
    Not(Box<ScimFilter>),
}

impl ScimFilter {
    /// Convert filter to SCIM query string.
    pub fn to_query_string(&self) -> String {
        match self {
            Self::Comparison { attribute, operator, value } => {
                format!("{} {} {}", attribute, operator.as_str(), value.to_query_string())
            }
            Self::And(lhs, rhs) => format!("{} and {}", lhs.to_query_string(), rhs.to_query_string()),
            Self::Or(lhs, rhs) => format!("{} or {}", lhs.to_query_string(), rhs.to_query_string()),
            Self::Not(inner) => format!("not ({})", inner.to_query_string()),
        }
    }
}

/// Parse a SCIM filter string into an AST.
pub fn parse_filter(input: &str) -> Result<ScimFilter, FilterError> {
    let mut parser = FilterParser::new(input);
    parser.parse()
}

struct FilterParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> FilterParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input: input.trim(), pos: 0 }
    }

    fn parse(&mut self) -> Result<ScimFilter, FilterError> {
        self.skip_whitespace();
        let expr = self.parse_or()?;
        self.skip_whitespace();
        if self.pos < self.input.len() {
            return Err(FilterError::UnexpectedChar(self.input.chars().nth(self.pos).unwrap()));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<ScimFilter, FilterError> {
        let mut lhs = self.parse_and()?;
        self.skip_whitespace();
        while self.consume_keyword("or") {
            self.skip_whitespace();
            let rhs = self.parse_and()?;
            lhs = ScimFilter::And(Box::new(lhs), Box::new(rhs));
            self.skip_whitespace();
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<ScimFilter, FilterError> {
        let mut lhs = self.parse_not()?;
        self.skip_whitespace();
        while self.consume_keyword("and") {
            self.skip_whitespace();
            let rhs = self.parse_not()?;
            lhs = ScimFilter::And(Box::new(lhs), Box::new(rhs));
            self.skip_whitespace();
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<ScimFilter, FilterError> {
        self.skip_whitespace();
        if self.consume_keyword("not") {
            self.skip_whitespace();
            if self.consume_char('(') {
                let inner = self.parse_or()?;
                self.skip_whitespace();
                self.expect_char(')')?;
                Ok(ScimFilter::Not(Box::new(inner)))
            } else {
                let inner = self.parse_not()?;
                Ok(ScimFilter::Not(Box::new(inner)))
            }
        } else if self.consume_char('(') {
            let inner = self.parse_or()?;
            self.skip_whitespace();
            self.expect_char(')')?;
            Ok(inner)
        } else {
            self.parse_comparison()
        }
    }

    fn parse_comparison(&mut self) -> Result<ScimFilter, FilterError> {
        self.skip_whitespace();
        let attribute = self.parse_attribute()?;
        self.skip_whitespace();
        let operator = self.parse_operator()?;
        self.skip_whitespace();
        let value = self.parse_value()?;
        Ok(ScimFilter::Comparison { attribute, operator, value })
    }

    fn parse_attribute(&mut self) -> Result<String, FilterError> {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input.chars().nth(self.pos).unwrap();
            if c.is_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '-' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(FilterError::ExpectedAttribute);
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_operator(&mut self) -> Result<ComparisonOp, FilterError> {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input.chars().nth(self.pos).unwrap();
            if c.is_alphabetic() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(FilterError::ExpectedOperator);
        }
        let op_str = &self.input[start..self.pos];
        ComparisonOp::from_str(op_str).ok_or_else(|| FilterError::Invalid(format!("Unknown operator: {}", op_str)))
    }

    fn parse_value(&mut self) -> Result<FilterValue, FilterError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return Err(FilterError::ExpectedValue);
        }
        let c = self.input.chars().nth(self.pos).unwrap();
        if c == '"' {
            self.parse_string()
        } else if c == 't' || c == 'f' {
            self.parse_bool()
        } else if c.is_ascii_digit() || c == '-' {
            self.parse_number()
        } else {
            Err(FilterError::ExpectedValue)
        }
    }

    fn parse_string(&mut self) -> Result<FilterValue, FilterError> {
        self.pos += 1; // skip opening quote
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input.chars().nth(self.pos).unwrap();
            if c == '"' {
                let s = self.input[start..self.pos].to_string();
                self.pos += 1; // skip closing quote
                return Ok(FilterValue::String(s));
            }
            self.pos += c.len_utf8();
        }
        Err(FilterError::UnterminatedString)
    }

    fn parse_bool(&mut self) -> Result<FilterValue, FilterError> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(FilterValue::Bool(true))
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(FilterValue::Bool(false))
        } else {
            Err(FilterError::Invalid("Expected boolean".to_string()))
        }
    }

    fn parse_number(&mut self) -> Result<FilterValue, FilterError> {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input.chars().nth(self.pos).unwrap();
            if c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        let s = &self.input[start..self.pos];
        s.parse::<f64>().map(FilterValue::Number).map_err(|_| FilterError::Invalid(format!("Invalid number: {}", s)))
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let c = self.input.chars().nth(self.pos).unwrap();
            if c.is_whitespace() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.pos < self.input.len() && self.input.chars().nth(self.pos).unwrap() == expected {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), FilterError> {
        if self.consume_char(expected) {
            Ok(())
        } else {
            Err(FilterError::UnexpectedChar(self.input.chars().nth(self.pos).unwrap_or('\0')))
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let start = self.pos;
        if self.input[start..].starts_with(keyword) {
            // Ensure it's a word boundary
            let end = start + keyword.len();
            if end <= self.input.len() {
                let next_char = self.input.chars().nth(end);
                if next_char.map_or(true, |c| c.is_whitespace() || c == '(' || c == ')') {
                    self.pos = end;
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_eq() {
        let filter = parse_filter("userName eq \"john\"").unwrap();
        assert_eq!(filter.to_query_string(), "userName eq \"john\"");
    }

    #[test]
    fn test_contains() {
        let filter = parse_filter("displayName co \"eng\"").unwrap();
        assert_eq!(filter.to_query_string(), "displayName co \"eng\"");
    }

    #[test]
    fn test_and() {
        let filter = parse_filter("userName eq \"john\" and active eq true").unwrap();
        assert!(filter.to_query_string().contains("and"));
    }

    #[test]
    fn test_or() {
        let filter = parse_filter("userName eq \"john\" or userName eq \"jane\"").unwrap();
        assert!(filter.to_query_string().contains("or"));
    }

    #[test]
    fn test_not() {
        let filter = parse_filter("not (userName eq \"john\")").unwrap();
        assert!(filter.to_query_string().starts_with("not"));
    }

    #[test]
    fn test_grouping() {
        let filter = parse_filter("(userName eq \"john\" or userName eq \"jane\") and active eq true").unwrap();
        let s = filter.to_query_string();
        assert!(s.contains("and"));
        assert!(s.contains("or"));
    }

    #[test]
    fn test_present() {
        let filter = parse_filter("emails pr").unwrap();
        assert_eq!(filter.to_query_string(), "emails pr");
    }

    #[test]
    fn test_numeric_comparison() {
        let filter = parse_filter("employeeNumber gt 1000").unwrap();
        assert_eq!(filter.to_query_string(), "employeeNumber gt 1000");
    }
}