//! Client-side HTTP `RateLimit` header handling per
//! `draft-ietf-httpapi-ratelimit-headers-12` and RFC 9651 Structured Field Values.
//!
//! Supported features:
//! - Parsing `RateLimit-Policy` (§2), `RateLimit` (§3), and `RateLimit-Partition` (§4)
//!   Structured Field Lists with Token or String bare items and case-insensitive policy
//!   matching (§2.1).
//! - Structured partition key construction and method-dimension filtering (§4.1, §4.2, §11.7).
//! - Request cost (`c`) estimation and pre-emptive request pacing (§3.1.4, §7).
//! - `Retry-After` precedence over `RateLimit` effective windows (§7) and bounded wait
//!   capping for DoS mitigation (§9.5.1).
//! - Ignoring rate-limit headers on cached responses with `Age > 0` (§8.4).
//! - Parsing RFC 9457 Problem Details bodies for `quota-exceeded`,
//!   `temporary-reduced-capacity`, and `abnormal-usage-detected` (§8).
//!
//! Trailer sections are never inspected because `reqwest::Response::headers()` exposes only
//! the response header section (§2, §3, §4).

use std::{
    borrow::{Borrow, Cow},
    collections::{HashMap, HashSet},
    fmt::{self, Write as _},
    hash::{Hash, Hasher},
    time::{Duration, Instant, SystemTime},
};

use data_encoding::{BASE64, BASE64_NOPAD};
use reqwest::{
    Method, Response, StatusCode,
    header::{AGE, CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use url::Url;

use crate::{Args, PermanentError, parse_decimal, parse_http_date, terminal_safe};

/// Maximum sleep duration honored from `RateLimit` `w` or `Retry-After` headers
/// (`draft-ietf-httpapi-ratelimit-headers-12` §9.5.1 `DoS` mitigation: ten minutes).
pub const MAX_RATELIMIT_WAIT_SECS: u64 = 600;

/// Maximum integer representable as an RFC 9651 Structured Field Integer (§3.3.1).
pub const SF_MAX_INTEGER: i64 = 999_999_999_999_999;

/// Minimum integer representable as an RFC 9651 Structured Field Integer (§3.3.1).
pub const SF_MIN_INTEGER: i64 = -999_999_999_999_999;

/// Unit Separator (`0x1F`) used to join dimension values in structured partition keys (§4.2).
pub const PARTITION_KEY_SEPARATOR: u8 = 0x1F;

/// HTTP header name for the `RateLimit` field (§3).
pub const RATELIMIT_HEADER: &str = "ratelimit";

/// HTTP header name for the `RateLimit-Policy` field (§2).
pub const RATELIMIT_POLICY_HEADER: &str = "ratelimit-policy";

/// HTTP header name for the `RateLimit-Partition` field (§4).
pub const RATELIMIT_PARTITION_HEADER: &str = "ratelimit-partition";

/// Maximum RFC 9457 Problem Details body size buffered from error responses.
const MAX_PROBLEM_BODY_BYTES: usize = 16 * 1024;

/// Maximum number of distinct origins tracked simultaneously in memory.
const MAX_TRACKED_ORIGINS: usize = 256;

/// Maximum number of distinct policies tracked per origin.
const MAX_POLICIES_PER_ORIGIN: usize = 64;

/// Maximum number of distinct partition keys tracked per policy.
const MAX_PARTITIONS_PER_POLICY: usize = 256;

/// Quota units registered in `draft-ietf-httpapi-ratelimit-headers-12` §2.1.2 and §11.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaUnit {
    /// Quota measured in number of HTTP requests (`requests` / `request`).
    Requests,
    /// Quota measured in number of content bytes (`content-bytes`).
    ContentBytes,
    /// Quota measured in number of concurrent requests (`concurrent-requests`).
    ConcurrentRequests,
    /// An extension quota unit not defined in the core specification.
    Other(String),
}

impl QuotaUnit {
    /// Parse a `qu` string parameter value into a [`QuotaUnit`].
    #[must_use]
    pub fn from_str_param(s: &str) -> Self {
        if s.eq_ignore_ascii_case("requests") || s.eq_ignore_ascii_case("request") {
            Self::Requests
        } else if s.eq_ignore_ascii_case("content-bytes") {
            Self::ContentBytes
        } else if s.eq_ignore_ascii_case("concurrent-requests") {
            Self::ConcurrentRequests
        } else {
            Self::Other(s.to_string())
        }
    }
}

impl fmt::Display for QuotaUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requests => f.write_str("requests"),
            Self::ContentBytes => f.write_str("content-bytes"),
            Self::ConcurrentRequests => f.write_str("concurrent-requests"),
            Self::Other(custom) => f.write_str(custom),
        }
    }
}

/// Parsed Quota Policy Item from `RateLimit-Policy` (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaPolicyItem {
    /// Policy identifier as advertised by the server (matched case-insensitively per §2.1).
    pub name: String,
    /// Allocated quota (`q` parameter, §2.1.1).
    pub quota: u64,
    /// Quota unit (`qu` parameter, defaults to [`QuotaUnit::Requests`], §2.1.2).
    pub unit: QuotaUnit,
    /// Optional positive time window in seconds (`w` parameter, §2.1.3).
    pub window: Option<u64>,
    /// Optional raw partition key bytes (`pk` parameter, §2.1.4).
    pub partition_key: Option<Vec<u8>>,
}

/// Parsed Service Limit Item from `RateLimit` (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLimitItem {
    /// Policy identifier as advertised by the server (matched case-insensitively per §2.1).
    pub name: String,
    /// Currently available quota (`a` parameter, §3.1.1).
    pub available_quota: u64,
    /// Optional effective window in seconds (`w` parameter, §3.1.2).
    pub effective_window: Option<u64>,
    /// Optional raw partition key bytes (`pk` parameter, §3.1.3).
    pub partition_key: Option<Vec<u8>>,
    /// Optional cost of the corresponding request in quota units (`c` parameter, §3.1.4).
    pub cost: Option<u64>,
}

/// A single dimension declaration within a `RateLimit-Partition` item (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionDimension {
    /// Boolean `true` parameter (e.g. `;method`): dimension varies across partitions.
    Varying,
    /// Non-Boolean parameter (e.g. `;method=GET`): policy applies only to matching requests.
    Fixed(String),
    /// Parameter value form that cannot be predicted (e.g. `?0`, decimal, byte sequence,
    /// or a fixed value containing `0x1F`), forcing the partition key to be treated as opaque.
    Opaque,
}

/// Parsed Partition Dimension Item from `RateLimit-Partition` (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionItem {
    /// Policy identifier as advertised by the server (matched case-insensitively per §2.1).
    pub name: String,
    /// Declared partition dimensions `(dimension_key, declaration)`.
    pub dimensions: Vec<(String, PartitionDimension)>,
}

/// Parsed RFC 9651 Structured Field parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfParamValue {
    /// RFC 9651 Integer (`-999_999_999_999_999..=999_999_999_999_999`).
    Integer(i64),
    /// RFC 9651 String.
    String(String),
    /// RFC 9651 Token.
    Token(String),
    /// Decoded RFC 9651 Byte Sequence (`:base64:`).
    ByteSeq(Vec<u8>),
    /// RFC 9651 Boolean (`?0`, `?1`, or omitted parameter value).
    Boolean(bool),
    /// Another valid RFC 9651 bare item type (Decimal, Date).
    Other,
}

/// Parsed RFC 9651 List Item whose bare item is a Token or String.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfItem {
    /// Bare item value (either Token text or unescaped String content).
    pub value: String,
    /// Deduplicated item parameters (RFC 9651 §3.1.2 last-value-wins).
    pub params: Vec<(String, SfParamValue)>,
}

/// Zero-indexing parser for RFC 9651 Structured Field Lists of Token/String Items.
struct SfParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SfParser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { bytes: input.as_bytes(), pos: 0 }
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    fn next_byte(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Parse an RFC 9651 String (`"..."`).
    fn parse_string(&mut self) -> Option<String> {
        if self.next_byte()? != b'"' {
            return None;
        }
        let mut out = String::new();
        while let Some(b) = self.next_byte() {
            match b {
                b'\\' => {
                    let esc = self.next_byte()?;
                    if !matches!(esc, b'"' | b'\\') {
                        return None;
                    }
                    out.push(char::from(esc));
                },
                b'"' => return Some(out),
                0x20..=0x7E => out.push(char::from(b)),
                _ => return None,
            }
        }
        None
    }

    /// Parse an RFC 9651 Token (`(ALPHA / "*") *(tchar / ":" / "/")`).
    fn parse_token(&mut self) -> Option<String> {
        let start = self.pos;
        let first = self.next_byte()?;
        if !(first.is_ascii_alphabetic() || first == b'*') {
            return None;
        }
        while let Some(b) = self.peek() {
            if is_sf_token_char(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        let slice = self.bytes.get(start..self.pos)?;
        std::str::from_utf8(slice).ok().map(str::to_owned)
    }

    /// Parse an RFC 9651 Token or String bare item.
    fn parse_token_or_string(&mut self) -> Option<String> {
        match self.peek()? {
            b'"' => self.parse_string(),
            b if b.is_ascii_alphabetic() || b == b'*' => self.parse_token(),
            _ => None,
        }
    }

    /// Parse an RFC 9651 parameter key.
    fn parse_key(&mut self) -> Option<String> {
        let start = self.pos;
        let first = self.next_byte()?;
        if !(first.is_ascii_lowercase() || first == b'*') {
            return None;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'-' | b'.' | b'*')
            {
                self.pos += 1;
            } else {
                break;
            }
        }
        let slice = self.bytes.get(start..self.pos)?;
        std::str::from_utf8(slice).ok().map(str::to_owned)
    }

    /// Parse an RFC 9651 Byte Sequence (`:base64:`), decoding standard base64
    /// (forgiving missing padding per RFC 9651 §4.2.7).
    fn parse_byte_seq(&mut self) -> Option<Vec<u8>> {
        if self.next_byte()? != b':' {
            return None;
        }
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b':' {
                break;
            }
            if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
                return None;
            }
            self.pos += 1;
        }
        let raw = self.bytes.get(start..self.pos)?;
        if self.next_byte()? != b':' {
            return None;
        }
        decode_sf_base64(raw)
    }

    /// Parse an RFC 9651 Integer (1..=15 digits) or Decimal (1..=12 int digits, 1..=3 frac digits).
    fn parse_number(&mut self) -> Option<SfParamValue> {
        let num_start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        let int_digits = self.pos - digits_start;
        if int_digits == 0 {
            return None;
        }
        if self.peek() == Some(b'.') {
            // RFC 9651 §3.3.2: Decimal integer part <= 12 digits, fraction 1..=3 digits.
            if int_digits > 12 {
                return None;
            }
            self.pos += 1;
            let frac_start = self.pos;
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            let frac_digits = self.pos - frac_start;
            if !(1..=3).contains(&frac_digits) {
                return None;
            }
            return Some(SfParamValue::Other);
        }

        // RFC 9651 §3.3.1: Integer is 1..=15 digits in -999_999_999_999_999..=999_999_999_999_999.
        if int_digits > 15 {
            return None;
        }
        let num_str = std::str::from_utf8(self.bytes.get(num_start..self.pos)?).ok()?;
        let n = num_str.parse::<i64>().ok()?;
        if !(SF_MIN_INTEGER..=SF_MAX_INTEGER).contains(&n) {
            return None;
        }
        Some(SfParamValue::Integer(n))
    }

    /// Parse an RFC 9651 Date (`@<sf-integer>`, §3.3.7).
    fn parse_date(&mut self) -> Option<SfParamValue> {
        if self.next_byte()? != b'@' {
            return None;
        }
        match self.parse_number()? {
            SfParamValue::Integer(_) => Some(SfParamValue::Other),
            _ => None,
        }
    }

    /// Parse an RFC 9651 parameter value after `=`.
    fn parse_param_value(&mut self) -> Option<SfParamValue> {
        match self.peek()? {
            b'"' => self.parse_string().map(SfParamValue::String),
            b':' => self.parse_byte_seq().map(SfParamValue::ByteSeq),
            b'?' => {
                self.pos += 1;
                match self.next_byte()? {
                    b'0' => Some(SfParamValue::Boolean(false)),
                    b'1' => Some(SfParamValue::Boolean(true)),
                    _ => None,
                }
            },
            b'-' | b'0'..=b'9' => self.parse_number(),
            b'@' => self.parse_date(),
            b if b.is_ascii_alphabetic() || b == b'*' => {
                self.parse_token().map(SfParamValue::Token)
            },
            _ => None,
        }
    }

    /// Parse RFC 9651 parameters (`*( ";" *SP parameter )`).
    fn parse_parameters(&mut self) -> Option<Vec<(String, SfParamValue)>> {
        let mut params: Vec<(String, SfParamValue)> = Vec::new();
        while self.peek() == Some(b';') {
            self.pos += 1; // consume ';'
            self.skip_sp();
            let key = self.parse_key()?;
            let val = if self.peek() == Some(b'=') {
                self.pos += 1;
                self.parse_param_value()?
            } else {
                // RFC 9651 §3.1.2: omitted value defaults to Boolean true.
                SfParamValue::Boolean(true)
            };

            // RFC 9651 §3.1.2: duplicate parameter keys overwrite earlier ones.
            if let Some(existing) = params.iter_mut().find(|(k, _)| k == &key) {
                existing.1 = val;
            } else {
                params.push((key, val));
            }
        }
        Some(params)
    }

    /// Parse a full RFC 9651 List of Token/String Items.
    fn parse_list(mut self) -> Option<Vec<SfItem>> {
        self.skip_ows();
        self.peek()?;

        let mut items = Vec::new();
        while self.peek().is_some() {
            let value = self.parse_token_or_string()?;
            let params = self.parse_parameters()?;
            items.push(SfItem { value, params });

            self.skip_ows();
            match self.peek() {
                None => break,
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ows();
                    // Trailing comma is invalid in an RFC 9651 List.
                    self.peek()?;
                },
                Some(_) => return None,
            }
        }

        if items.is_empty() { None } else { Some(items) }
    }
}

/// Return `true` if `b` is a valid continuation byte of an RFC 9651 Token (`tchar / ":" / "/"`).
#[inline]
const fn is_sf_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b':'
                | b'/'
        )
}

/// Decode an RFC 9651 Byte Sequence's base64 payload, forgiving omitted `=` padding (§4.2.7).
fn decode_sf_base64(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return Some(Vec::new());
    }
    if raw.contains(&b'=') || raw.len().is_multiple_of(4) {
        BASE64.decode(raw).ok()
    } else {
        BASE64_NOPAD.decode(raw).ok()
    }
}

/// Convert a non-negative RFC 9651 integer (`0..=SF_MAX_INTEGER`) to `u64`.
#[inline]
fn sf_non_negative_u64(n: i64) -> Option<u64> {
    if (0..=SF_MAX_INTEGER).contains(&n) { u64::try_from(n).ok() } else { None }
}

/// Convert a positive RFC 9651 integer (`1..=SF_MAX_INTEGER`) to `u64`.
#[inline]
fn sf_positive_u64(n: i64) -> Option<u64> {
    if (1..=SF_MAX_INTEGER).contains(&n) { u64::try_from(n).ok() } else { None }
}

/// Parse an RFC 9651 Structured Field List of Token or String Items with parameters,
/// used by `RateLimit-Policy` (§2), `RateLimit` (§3), and `RateLimit-Partition` (§4).
///
/// Returns `None` if the header value is empty or syntactically malformed (§7:
/// "Malformed `RateLimit` header fields MUST be ignored").
#[must_use]
pub fn parse_sf_item_list(input: &str) -> Option<Vec<SfItem>> {
    SfParser::new(input).parse_list()
}

/// Construct a structured partition key byte sequence per
/// `draft-ietf-httpapi-ratelimit-headers-12` §4.2.
///
/// Sorts `dimensions` lexicographically by dimension key, encodes values as UTF-8, and
/// concatenates them separated by `0x1F` (Unit Separator).
///
/// Returns `None` if `dimensions` is empty or any dimension value contains `0x1F`.
#[must_use]
pub fn build_structured_partition_key(dimensions: &[(&str, &str)]) -> Option<Vec<u8>> {
    if dimensions.is_empty() {
        return None;
    }

    let mut sorted: Vec<(&str, &str)> = Vec::with_capacity(dimensions.len());
    let mut total_bytes = dimensions.len().saturating_sub(1);
    for &(key, val) in dimensions {
        if val.as_bytes().contains(&PARTITION_KEY_SEPARATOR) {
            return None;
        }
        total_bytes = total_bytes.checked_add(val.len())?;
        sorted.push((key, val));
    }

    sorted.sort_unstable_by_key(|&(k, _)| k);

    let mut out = Vec::with_capacity(total_bytes);
    for (idx, (_, val)) in sorted.iter().enumerate() {
        if idx > 0 {
            out.push(PARTITION_KEY_SEPARATOR);
        }
        out.extend_from_slice(val.as_bytes());
    }
    Some(out)
}

/// Check whether a response came from an HTTP cache (`Age > 0`).
///
/// Per `draft-ietf-httpapi-ratelimit-headers-12` §8.4, `RateLimit` header fields
/// SHOULD be ignored on responses with a positive `current_age`.
#[must_use]
pub fn is_cached_response(headers: &HeaderMap) -> bool {
    headers
        .get(AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_decimal(s.trim()))
        .is_some_and(|age| age > 0)
}

/// Parse all `RateLimit-Policy` header fields in `headers` (§2).
///
/// Malformed list items and duplicate case-insensitive policy identifiers are ignored (§2.1).
#[must_use]
pub fn parse_ratelimit_policy_headers(headers: &HeaderMap, debug: bool) -> Vec<QuotaPolicyItem> {
    if is_cached_response(headers) {
        if debug {
            eprintln!("[DEBUG] RateLimit-Policy: ignoring headers on cached response (Age > 0)");
        }
        return Vec::new();
    }

    let mut policies = Vec::new();
    let mut seen_names = HashSet::new();

    for val in headers.get_all(RATELIMIT_POLICY_HEADER) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        let Some(sf_items) = parse_sf_item_list(s) else {
            if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Policy: ignoring malformed header '{}'",
                    terminal_safe(s)
                );
            }
            continue;
        };

        for item in sf_items {
            if item.value.is_empty() {
                if debug {
                    eprintln!("[DEBUG] RateLimit-Policy: ignoring empty policy identifier");
                }
                continue;
            }

            let mut q: Option<u64> = None;
            let mut qu = QuotaUnit::Requests;
            let mut w: Option<u64> = None;
            let mut pk: Option<Vec<u8>> = None;
            let mut valid = true;

            for (k, v) in item.params {
                match k.as_str() {
                    "q" => match v {
                        // §2.1.1: "q" MUST be a non-negative Integer
                        SfParamValue::Integer(n) => {
                            if let Some(val) = sf_non_negative_u64(n) {
                                q = Some(val);
                            } else {
                                valid = false;
                                break;
                            }
                        },
                        _ => {
                            valid = false;
                            break;
                        },
                    },
                    "qu" => {
                        // §2.1.2: "qu" MUST be a String
                        if let SfParamValue::String(ref unit_str) = v {
                            qu = QuotaUnit::from_str_param(unit_str);
                        } else {
                            valid = false;
                            break;
                        }
                    },
                    "w" => match v {
                        // §2.1.3: "w" MUST be a non-negative, non-zero Integer
                        SfParamValue::Integer(n) => {
                            if let Some(val) = sf_positive_u64(n) {
                                w = Some(val);
                            } else {
                                valid = false;
                                break;
                            }
                        },
                        _ => {
                            valid = false;
                            break;
                        },
                    },
                    "pk" => {
                        // §2.1.4: "pk" MUST be a Byte Sequence
                        if let SfParamValue::ByteSeq(b) = v {
                            pk = Some(b);
                        } else {
                            valid = false;
                            break;
                        }
                    },
                    _ => {}, // Unknown parameters MUST be ignored (§2.1)
                }
            }

            let (true, Some(quota)) = (valid, q) else {
                if debug {
                    eprintln!(
                        "[DEBUG] RateLimit-Policy: ignoring invalid policy item '{}'",
                        terminal_safe(&item.value)
                    );
                }
                continue;
            };

            // §2.1: Policy identifiers are compared case-insensitively; ignore duplicates.
            let norm_name = item.value.to_ascii_lowercase();
            if !seen_names.insert(norm_name) {
                if debug {
                    eprintln!(
                        "[DEBUG] RateLimit-Policy: ignoring duplicate policy identifier '{}'",
                        terminal_safe(&item.value)
                    );
                }
                continue;
            }

            policies.push(QuotaPolicyItem {
                name: item.value,
                quota,
                unit: qu,
                window: w,
                partition_key: pk,
            });
        }
    }
    policies
}

/// Parse all `RateLimit` header fields in `headers` (§3).
///
/// Malformed `RateLimit` header fields are ignored (§7), and duplicate case-insensitive
/// policy identifiers are skipped (§2.1).
#[must_use]
pub fn parse_ratelimit_headers(headers: &HeaderMap, debug: bool) -> Vec<ServiceLimitItem> {
    if is_cached_response(headers) {
        if debug {
            eprintln!("[DEBUG] RateLimit: ignoring headers on cached response (Age > 0)");
        }
        return Vec::new();
    }

    let mut limits = Vec::new();
    let mut seen_names = HashSet::new();

    for val in headers.get_all(RATELIMIT_HEADER) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        let Some(sf_items) = parse_sf_item_list(s) else {
            if debug {
                eprintln!("[DEBUG] RateLimit: ignoring malformed header '{}'", terminal_safe(s));
            }
            continue;
        };

        let mut header_items = Vec::with_capacity(sf_items.len());
        let mut header_valid = true;

        for item in sf_items {
            if item.value.is_empty() {
                header_valid = false;
                break;
            }

            let mut a: Option<u64> = None;
            let mut w: Option<u64> = None;
            let mut pk: Option<Vec<u8>> = None;
            let mut c: Option<u64> = None;

            for (k, v) in item.params {
                match k.as_str() {
                    "a" => match v {
                        // §3.1.1: "a" is a REQUIRED non-negative Integer
                        SfParamValue::Integer(n) => {
                            if let Some(val) = sf_non_negative_u64(n) {
                                a = Some(val);
                            } else {
                                header_valid = false;
                                break;
                            }
                        },
                        _ => {
                            header_valid = false;
                            break;
                        },
                    },
                    "w" => match v {
                        // §3.1.2: "w" is an OPTIONAL non-negative Integer (0 is allowed)
                        SfParamValue::Integer(n) => {
                            if let Some(val) = sf_non_negative_u64(n) {
                                w = Some(val);
                            } else {
                                header_valid = false;
                                break;
                            }
                        },
                        _ => {
                            header_valid = false;
                            break;
                        },
                    },
                    "pk" => {
                        // §3.1.3: "pk" MUST be a Byte Sequence
                        if let SfParamValue::ByteSeq(b) = v {
                            pk = Some(b);
                        } else {
                            header_valid = false;
                            break;
                        }
                    },
                    "c" => match v {
                        // §3.1.4: "c" is an OPTIONAL non-negative Integer
                        SfParamValue::Integer(n) => {
                            if let Some(val) = sf_non_negative_u64(n) {
                                c = Some(val);
                            } else {
                                header_valid = false;
                                break;
                            }
                        },
                        _ => {
                            header_valid = false;
                            break;
                        },
                    },
                    _ => {}, // Unknown parameters MUST be ignored (§3.1)
                }
            }

            if !header_valid {
                break;
            }
            let Some(available_quota) = a else {
                header_valid = false;
                break;
            };

            header_items.push(ServiceLimitItem {
                name: item.value,
                available_quota,
                effective_window: w,
                partition_key: pk,
                cost: c,
            });
        }

        if header_valid {
            for item in header_items {
                let norm_name = item.name.to_ascii_lowercase();
                if seen_names.insert(norm_name) {
                    limits.push(item);
                } else if debug {
                    eprintln!(
                        "[DEBUG] RateLimit: ignoring duplicate policy identifier '{}'",
                        terminal_safe(&item.name)
                    );
                }
            }
        } else if debug {
            eprintln!(
                "[DEBUG] RateLimit: ignoring malformed service limit item in '{}'",
                terminal_safe(s)
            );
        }
    }
    limits
}

/// Parse all `RateLimit-Partition` header fields in `headers` (§4).
///
/// Malformed headers and duplicate case-insensitive policy identifiers are ignored (§2.1, §4.1).
#[must_use]
pub fn parse_ratelimit_partition_headers(headers: &HeaderMap, debug: bool) -> Vec<PartitionItem> {
    if is_cached_response(headers) {
        if debug {
            eprintln!("[DEBUG] RateLimit-Partition: ignoring headers on cached response (Age > 0)");
        }
        return Vec::new();
    }

    let mut partitions = Vec::new();
    let mut seen_names = HashSet::new();

    for val in headers.get_all(RATELIMIT_PARTITION_HEADER) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        let Some(sf_items) = parse_sf_item_list(s) else {
            if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Partition: ignoring malformed header '{}'",
                    terminal_safe(s)
                );
            }
            continue;
        };

        for item in sf_items {
            if item.value.is_empty() {
                if debug {
                    eprintln!("[DEBUG] RateLimit-Partition: ignoring empty policy identifier");
                }
                continue;
            }

            let norm_name = item.value.to_ascii_lowercase();
            if !seen_names.insert(norm_name) {
                if debug {
                    eprintln!(
                        "[DEBUG] RateLimit-Partition: ignoring duplicate policy identifier '{}'",
                        terminal_safe(&item.value)
                    );
                }
                continue;
            }

            let mut dimensions = Vec::with_capacity(item.params.len());
            for (k, v) in item.params {
                let decl = match v {
                    SfParamValue::Boolean(true) => PartitionDimension::Varying,
                    SfParamValue::String(s) | SfParamValue::Token(s) => {
                        if s.as_bytes().contains(&PARTITION_KEY_SEPARATOR) {
                            PartitionDimension::Opaque
                        } else {
                            PartitionDimension::Fixed(s)
                        }
                    },
                    SfParamValue::Integer(n) => PartitionDimension::Fixed(n.to_string()),
                    SfParamValue::Boolean(false)
                    | SfParamValue::ByteSeq(_)
                    | SfParamValue::Other => PartitionDimension::Opaque,
                };
                dimensions.push((k, decl));
            }

            partitions.push(PartitionItem { name: item.value, dimensions });
        }
    }

    partitions
}

/// Parse `Retry-After` (RFC 9110 §10.2.3) as either `delay-seconds` or `HTTP-date`,
/// capped at [`MAX_RATELIMIT_WAIT_SECS`].
fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let val = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Some(secs) = parse_decimal(val) {
        return Some(Duration::from_secs(secs.min(MAX_RATELIMIT_WAIT_SECS)));
    }
    if let Some(target_time) = parse_http_date(val) {
        let now = SystemTime::now();
        let dur = target_time.duration_since(now).unwrap_or(Duration::ZERO);
        return Some(Duration::from_secs(dur.as_secs().min(MAX_RATELIMIT_WAIT_SECS)));
    }
    None
}

/// Check whether `Content-Type` has media type `application/problem+json`.
fn is_problem_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/problem+json"))
}

/// Parse an RFC 9457 Problem Details JSON body for the three problem types defined
/// in `draft-ietf-httpapi-ratelimit-headers-12` §8 (`quota-exceeded`,
/// `temporary-reduced-capacity`, `abnormal-usage-detected`).
#[must_use]
pub fn parse_ratelimit_problem_body(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    if !is_problem_json(headers) {
        return None;
    }
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    let prob_type = val.get("type").and_then(serde_json::Value::as_str).unwrap_or("");
    let short_type = match prob_type {
        "https://iana.org/assignments/http-problem-types#quota-exceeded" => Some("quota-exceeded"),
        "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity" => {
            Some("temporary-reduced-capacity")
        },
        "https://iana.org/assignments/http-problem-types#abnormal-usage-detected" => {
            Some("abnormal-usage-detected")
        },
        _ => None,
    };
    let title = val.get("title").and_then(serde_json::Value::as_str);
    let violated_arr = val.get("violated-policies").and_then(serde_json::Value::as_array);
    let has_violated = violated_arr.is_some_and(|arr| arr.iter().any(|x| x.as_str().is_some()));

    if short_type.is_none() && !has_violated && title.is_none() {
        return None;
    }

    let mut summary = String::with_capacity(96);
    if let Some(st) = short_type {
        summary.push_str(st);
    } else if !prob_type.is_empty() {
        summary.push_str(&terminal_safe(prob_type));
    }
    if let Some(t) = title {
        if !summary.is_empty() {
            summary.push_str(": ");
        }
        summary.push_str(&terminal_safe(t));
    }
    if has_violated && let Some(arr) = violated_arr {
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str("(violated-policies: ");
        let mut first = true;
        for policy in arr.iter().filter_map(serde_json::Value::as_str) {
            if !first {
                summary.push_str(", ");
            }
            first = false;
            let _ = write!(summary, "{}", terminal_safe(policy));
        }
        summary.push(')');
    }
    Some(summary)
}

/// Canonical uppercase HTTP method name per §11.7 (`"GET"`, `"HEAD"`, ...).
fn canonical_method(method: &Method) -> Cow<'_, str> {
    let raw = method.as_str();
    if raw.bytes().all(|b| !b.is_ascii_lowercase()) {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(raw.to_ascii_uppercase())
    }
}

/// Borrowed view trait enabling zero-allocation lookups into `HashMap<OriginKey, _>`.
trait OriginKeyView {
    fn scheme(&self) -> &str;
    fn host(&self) -> &str;
    fn port(&self) -> u16;
}

impl PartialEq for dyn OriginKeyView + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.port() == other.port()
            && self.scheme().eq_ignore_ascii_case(other.scheme())
            && self.host().eq_ignore_ascii_case(other.host())
    }
}

impl Eq for dyn OriginKeyView + '_ {}

impl Hash for dyn OriginKeyView + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.scheme().bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0);
        for b in self.host().bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0);
        self.port().hash(state);
    }
}

/// Owned origin key (`scheme`, lowercase `host`, `port`).
#[derive(Debug, Clone)]
struct OriginKey {
    scheme: Box<str>,
    host: Box<str>,
    port: u16,
}

impl OriginKeyView for OriginKey {
    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl PartialEq for OriginKey {
    fn eq(&self, other: &Self) -> bool {
        (self as &dyn OriginKeyView) == (other as &dyn OriginKeyView)
    }
}

impl Eq for OriginKey {}

impl Hash for OriginKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self as &dyn OriginKeyView).hash(state);
    }
}

impl<'a> Borrow<dyn OriginKeyView + 'a> for OriginKey {
    fn borrow(&self) -> &(dyn OriginKeyView + 'a) {
        self
    }
}

/// Borrowed origin key extracted directly from a [`Url`] without allocation.
#[derive(Clone, Copy)]
struct OriginKeyRef<'a> {
    scheme: &'a str,
    host: &'a str,
    port: u16,
}

impl<'a> OriginKeyRef<'a> {
    fn from_url(url: &'a Url) -> Option<Self> {
        let host = url.host_str()?;
        let port = url.port_or_known_default().unwrap_or(443);
        Some(Self { scheme: url.scheme(), host, port })
    }

    fn to_owned_key(self) -> OriginKey {
        OriginKey {
            scheme: self.scheme.to_ascii_lowercase().into_boxed_str(),
            host: self.host.to_ascii_lowercase().into_boxed_str(),
            port: self.port,
        }
    }
}

impl OriginKeyView for OriginKeyRef<'_> {
    fn scheme(&self) -> &str {
        self.scheme
    }

    fn host(&self) -> &str {
        self.host
    }

    fn port(&self) -> u16 {
        self.port
    }
}

/// Stored `RateLimit-Partition` declaration for a single policy.
#[derive(Debug, Clone)]
struct PartitionDeclaration {
    dimensions: Box<[(Box<str>, PartitionDimension)]>,
}

/// Outcome of evaluating a [`PartitionDeclaration`] against an outgoing request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PartitionMatch {
    /// Policy does not apply to this request (a known fixed dimension did not match).
    NotApplicable,
    /// Policy applies and its structured partition key (§4.2) was deterministically computed.
    PredictedKey(Vec<u8>),
    /// Policy applies (or might apply), but at least one dimension cannot be computed,
    /// so its partition key MUST be treated as opaque (§4.1).
    Opaque,
}

impl PartitionDeclaration {
    fn from_item(item: PartitionItem) -> Self {
        let dimensions = item
            .dimensions
            .into_iter()
            .map(|(k, v)| (k.into_boxed_str(), v))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { dimensions }
    }

    /// Evaluate whether this policy applies to a request with `method`, and if all
    /// declared dimensions are computable, return the structured partition key (§4.2).
    fn evaluate(&self, method: &Method) -> PartitionMatch {
        let req_method = canonical_method(method);

        // First check known fixed dimensions so we can skip inapplicable policies (§4.1/§4.2)
        // even when other dimensions (like `user_id`) are opaque.
        for (key, decl) in &self.dimensions {
            if key.as_ref() == "method"
                && let PartitionDimension::Fixed(expected) = decl
                && expected.as_str() != req_method.as_ref()
            {
                return PartitionMatch::NotApplicable;
            }
        }

        if self.dimensions.is_empty() {
            return PartitionMatch::Opaque;
        }

        let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(self.dimensions.len());
        for (key, decl) in &self.dimensions {
            match (key.as_ref(), decl) {
                ("method", PartitionDimension::Varying) => {
                    pairs.push(("method", req_method.as_ref()));
                },
                ("method", PartitionDimension::Fixed(expected)) => {
                    pairs.push(("method", expected.as_str()));
                },
                // §4.1: Any unrecognized or non-computable dimension forces opaque handling.
                _ => return PartitionMatch::Opaque,
            }
        }

        build_structured_partition_key(&pairs)
            .map_or(PartitionMatch::Opaque, PartitionMatch::PredictedKey)
    }
}

/// Partitioned and unpartitioned wait deadlines for a single policy.
#[derive(Debug, Default)]
struct DeadlineStore {
    /// Earliest next request time when no partition key was advertised for this policy.
    unpartitioned: Option<Instant>,
    /// Earliest next request time keyed by raw partition key bytes (`pk`).
    by_partition: HashMap<Box<[u8]>, Instant>,
}

impl DeadlineStore {
    fn prune_expired(&mut self, now: Instant) {
        if self.unpartitioned.is_some_and(|d| d <= now) {
            self.unpartitioned = None;
        }
        self.by_partition.retain(|_, &mut d| d > now);
    }

    fn record(&mut self, pk: Option<&[u8]>, deadline: Instant, now: Instant) {
        let Some(pk_bytes) = pk else {
            self.unpartitioned = Some(self.unpartitioned.map_or(deadline, |cur| cur.max(deadline)));
            return;
        };

        if let Some(existing) = self.by_partition.get_mut(pk_bytes) {
            *existing = (*existing).max(deadline);
            return;
        }

        if self.by_partition.len() >= MAX_PARTITIONS_PER_POLICY {
            self.by_partition.retain(|_, &mut d| d > now);
            if self.by_partition.len() >= MAX_PARTITIONS_PER_POLICY
                && let Some(oldest_key) =
                    self.by_partition.iter().min_by_key(|&(_, &d)| d).map(|(k, _)| k.clone())
            {
                self.by_partition.remove(&oldest_key);
            }
        }

        self.by_partition.insert(pk_bytes.into(), deadline);
    }

    fn max_active(&self, now: Instant) -> Option<Instant> {
        let mut target = self.unpartitioned.filter(|&d| d > now);
        for &d in self.by_partition.values() {
            if d > now {
                target = Some(target.map_or(d, |cur| cur.max(d)));
            }
        }
        target
    }

    fn active_for_partition(&self, pk: &[u8], now: Instant) -> Option<Instant> {
        let mut target = self.unpartitioned.filter(|&d| d > now);
        if let Some(&d) = self.by_partition.get(pk)
            && d > now
        {
            target = Some(target.map_or(d, |cur| cur.max(d)));
        }
        target
    }
}

/// Per-policy rate-limit state tracked for a single origin.
#[derive(Debug, Default)]
struct PolicyState {
    policy: Option<QuotaPolicyItem>,
    partition: Option<PartitionDeclaration>,
    deadlines: DeadlineStore,
}

impl PolicyState {
    fn prune_expired(&mut self, now: Instant) {
        self.deadlines.prune_expired(now);
    }

    fn max_active_deadline(&self, now: Instant) -> Option<Instant> {
        self.deadlines.max_active(now)
    }

    fn active_deadline_for(&self, method: &Method, now: Instant) -> Option<Instant> {
        let Some(ref partition) = self.partition else {
            return self.deadlines.max_active(now);
        };

        match partition.evaluate(method) {
            PartitionMatch::NotApplicable => None,
            PartitionMatch::PredictedKey(pk) => self.deadlines.active_for_partition(&pk, now),
            PartitionMatch::Opaque => self.deadlines.max_active(now),
        }
    }
}

/// Per-origin state tracked by [`RateLimitTracker`].
#[derive(Debug, Default)]
struct OriginState {
    /// Origin-wide earliest next request time (from `Retry-After`).
    next_allowed_origin: Option<Instant>,
    /// Policies keyed by ASCII-lowercase policy identifier (§2.1).
    policies: HashMap<Box<str>, PolicyState>,
}

impl OriginState {
    fn prune_expired(&mut self, now: Instant) {
        if self.next_allowed_origin.is_some_and(|d| d <= now) {
            self.next_allowed_origin = None;
        }
        for state in self.policies.values_mut() {
            state.prune_expired(now);
        }
    }

    fn latest_deadline(&self, now: Instant) -> Option<Instant> {
        let mut latest = self.next_allowed_origin.filter(|&d| d > now);
        for state in self.policies.values() {
            if let Some(d) = state.max_active_deadline(now) {
                latest = Some(latest.map_or(d, |cur| cur.max(d)));
            }
        }
        latest
    }

    fn policy_entry_mut(&mut self, norm_name: &str, now: Instant) -> &mut PolicyState {
        if !self.policies.contains_key(norm_name) {
            if self.policies.len() >= MAX_POLICIES_PER_ORIGIN {
                self.prune_expired(now);
                // Evict an inactive policy first, or the one with the earliest deadline.
                if let Some(evict_key) = self
                    .policies
                    .iter()
                    .min_by_key(|(_, st)| st.max_active_deadline(now))
                    .map(|(k, _)| k.clone())
                {
                    self.policies.remove(&evict_key);
                }
            }
            self.policies.insert(norm_name.into(), PolicyState::default());
        }
        // Key is guaranteed present because we inserted it above if missing.
        self.policies.get_mut(norm_name).expect("policy entry inserted")
    }
}

/// Per-origin `RateLimit` state tracker implementing client behavior from
/// `draft-ietf-httpapi-ratelimit-headers-12` §4 and §7.
#[derive(Debug, Default)]
pub struct RateLimitTracker {
    origins: HashMap<OriginKey, OriginState>,
}

impl RateLimitTracker {
    /// Create a new, empty [`RateLimitTracker`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up or insert the [`OriginState`] for `key_ref` without allocating on hits.
    fn origin_state_mut(&mut self, key_ref: OriginKeyRef<'_>, now: Instant) -> &mut OriginState {
        if !self.origins.contains_key(&key_ref as &dyn OriginKeyView) {
            if self.origins.len() >= MAX_TRACKED_ORIGINS {
                for state in self.origins.values_mut() {
                    state.prune_expired(now);
                }
                if let Some(evict_key) = self
                    .origins
                    .iter()
                    .min_by_key(|(_, st)| st.latest_deadline(now))
                    .map(|(k, _)| k.clone())
                {
                    self.origins.remove(&evict_key);
                }
            }
            self.origins.insert(key_ref.to_owned_key(), OriginState::default());
        }
        self.origins.get_mut(&key_ref as &dyn OriginKeyView).expect("origin state inserted")
    }

    /// Compute the remaining wait duration before sending a `method` request to `url` at `now`.
    fn compute_wait_delay(&self, url: &Url, method: &Method, now: Instant) -> Option<Duration> {
        let key_ref = OriginKeyRef::from_url(url)?;
        let origin_state = self.origins.get(&key_ref as &dyn OriginKeyView)?;

        let mut target = origin_state.next_allowed_origin.filter(|&d| d > now);
        for policy_state in origin_state.policies.values() {
            if let Some(d) = policy_state.active_deadline_for(method, now) {
                target = Some(target.map_or(d, |cur| cur.max(d)));
            }
        }

        target.map(|deadline| deadline.saturating_duration_since(now)).filter(|d| !d.is_zero())
    }

    /// Wait if a previous response from this origin advertised an active rate-limit window
    /// applicable to `(url, method)`.
    pub async fn wait_before_request(&mut self, url: &Url, method: &Method, args: &Args) {
        let now = Instant::now();
        if let Some(delay) = self.compute_wait_delay(url, method, now) {
            if !args.quiet {
                eprintln!(
                    "RateLimit: waiting {:.1}s before requesting {}",
                    delay.as_secs_f64(),
                    url.host_str().unwrap_or("<host>")
                );
            }
            sleep(delay).await;
        }
    }

    /// Update state from response headers and return the recommended wait [`Duration`]
    /// (if `Retry-After` is present or any policy cannot satisfy another similar request).
    ///
    /// Implements `draft-ietf-httpapi-ratelimit-headers-12` §4 and §7:
    /// - Records `RateLimit-Policy` (§2) and `RateLimit-Partition` (§4) declarations using
    ///   case-insensitive policy identifiers (§2.1).
    /// - If both `Retry-After` and `RateLimit` are present, `Retry-After` MUST take
    ///   precedence and `w` MAY be ignored (§7).
    /// - When `a == 0` (or `a < c` when `c > 0` for request quotas or error responses) and
    ///   `w` is present, schedules the next request after `w` seconds (capped at
    ///   [`MAX_RATELIMIT_WAIT_SECS`] per §9.5.1).
    /// - When `a > 0` and `w > 0` for request-based quotas, uses `c` (when present, §3.1.4)
    ///   to estimate remaining requests and pre-emptively paces when throttled down.
    pub fn record_response(
        &mut self,
        url: &Url,
        method: &Method,
        status: StatusCode,
        headers: &HeaderMap,
        args: &Args,
    ) -> Option<Duration> {
        self.record_response_at(url, method, status, headers, args.debug, Instant::now())
    }

    /// Internal deterministic entry point accepting an explicit `now` [`Instant`].
    fn record_response_at(
        &mut self,
        url: &Url,
        method: &Method,
        status: StatusCode,
        headers: &HeaderMap,
        debug: bool,
        now: Instant,
    ) -> Option<Duration> {
        let key_ref = OriginKeyRef::from_url(url)?;

        let policies = parse_ratelimit_policy_headers(headers, debug);
        let partitions = parse_ratelimit_partition_headers(headers, debug);
        let limits = parse_ratelimit_headers(headers, debug);
        let retry_after = parse_retry_after(headers);

        if policies.is_empty()
            && partitions.is_empty()
            && limits.is_empty()
            && retry_after.is_none()
        {
            return None;
        }

        let origin_state = self.origin_state_mut(key_ref, now);

        for p in policies {
            if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Policy: '{}' q={} qu={} w={:?} pk={:?}",
                    terminal_safe(&p.name),
                    p.quota,
                    p.unit,
                    p.window,
                    p.partition_key.as_deref().map(|b| BASE64.encode(b))
                );
            }
            let norm_name = p.name.to_ascii_lowercase();
            origin_state.policy_entry_mut(&norm_name, now).policy = Some(p);
        }

        for part in partitions {
            if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Partition: '{}' dims={:?}",
                    terminal_safe(&part.name),
                    part.dimensions
                );
            }
            let norm_name = part.name.to_ascii_lowercase();
            origin_state.policy_entry_mut(&norm_name, now).partition =
                Some(PartitionDeclaration::from_item(part));
        }

        // §7: "If a response contains both the RateLimit and Retry-After fields,
        // the Retry-After field MUST take precedence and the effective window MAY be ignored."
        if let Some(ra_dur) = retry_after {
            if debug {
                eprintln!(
                    "[DEBUG] Retry-After takes precedence over RateLimit: {}s",
                    ra_dur.as_secs()
                );
            }
            if let Some(deadline) = now.checked_add(ra_dur) {
                origin_state.next_allowed_origin = Some(
                    origin_state.next_allowed_origin.map_or(deadline, |cur| cur.max(deadline)),
                );
            }
            return Some(ra_dur);
        }

        let is_error_status = status.is_client_error() || status.is_server_error();
        let mut max_exhausted_wait: Option<Duration> = None;

        for item in limits {
            let norm_name = item.name.to_ascii_lowercase();
            let policy_state = origin_state.policy_entry_mut(&norm_name, now);

            let policy = policy_state.policy.as_ref();
            let unit = policy.map_or(&QuotaUnit::Requests, |p| &p.unit);
            let derived_pk: Option<Vec<u8>> = if item.partition_key.is_none()
                && policy.and_then(|p| p.partition_key.as_deref()).is_none()
            {
                policy_state.partition.as_ref().and_then(|part| match part.evaluate(method) {
                    PartitionMatch::PredictedKey(k) => Some(k),
                    PartitionMatch::NotApplicable | PartitionMatch::Opaque => None,
                })
            } else {
                None
            };
            let pk: Option<&[u8]> = item
                .partition_key
                .as_deref()
                .or_else(|| policy.and_then(|p| p.partition_key.as_deref()))
                .or(derived_pk.as_deref());

            if debug {
                eprintln!(
                    "[DEBUG] RateLimit: '{}' a={} w={:?} c={:?} pk={:?} (unit={unit})",
                    terminal_safe(&item.name),
                    item.available_quota,
                    item.effective_window,
                    item.cost,
                    pk.map(|b| BASE64.encode(b))
                );
            }

            let Some(raw_w) = item.effective_window else {
                continue;
            };
            // §9.5.1 DoS protection: cap unreasonably large effective windows.
            let capped_w = raw_w.min(MAX_RATELIMIT_WAIT_SECS);
            if raw_w > MAX_RATELIMIT_WAIT_SECS && debug {
                eprintln!(
                    "[DEBUG] RateLimit: capping effective window w={raw_w}s to {MAX_RATELIMIT_WAIT_SECS}s"
                );
            }

            let insufficient_for_cost =
                item.cost.is_some_and(|cost| cost > 0 && item.available_quota < cost)
                    && (*unit == QuotaUnit::Requests || is_error_status);

            if item.available_quota == 0 || insufficient_for_cost {
                let wait = Duration::from_secs(capped_w);
                if let Some(deadline) = now.checked_add(wait) {
                    policy_state.deadlines.record(pk, deadline, now);
                }
                max_exhausted_wait = Some(max_exhausted_wait.map_or(wait, |cur| cur.max(wait)));
            } else if *unit == QuotaUnit::Requests && capped_w > 0 {
                // Pre-emptive pacing (§3.1.4, §7): estimate remaining similar requests
                // using `c` when advertised, and pace smoothly when throttled down
                // (e.g. Appendix A.2.2: "dynamic";q=100;w=60 with a=9;w=50) or down to 1.
                let effective_cost = item.cost.filter(|&c| c > 0).unwrap_or(1);
                let remaining_requests = item.available_quota / effective_cost;

                let is_throttled_down = policy
                    .and_then(|p| {
                        let policy_w = p.window?;
                        // Compare available rate (a / capped_w) against nominal policy rate (q / policy_w)
                        Some(
                            u128::from(item.available_quota) * u128::from(policy_w)
                                < u128::from(p.quota) * u128::from(capped_w),
                        )
                    })
                    .unwrap_or(remaining_requests == 1);

                if is_throttled_down && capped_w >= remaining_requests {
                    let pace_ms =
                        capped_w.saturating_mul(1000) / remaining_requests.saturating_add(1);
                    if pace_ms > 0
                        && let Some(deadline) = now.checked_add(Duration::from_millis(pace_ms))
                    {
                        policy_state.deadlines.record(pk, deadline, now);
                    }
                }
            }
        }

        max_exhausted_wait
    }
}

/// Build an [`PermanentError::HttpClientError`] or [`PermanentError::HttpRateLimited`] error
/// from a non-2xx [`Response`], updating `rl_tracker` and extracting any RFC 9457 rate-limit
/// problem details (§8).
pub async fn handle_error_response(
    response: Response,
    url: &Url,
    method: &Method,
    args: &Args,
    rl_tracker: &mut RateLimitTracker,
) -> anyhow::Error {
    let status = response.status();
    let headers = response.headers().clone();
    let wait = rl_tracker.record_response(url, method, status, &headers, args);

    let problem_detail = if is_problem_json(&headers) {
        let mut buf = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(Ok(chunk)) = stream.next().await {
            if buf.len().saturating_add(chunk.len()) > MAX_PROBLEM_BODY_BYTES {
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        parse_ratelimit_problem_body(&headers, &buf)
    } else {
        None
    };

    if status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::SERVICE_UNAVAILABLE
        || wait.is_some()
        || problem_detail.is_some()
    {
        PermanentError::HttpRateLimited { status: status.as_u16(), wait, problem_detail }.into()
    } else {
        PermanentError::HttpClientError(status.as_u16()).into()
    }
}

/// Extract server-advertised retry wait from an error, if present.
#[must_use]
pub fn extract_ratelimit_wait(err: &anyhow::Error) -> Option<Duration> {
    if let Some(PermanentError::HttpRateLimited { wait: Some(w), .. }) =
        err.downcast_ref::<PermanentError>()
    {
        return Some(*w);
    }
    None
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderName, HeaderValue};

    use super::*;

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(v).expect("valid header value"),
            );
        }
        map
    }

    #[test]
    fn parse_sf_accepts_tokens_and_strings_with_all_param_types() {
        let input = r#"burst;q=100;w=60,"daily";q=1000;qu="content-bytes";pk=:R0VUH2FsaWNl:;flag;off=?0;method=GET;ratio=1.5;ts=@1700000000"#;
        let items = parse_sf_item_list(input).expect("valid SF list");
        assert_eq!(items.len(), 2);

        assert_eq!(items[0].value, "burst");
        assert_eq!(
            items[0].params,
            vec![("q".into(), SfParamValue::Integer(100)), ("w".into(), SfParamValue::Integer(60)),]
        );

        assert_eq!(items[1].value, "daily");
        assert_eq!(
            items[1].params,
            vec![
                ("q".into(), SfParamValue::Integer(1000)),
                ("qu".into(), SfParamValue::String("content-bytes".into())),
                ("pk".into(), SfParamValue::ByteSeq(b"GET\x1Falice".to_vec())),
                ("flag".into(), SfParamValue::Boolean(true)),
                ("off".into(), SfParamValue::Boolean(false)),
                ("method".into(), SfParamValue::Token("GET".into())),
                ("ratio".into(), SfParamValue::Other),
                ("ts".into(), SfParamValue::Other),
            ]
        );
    }

    #[test]
    fn parse_sf_enforces_rfc9651_integer_and_decimal_bounds() {
        // Exact SF_MAX_INTEGER (15 digits) succeeds
        let ok = parse_sf_item_list("p;a=999999999999999;neg=-999999999999999")
            .expect("15-digit SF integers are valid");
        assert_eq!(ok[0].params[0].1, SfParamValue::Integer(SF_MAX_INTEGER));
        assert_eq!(ok[0].params[1].1, SfParamValue::Integer(SF_MIN_INTEGER));

        // 16 digits exceeds RFC 9651 §3.3.1
        assert!(parse_sf_item_list("p;a=1000000000000000").is_none());
        // Decimal with 4 fractional digits violates RFC 9651 §3.3.2
        assert!(parse_sf_item_list("p;x=1.2345").is_none());
        // Trailing comma is invalid
        assert!(parse_sf_item_list("p;a=1,").is_none());
        // Invalid base64 byte sequence is rejected
        assert!(parse_sf_item_list("p;pk=:not!base64:").is_none());
        // Whitespace before ';' violates RFC 9651 §4.2.3.2
        assert!(parse_sf_item_list("p ;a=1").is_none());
    }

    #[test]
    fn parse_sf_byte_seq_handles_empty_and_unpadded_base64() {
        let items = parse_sf_item_list("empty;pk=::, unpadded;pk=:SEVBRA:").expect("valid SF");
        assert_eq!(items[0].params[0].1, SfParamValue::ByteSeq(Vec::new()));
        assert_eq!(items[1].params[0].1, SfParamValue::ByteSeq(b"HEAD".to_vec()));
        // Unterminated byte sequence must be rejected
        assert!(parse_sf_item_list("unclosed;pk=:SEVBRA").is_none());
    }

    #[test]
    fn build_structured_partition_key_matches_draft12_section_4_2_example() {
        // Draft-12 §4.2: "api";user_id;method with user="alice", method="GET"
        // sorted -> ("method", "GET"), ("user_id", "alice") -> "GET\x1Falice" -> R0VUH2FsaWNl
        let pk = build_structured_partition_key(&[("user_id", "alice"), ("method", "GET")])
            .expect("valid key");
        assert_eq!(pk, b"GET\x1Falice");
        assert_eq!(BASE64.encode(&pk), "R0VUH2FsaWNl");

        // Rejects 0x1F inside dimension values (§4.2)
        assert!(build_structured_partition_key(&[("user_id", "bad\x1Fval")]).is_none());
        // Rejects empty dimension list
        assert!(build_structured_partition_key(&[]).is_none());
    }

    #[test]
    fn parse_ratelimit_policy_validates_params_and_deduplicates_case_insensitively() {
        let headers = headers_from(&[
            (
                "RateLimit-Policy",
                r#"burst;q=100;w=60, "BURST";q=200;w=120, zero_w;q=10;w=0, bw;q=1024;qu="content-bytes";w=3600;pk=:R0VU:"#,
            ),
            ("RateLimit-Policy", r#"conc;q=5;qu="concurrent-requests""#),
        ]);

        let policies = parse_ratelimit_policy_headers(&headers, false);
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].name, "burst");
        assert_eq!(policies[0].quota, 100);
        assert_eq!(policies[0].unit, QuotaUnit::Requests);
        assert_eq!(policies[0].window, Some(60));

        assert_eq!(policies[1].name, "bw");
        assert_eq!(policies[1].quota, 1024);
        assert_eq!(policies[1].unit, QuotaUnit::ContentBytes);
        assert_eq!(policies[1].window, Some(3600));
        assert_eq!(policies[1].partition_key.as_deref(), Some(b"GET".as_slice()));

        assert_eq!(policies[2].name, "conc");
        assert_eq!(policies[2].unit, QuotaUnit::ConcurrentRequests);
        assert_eq!(policies[2].window, None);
    }

    #[test]
    fn parse_ratelimit_headers_uses_draft12_a_w_c_and_rejects_draft11_r_t() {
        let headers = headers_from(&[
            ("RateLimit", r#"default;a=50;w=30;c=5;pk=:R0VU:, "second";a=0;w=0"#),
            ("RateLimit", r#""legacy";r=10;t=60"#), // missing required `a` -> ignored
            ("RateLimit", r#""badcost";a=10;w=5;c=-1"#), // negative `c` -> ignored
        ]);

        let limits = parse_ratelimit_headers(&headers, false);
        assert_eq!(limits.len(), 2);
        assert_eq!(
            limits[0],
            ServiceLimitItem {
                name: "default".into(),
                available_quota: 50,
                effective_window: Some(30),
                partition_key: Some(b"GET".to_vec()),
                cost: Some(5),
            }
        );
        assert_eq!(
            limits[1],
            ServiceLimitItem {
                name: "second".into(),
                available_quota: 0,
                effective_window: Some(0),
                partition_key: None,
                cost: None,
            }
        );
    }

    #[test]
    fn parse_ratelimit_partition_headers_parses_varying_and_fixed_dimensions() {
        let headers = headers_from(&[
            ("RateLimit-Partition", r#"api;user_id;method, "reads";user_id;method=GET"#),
            ("RateLimit-Partition", r#"API;method"#), // case-insensitive duplicate -> ignored
        ]);

        let parts = parse_ratelimit_partition_headers(&headers, false);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "api");
        assert_eq!(
            parts[0].dimensions,
            vec![
                ("user_id".into(), PartitionDimension::Varying),
                ("method".into(), PartitionDimension::Varying),
            ]
        );
        assert_eq!(parts[1].name, "reads");
        assert_eq!(
            parts[1].dimensions,
            vec![
                ("user_id".into(), PartitionDimension::Varying),
                ("method".into(), PartitionDimension::Fixed("GET".into())),
            ]
        );
    }

    #[test]
    fn cached_responses_ignore_all_ratelimit_headers() {
        let headers = headers_from(&[
            ("Age", "12"),
            ("RateLimit-Policy", "default;q=100;w=60"),
            ("RateLimit", "default;a=0;w=60"),
            ("RateLimit-Partition", "default;method"),
        ]);

        assert!(is_cached_response(&headers));
        assert!(parse_ratelimit_policy_headers(&headers, false).is_empty());
        assert!(parse_ratelimit_headers(&headers, false).is_empty());
        assert!(parse_ratelimit_partition_headers(&headers, false).is_empty());
    }

    #[test]
    fn tracker_method_partition_isolates_head_and_get_quotas() {
        let url = Url::parse("https://api.example/file.bin").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // HEAD is exhausted under policy "api" partitioned by ;method (pk = base64("HEAD"))
        let headers = headers_from(&[
            ("RateLimit-Policy", "API;q=10;w=60"),
            ("RateLimit-Partition", r#""api";method"#),
            ("RateLimit", "Api;a=0;w=30;pk=:SEVBRA==:"),
        ]);

        let wait = tracker.record_response_at(
            &url,
            &Method::HEAD,
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
            false,
            now,
        );
        assert_eq!(wait, Some(Duration::from_secs(30)));

        // HEAD must wait 30s
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::HEAD, now),
            Some(Duration::from_secs(30))
        );
        // GET belongs to a different partition ("GET") and is not blocked
        assert_eq!(tracker.compute_wait_delay(&url, &Method::GET, now), None);
    }

    #[test]
    fn tracker_fixed_method_filter_with_opaque_user_id_skips_other_methods() {
        let url = Url::parse("https://api.example/resource").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // Draft-12 §4.2: "reads";user_id;method=GET only applies to GET requests.
        let headers = headers_from(&[
            ("RateLimit-Partition", r#""reads";user_id;method=GET"#),
            ("RateLimit", r#""reads";a=0;w=25;pk=:R0VUH2FsaWNl:"#),
        ]);

        tracker.record_response_at(
            &url,
            &Method::GET,
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
            false,
            now,
        );

        // Not applicable to HEAD
        assert_eq!(tracker.compute_wait_delay(&url, &Method::HEAD, now), None);
        // Applicable to GET (opaque due to user_id, so conservatively waits)
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(25))
        );
    }

    #[test]
    fn tracker_honors_cost_parameter_and_caps_dos_windows() {
        let url = Url::parse("https://api.example/heavy").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // Remaining quota a=4 is smaller than request cost c=10 -> must wait capped window.
        let headers = headers_from(&[
            ("RateLimit-Policy", r#""heavy";q=100;w=60"#),
            ("RateLimit", r#""heavy";a=4;w=999999;c=10"#),
        ]);

        let wait =
            tracker.record_response_at(&url, &Method::GET, StatusCode::OK, &headers, false, now);
        assert_eq!(wait, Some(Duration::from_secs(MAX_RATELIMIT_WAIT_SECS)));
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(MAX_RATELIMIT_WAIT_SECS))
        );
    }

    #[test]
    fn tracker_preserves_content_bytes_rejection_wait_when_a_less_than_c() {
        let url = Url::parse("https://api.example/upload").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // Rejected content-bytes request keeps available quota intact (a=50) while cost c=100.
        let headers = headers_from(&[
            ("RateLimit-Policy", r#""bw";q=1000;qu="content-bytes";w=60"#),
            ("RateLimit", r#""bw";a=50;w=15;c=100"#),
        ]);

        let wait = tracker.record_response_at(
            &url,
            &Method::GET,
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
            false,
            now,
        );
        assert_eq!(wait, Some(Duration::from_secs(15)));
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn tracker_retry_after_takes_precedence_over_ratelimit_window() {
        let url = Url::parse("https://api.example/items").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        let headers = headers_from(&[
            ("Retry-After", "20"),
            ("RateLimit-Policy", r#""dynamic";q=100;w=60"#),
            ("RateLimit", r#""dynamic";a=0;w=40"#),
        ]);

        let wait = tracker.record_response_at(
            &url,
            &Method::GET,
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
            false,
            now,
        );
        assert_eq!(wait, Some(Duration::from_secs(20)));
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(20))
        );
    }

    #[test]
    fn tracker_preemptive_pacing_matches_appendix_a_2_2() {
        let url = Url::parse("https://api.example/items").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // Appendix A.2.2: "dynamic";q=100;w=60, RateLimit: "dynamic";a=9;w=50
        // pace_ms = (50 * 1000) / (9 + 1) = 5000ms
        let headers = headers_from(&[
            ("RateLimit-Policy", r#""dynamic";q=100;w=60"#),
            ("RateLimit", r#""dynamic";a=9;w=50"#),
        ]);

        let wait =
            tracker.record_response_at(&url, &Method::GET, StatusCode::OK, &headers, false, now);
        assert_eq!(wait, None);
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn parse_problem_body_extracts_draft12_problem_types() {
        let headers = headers_from(&[("Content-Type", "application/problem+json; charset=utf-8")]);
        let body = br#"{
            "type": "https://iana.org/assignments/http-problem-types#quota-exceeded",
            "title": "Quota exceeded",
            "violated-policies": ["daily", "bandwidth"]
        }"#;

        let summary = parse_ratelimit_problem_body(&headers, body).expect("problem summary");
        assert_eq!(summary, "quota-exceeded: Quota exceeded (violated-policies: daily, bandwidth)");
    }

    #[test]
    fn parse_sf_handles_escaped_strings_and_duplicate_params_last_wins() {
        let items = parse_sf_item_list(r#""a\"b\\c";a=1;a=7;w=10"#).expect("valid SF");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, r#"a"b\c"#);
        assert_eq!(
            items[0].params,
            vec![("a".into(), SfParamValue::Integer(7)), ("w".into(), SfParamValue::Integer(10)),]
        );
    }

    #[test]
    fn quota_unit_display_and_parsing_roundtrip() {
        assert_eq!(QuotaUnit::from_str_param("requests").to_string(), "requests");
        assert_eq!(QuotaUnit::from_str_param("request"), QuotaUnit::Requests);
        assert_eq!(QuotaUnit::from_str_param("content-bytes").to_string(), "content-bytes");
        assert_eq!(
            QuotaUnit::from_str_param("concurrent-requests").to_string(),
            "concurrent-requests"
        );
        assert_eq!(QuotaUnit::from_str_param("tokens").to_string(), "tokens");
    }

    #[test]
    fn tracker_cost_zero_does_not_divide_by_zero_and_cost_paces_remaining_requests() {
        let url = Url::parse("https://api.example/cost").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        // c=0 with a=10 and w=60 must not panic or block
        let zero_cost = headers_from(&[("RateLimit", "p;a=10;w=60;c=0")]);
        assert_eq!(
            tracker.record_response_at(&url, &Method::GET, StatusCode::OK, &zero_cost, false, now),
            None
        );
        assert_eq!(tracker.compute_wait_delay(&url, &Method::GET, now), None);

        // a=5, c=5 -> 1 remaining similar request over w=20 -> pace_ms = 20000 / 2 = 10s
        let one_left = headers_from(&[("RateLimit", "p;a=5;w=20;c=5")]);
        assert_eq!(
            tracker.record_response_at(&url, &Method::GET, StatusCode::OK, &one_left, false, now),
            None
        );
        assert_eq!(
            tracker.compute_wait_delay(&url, &Method::GET, now),
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn tracker_bounds_partition_storage_capacity() {
        let url = Url::parse("https://api.example/bounded").expect("valid url");
        let now = Instant::now();
        let mut tracker = RateLimitTracker::new();

        for i in 0..(MAX_PARTITIONS_PER_POLICY + 32) {
            let pk_b64 = BASE64.encode(format!("part-{i}").as_bytes());
            let rl = format!("p;a=0;w=10;pk=:{pk_b64}:");
            let headers = headers_from(&[("RateLimit", &rl)]);
            tracker.record_response_at(
                &url,
                &Method::GET,
                StatusCode::TOO_MANY_REQUESTS,
                &headers,
                false,
                now,
            );
        }

        let key_ref = OriginKeyRef::from_url(&url).expect("origin key");
        let origin_state = tracker.origins.get(&key_ref as &dyn OriginKeyView).expect("origin");
        let policy_state = origin_state.policies.get("p").expect("policy");
        assert!(policy_state.deadlines.by_partition.len() <= MAX_PARTITIONS_PER_POLICY);
    }
}
