use std::fmt::Write;
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
};

use reqwest::{
    Response, StatusCode,
    header::{AGE, CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use url::Url;

use crate::{Args, PermanentError, parse_decimal, parse_http_date, terminal_safe};

/// Maximum sleep duration honored from `RateLimit` `t` or `Retry-After` headers
/// (draft-ietf-httpapi-ratelimit-headers-11 §8.5.1 `DoS` mitigation: ten minutes).
pub const MAX_RATELIMIT_WAIT_SECS: u64 = 600;

/// Quota units registered in draft-ietf-httpapi-ratelimit-headers-11 §3.1.2 / §10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QuotaUnit {
    Requests,
    ContentBytes,
    ConcurrentRequests,
    Other(String),
}

impl QuotaUnit {
    fn from_str_param(s: &str) -> Self {
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

/// Parsed Quota Policy Item from `RateLimit-Policy` (§3.1).
#[derive(Debug, Clone)]
pub(crate) struct QuotaPolicyItem {
    name: String,
    quota: u64,
    unit: QuotaUnit,
    window: Option<u64>,
    partition_key: Option<String>,
}

/// Parsed Service Limit Item from `RateLimit` (§4.1).
#[derive(Debug, Clone)]
pub(crate) struct ServiceLimitItem {
    name: String,
    remaining: u64,
    effective_window: Option<u64>,
    partition_key: Option<String>,
}

#[derive(Debug, Clone)]
enum SfParamValue {
    Integer(i64),
    String(String),
    ByteSeq(String),
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct SfItem {
    value: String,
    params: Vec<(String, SfParamValue)>,
}

/// Parse an RFC 9651 Structured Field List of String Items with parameters,
/// used by `RateLimit-Policy` (§3) and `RateLimit` (§4).
/// Returns `None` if the header value is syntactically malformed (§7:
/// "Malformed `RateLimit` header fields MUST be ignored").
pub fn parse_sf_string_item_list(input: &str) -> Option<Vec<SfItem>> {
    let bytes = input.as_bytes();
    let mut pos = 0;
    let mut items = Vec::new();

    let skip_sp = |pos: &mut usize| {
        while *pos < bytes.len() && bytes[*pos] == b' ' {
            *pos += 1;
        }
    };
    let skip_ows = |pos: &mut usize| {
        while *pos < bytes.len() && (bytes[*pos] == b' ' || bytes[*pos] == b'\t') {
            *pos += 1;
        }
    };

    skip_ows(&mut pos);
    if pos >= bytes.len() {
        return None;
    }

    while pos < bytes.len() {
        // Bare item MUST be an SF String: DQUOTE *chr DQUOTE
        if bytes[pos] != b'"' {
            return None;
        }
        pos += 1;
        let mut item_str = String::new();
        let mut closed = false;
        while pos < bytes.len() {
            let b = bytes[pos];
            if b == b'\\' {
                pos += 1;
                if pos >= bytes.len() {
                    return None;
                }
                let esc = bytes[pos];
                if esc != b'"' && esc != b'\\' {
                    return None;
                }
                item_str.push(esc as char);
                pos += 1;
            } else if b == b'"' {
                pos += 1;
                closed = true;
                break;
            } else if (0x20..=0x7e).contains(&b) {
                item_str.push(b as char);
                pos += 1;
            } else {
                return None;
            }
        }
        if !closed {
            return None;
        }

        // Parse parameters: *( OWS ";" *SP param-key [ "=" param-value ] )
        let mut params: Vec<(String, SfParamValue)> = Vec::new();
        loop {
            let saved = pos;
            skip_ows(&mut pos);
            if pos >= bytes.len() || bytes[pos] != b';' {
                pos = saved;
                break;
            }
            pos += 1; // consume ';'
            skip_sp(&mut pos);

            // key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
            if pos >= bytes.len() {
                return None;
            }
            let first = bytes[pos];
            if !(first.is_ascii_lowercase() || first == b'*') {
                return None;
            }
            let key_start = pos;
            pos += 1;
            while pos < bytes.len() {
                let c = bytes[pos];
                if c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, b'_' | b'-' | b'.' | b'*')
                {
                    pos += 1;
                } else {
                    break;
                }
            }
            let key = std::str::from_utf8(&bytes[key_start..pos]).ok()?.to_string();

            let val = if pos < bytes.len() && bytes[pos] == b'=' {
                pos += 1; // consume '='
                if pos >= bytes.len() {
                    return None;
                }
                match bytes[pos] {
                    b'"' => {
                        pos += 1;
                        let mut s = String::new();
                        let mut str_closed = false;
                        while pos < bytes.len() {
                            let b = bytes[pos];
                            if b == b'\\' {
                                pos += 1;
                                if pos >= bytes.len() {
                                    return None;
                                }
                                let esc = bytes[pos];
                                if esc != b'"' && esc != b'\\' {
                                    return None;
                                }
                                s.push(esc as char);
                                pos += 1;
                            } else if b == b'"' {
                                pos += 1;
                                str_closed = true;
                                break;
                            } else if (0x20..=0x7e).contains(&b) {
                                s.push(b as char);
                                pos += 1;
                            } else {
                                return None;
                            }
                        }
                        if !str_closed {
                            return None;
                        }
                        SfParamValue::String(s)
                    }
                    b':' => {
                        pos += 1;
                        let start = pos;
                        while pos < bytes.len() && bytes[pos] != b':' {
                            let b = bytes[pos];
                            if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
                                return None;
                            }
                            pos += 1;
                        }
                        if pos >= bytes.len() || bytes[pos] != b':' {
                            return None;
                        }
                        let b64 = std::str::from_utf8(&bytes[start..pos]).ok()?.to_string();
                        pos += 1; // consume closing ':'
                        SfParamValue::ByteSeq(b64)
                    }
                    b'?' => {
                        pos += 1;
                        if pos >= bytes.len() || (bytes[pos] != b'0' && bytes[pos] != b'1') {
                            return None;
                        }
                        pos += 1;
                        SfParamValue::Other
                    }
                    b'-' | b'0'..=b'9' => {
                        let num_start = pos;
                        if bytes[pos] == b'-' {
                            pos += 1;
                        }
                        let digits_start = pos;
                        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                            pos += 1;
                        }
                        if pos == digits_start {
                            return None;
                        }
                        if pos < bytes.len() && bytes[pos] == b'.' {
                            pos += 1;
                            let frac_start = pos;
                            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                                pos += 1;
                            }
                            if pos == frac_start {
                                return None;
                            }
                            SfParamValue::Other
                        } else {
                            let num_str = std::str::from_utf8(&bytes[num_start..pos]).ok()?;
                            let n = num_str.parse::<i64>().ok()?;
                            SfParamValue::Integer(n)
                        }
                    }
                    c if c.is_ascii_alphabetic() || c == b'*' => {
                        // SF Token
                        pos += 1;
                        while pos < bytes.len() {
                            let b = bytes[pos];
                            if b.is_ascii_alphanumeric()
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
                            {
                                pos += 1;
                            } else {
                                break;
                            }
                        }
                        SfParamValue::Other
                    }
                    _ => return None,
                }
            } else {
                // Boolean true parameter
                SfParamValue::Other
            };

            // RFC 9651 §3.1.2: duplicate parameter keys overwrite earlier ones
            if let Some(existing) = params.iter_mut().find(|(k, _)| k == &key) {
                existing.1 = val;
            } else {
                params.push((key, val));
            }
        }

        items.push(SfItem { value: item_str, params });

        skip_ows(&mut pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b',' {
            return None;
        }
        pos += 1; // consume ','
        skip_ows(&mut pos);
        if pos >= bytes.len() {
            return None; // trailing comma is invalid in SF List
        }
    }

    if items.is_empty() { None } else { Some(items) }
}

/// Check whether response came from an HTTP cache (`Age > 0`).
/// Per draft-ietf-httpapi-ratelimit-headers-11 §7.3, `RateLimit` header fields
/// SHOULD be ignored on responses with a positive `current_age`.
pub fn is_cached_response(headers: &HeaderMap) -> bool {
    headers
        .get(AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_decimal(s.trim()))
        .is_some_and(|age| age > 0)
}

/// Parse all `RateLimit-Policy` header fields in `headers` (§3).
/// Malformed header fields are ignored (§7).
pub fn parse_ratelimit_policy_headers(headers: &HeaderMap, debug: bool) -> Vec<QuotaPolicyItem> {
    if is_cached_response(headers) {
        if debug {
            eprintln!("[DEBUG] RateLimit-Policy: ignoring headers on cached response (Age > 0)");
        }
        return Vec::new();
    }

    let mut policies = Vec::new();
    for val in headers.get_all("ratelimit-policy") {
        let Ok(s) = val.to_str() else {
            continue;
        };
        let Some(sf_items) = parse_sf_string_item_list(s) else {
            if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Policy: ignoring malformed header '{}'",
                    terminal_safe(s)
                );
            }
            continue;
        };

        for item in sf_items {
            let mut q: Option<u64> = None;
            let mut qu = QuotaUnit::Requests;
            let mut w: Option<u64> = None;
            let mut pk: Option<String> = None;
            let mut valid = true;

            for (k, v) in item.params {
                match k.as_str() {
                    "q" => match v {
                        // §3.1.1: "q" MUST be a non-negative Integer
                        SfParamValue::Integer(n) if n >= 0 => q = Some(n as u64),
                        _ => {
                            valid = false;
                            break;
                        }
                    },
                    "qu" => {
                        // §3.1.2: "qu" MUST be a String
                        if let SfParamValue::String(ref unit_str) = v {
                            qu = QuotaUnit::from_str_param(unit_str);
                        } else {
                            valid = false;
                            break;
                        }
                    }
                    "w" => match v {
                        // §3.1.3: "w" MUST be a non-negative, non-zero Integer
                        SfParamValue::Integer(n) if n > 0 => w = Some(n as u64),
                        _ => {
                            valid = false;
                            break;
                        }
                    },
                    "pk" => {
                        // §3.1.4: "pk" MUST be a Byte Sequence
                        if let SfParamValue::ByteSeq(b) = v {
                            pk = Some(b);
                        } else {
                            valid = false;
                            break;
                        }
                    }
                    _ => {} // Other/vendor parameters are allowed and ignored (§3.1)
                }
            }

            if let (true, Some(quota)) = (valid, q) {
                policies.push(QuotaPolicyItem {
                    name: item.value,
                    quota,
                    unit: qu,
                    window: w,
                    partition_key: pk,
                });
            } else if debug {
                eprintln!(
                    "[DEBUG] RateLimit-Policy: ignoring invalid policy item '{}'",
                    terminal_safe(&item.value)
                );
            }
        }
    }
    policies
}

/// Parse all `RateLimit` header fields in `headers` (§4).
/// If any `RateLimit` header field is malformed, it is ignored (§7).
pub fn parse_ratelimit_headers(headers: &HeaderMap, debug: bool) -> Vec<ServiceLimitItem> {
    if is_cached_response(headers) {
        if debug {
            eprintln!("[DEBUG] RateLimit: ignoring headers on cached response (Age > 0)");
        }
        return Vec::new();
    }

    let mut limits = Vec::new();
    for val in headers.get_all("ratelimit") {
        let Ok(s) = val.to_str() else {
            continue;
        };
        let Some(sf_items) = parse_sf_string_item_list(s) else {
            if debug {
                eprintln!("[DEBUG] RateLimit: ignoring malformed header '{}'", terminal_safe(s));
            }
            continue;
        };

        let mut header_items = Vec::with_capacity(sf_items.len());
        let mut header_valid = true;

        for item in sf_items {
            let mut r: Option<u64> = None;
            let mut t: Option<u64> = None;
            let mut pk: Option<String> = None;

            for (k, v) in item.params {
                match k.as_str() {
                    "r" => match v {
                        // §4.1.1: "r" is a REQUIRED non-negative Integer
                        SfParamValue::Integer(n) if n >= 0 => r = Some(n as u64),
                        _ => {
                            header_valid = false;
                            break;
                        }
                    },
                    "t" => match v {
                        // §4.1.2: "t" is an OPTIONAL non-negative Integer
                        SfParamValue::Integer(n) if n >= 0 => t = Some(n as u64),
                        _ => {
                            header_valid = false;
                            break;
                        }
                    },
                    "pk" => {
                        // §4.1.3: "pk" MUST be a Byte Sequence
                        if let SfParamValue::ByteSeq(b) = v {
                            pk = Some(b);
                        } else {
                            header_valid = false;
                            break;
                        }
                    }
                    _ => {} // Other/vendor parameters are allowed and ignored (§4.1)
                }
            }

            if !header_valid {
                break;
            }
            let Some(remaining) = r else {
                header_valid = false;
                break;
            };

            header_items.push(ServiceLimitItem {
                name: item.value,
                remaining,
                effective_window: t,
                partition_key: pk,
            });
        }

        if header_valid {
            limits.extend(header_items);
        } else if debug {
            eprintln!(
                "[DEBUG] RateLimit: ignoring malformed service limit item in '{}'",
                terminal_safe(s)
            );
        }
    }
    limits
}

/// Parse `Retry-After` (RFC 9110 §10.2.3) as either `delay-seconds` or `HTTP-date`.
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

/// Parse an RFC 9457 Problem Details JSON body for the three problem types defined
/// in draft-ietf-httpapi-ratelimit-headers-11 §5 (`quota-exceeded`,
/// `temporary-reduced-capacity`, `abnormal-usage-detected`).
pub fn parse_ratelimit_problem_body(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let ct = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media_type = ct.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/problem+json") {
        return None;
    }
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    let prob_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let short_type = match prob_type {
        "https://iana.org/assignments/http-problem-types#quota-exceeded" => Some("quota-exceeded"),
        "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity" => {
            Some("temporary-reduced-capacity")
        }
        "https://iana.org/assignments/http-problem-types#abnormal-usage-detected" => {
            Some("abnormal-usage-detected")
        }
        _ => None,
    };
    let title = val.get("title").and_then(|v| v.as_str());
    let violated: Vec<String> = val
        .get("violated-policies")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(terminal_safe)).collect())
        .unwrap_or_default();

    if short_type.is_none() && violated.is_empty() && title.is_none() {
        return None;
    }

    let mut summary = String::new();
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
    if !violated.is_empty() {
        if !summary.is_empty() {
            summary.push(' ');
        }
        let _ = write!(summary, "(violated-policies: {})", violated.join(", "));
    }
    Some(summary)
}

/// Per-origin `RateLimit` state tracker implementing client behavior from
/// draft-ietf-httpapi-ratelimit-headers-11 §7.
#[derive(Debug, Default)]
pub struct RateLimitTracker {
    /// Known quota policies keyed by `(origin_key, policy_name)`.
    policies: HashMap<(String, String), QuotaPolicyItem>,
    /// Earliest `Instant` at which the next request to `(origin_key, partition_key)` may be sent.
    next_allowed_by_partition: HashMap<(String, Option<String>), Instant>,
    /// Earliest `Instant` at which the next request to `origin_key` may be sent (any partition).
    next_allowed_by_origin: HashMap<String, Instant>,
}

impl RateLimitTracker {
    fn origin_key(url: &Url) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port_or_known_default().unwrap_or(443);
        Some(format!("{}://{}:{}", url.scheme(), host, port))
    }

    /// Wait if a previous response from this origin advertised an active rate-limit window.
    pub async fn wait_before_request(&mut self, url: &Url, args: &Args) {
        let Some(origin) = Self::origin_key(url) else {
            return;
        };
        let now = Instant::now();
        let mut target: Option<Instant> = self.next_allowed_by_origin.get(&origin).copied();

        for ((o, _pk), &inst) in &self.next_allowed_by_partition {
            if o == &origin {
                target = Some(target.map_or(inst, |cur| cur.max(inst)));
            }
        }

        if let Some(deadline) = target
            && deadline > now
        {
            let delay = deadline - now;
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

    /// Update state from response headers and return the recommended wait `Duration`
    /// (if `Retry-After` is present or any policy has `r == 0`).
    ///
    /// Implements §7:
    /// - If both `Retry-After` and `RateLimit` are present, `Retry-After` MUST take
    ///   precedence and `t` MAY be ignored.
    /// - When `r == 0` and `t` is present, schedules the next request after `t` seconds
    ///   (capped at `MAX_RATELIMIT_WAIT_SECS` per §8.5.1).
    /// - When `r > 0` and `t > 0` for request-based quotas, spaces subsequent requests
    ///   smoothly only when remaining quota is low relative to the policy or window.
    pub fn record_response(
        &mut self,
        url: &Url,
        headers: &HeaderMap,
        args: &Args,
    ) -> Option<Duration> {
        let origin = Self::origin_key(url)?;
        let now = Instant::now();

        let policies = parse_ratelimit_policy_headers(headers, args.debug);
        for p in policies {
            if args.debug {
                eprintln!(
                    "[DEBUG] RateLimit-Policy: '{}' q={} qu={:?} w={:?} pk={:?}",
                    terminal_safe(&p.name),
                    p.quota,
                    p.unit,
                    p.window,
                    p.partition_key
                );
            }
            self.policies.insert((origin.clone(), p.name.clone()), p);
        }

        let limits = parse_ratelimit_headers(headers, args.debug);
        let retry_after = parse_retry_after(headers);

        // §7: "If a response contains both the RateLimit and Retry-After fields,
        // the Retry-After field MUST take precedence and the effective window MAY be ignored."
        if let Some(ra_dur) = retry_after {
            if args.debug {
                eprintln!(
                    "[DEBUG] Retry-After takes precedence over RateLimit: {}s",
                    ra_dur.as_secs()
                );
            }
            let deadline = now + ra_dur;
            self.next_allowed_by_origin
                .entry(origin)
                .and_modify(|e| *e = (*e).max(deadline))
                .or_insert(deadline);
            return Some(ra_dur);
        }

        let mut max_zero_quota_wait: Option<Duration> = None;

        for item in limits {
            let policy = self.policies.get(&(origin.clone(), item.name.clone()));
            let unit = policy.map_or(&QuotaUnit::Requests, |p| &p.unit);
            let pk =
                item.partition_key.clone().or_else(|| policy.and_then(|p| p.partition_key.clone()));

            if args.debug {
                eprintln!(
                    "[DEBUG] RateLimit: '{}' r={} t={:?} pk={:?} (unit={:?})",
                    terminal_safe(&item.name),
                    item.remaining,
                    item.effective_window,
                    pk,
                    unit
                );
            }

            let Some(raw_t) = item.effective_window else {
                continue;
            };
            // §8.5.1 DoS protection: cap unreasonably large effective windows
            let capped_t = raw_t.min(MAX_RATELIMIT_WAIT_SECS);
            if raw_t > MAX_RATELIMIT_WAIT_SECS && args.debug {
                eprintln!(
                    "[DEBUG] RateLimit: capping effective window t={raw_t}s to {MAX_RATELIMIT_WAIT_SECS}s"
                );
            }

            if item.remaining == 0 {
                let wait = Duration::from_secs(capped_t);
                let deadline = now + wait;
                self.next_allowed_by_partition
                    .entry((origin.clone(), pk))
                    .and_modify(|e| *e = (*e).max(deadline))
                    .or_insert(deadline);
                max_zero_quota_wait = Some(max_zero_quota_wait.map_or(wait, |cur| cur.max(wait)));
            } else if *unit == QuotaUnit::Requests && capped_t > 0 {
                // Pre-emptive pacing (§7): if remaining requests are scarce and
                // evenly spacing them over `t` requires >= 1s per request (e.g. §B.2.2
                // "dynamic";q=100;w=60 with r=9;t=50), pace only when policy indicates
                // throttling or remaining <= 1.
                let is_throttled_down = policy
                    .and_then(|p| {
                        let w = p.window?;
                        // Compare available rate (r / t) against nominal policy rate (q / w)
                        Some(
                            u128::from(item.remaining) * u128::from(w)
                                < u128::from(p.quota) * u128::from(capped_t),
                        )
                    })
                    .unwrap_or(item.remaining == 1);

                if is_throttled_down && capped_t >= item.remaining {
                    let pace_ms = (capped_t * 1000) / (item.remaining + 1);
                    if pace_ms > 0 {
                        let deadline = now + Duration::from_millis(pace_ms);
                        self.next_allowed_by_partition
                            .entry((origin.clone(), pk))
                            .and_modify(|e| *e = (*e).max(deadline))
                            .or_insert(deadline);
                    }
                }
            }
        }

        max_zero_quota_wait
    }
}

/// Build an `HttpClientError` or `HttpRateLimited` error from a non-2xx `Response`,
/// updating `rl_tracker` and extracting any RFC 9457 rate-limit problem details (§5).
pub async fn handle_error_response(
    response: Response,
    url: &Url,
    args: &Args,
    rl_tracker: &mut RateLimitTracker,
) -> anyhow::Error {
    let status = response.status();
    let headers = response.headers().clone();
    let wait = rl_tracker.record_response(url, &headers, args);

    let is_problem_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/problem+json"));

    let problem_detail = if is_problem_json {
        // Read up to 16 KiB for the RFC 9457 problem details payload
        let mut buf = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(Ok(chunk)) = stream.next().await {
            if buf.len() + chunk.len() > 16 * 1024 {
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
pub fn extract_ratelimit_wait(err: &anyhow::Error) -> Option<Duration> {
    if let Some(PermanentError::HttpRateLimited { wait: Some(w), .. }) =
        err.downcast_ref::<PermanentError>()
    {
        return Some(*w);
    }
    None
}
