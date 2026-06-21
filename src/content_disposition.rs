// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sami Farin
//
// Based on 62330e3d606cbe32219300422f5922f55bedb3a2 commit
// from https://github.com/y0zong/content-disposition
//
// More tests at http://test.greenbytes.de/tech/tc2231/
//
// Adapted for local use to fix RFC 6266 precedence issues.

use charset::Charset;
use std::collections::{BTreeMap, HashMap};

/// The possible disposition types in a Content-Disposition header.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum DispositionType {
    #[default]
    Inline,
    Attachment,
    FormData,
    Extension(String),
}

/// Convert the string represented disposition type to enum.
fn parse_disposition_type(disposition: &str) -> DispositionType {
    match &disposition.to_lowercase()[..] {
        "inline" => DispositionType::Inline,
        "attachment" => DispositionType::Attachment,
        "form-data" => DispositionType::FormData,
        extension => DispositionType::Extension(extension.to_string()),
    }
}

/// A struct to hold a more structured representation of the Content-Disposition header.
#[derive(Debug, Clone, Default)]
pub struct ParsedContentDisposition {
    pub disposition: DispositionType,
    pub params: BTreeMap<String, String>,
}

impl ParsedContentDisposition {
    #[allow(dead_code)]
    pub fn name(&self) -> Option<String> {
        self.params.get("name").cloned()
    }
    #[allow(dead_code)]
    pub fn filename_full(&self) -> Option<String> {
        self.params.get("filename").cloned()
    }
    #[allow(dead_code)]
    pub fn filename(&self) -> Option<(String, Option<String>)> {
        let clone = self.params.get("filename").cloned();
        match clone {
            Some(c) => {
                let mut arr: Vec<&str> = c.split(".").collect();
                let last = arr.pop();
                let first = arr.join(".");
                Some(match last {
                    Some(l) => (first, Some(l.to_owned())),
                    None => (first, None),
                })
            }
            None => None,
        }
    }
}

/// Process RFC 7230 §3.2.6 quoted-pair sequences inside a quoted-string body.
/// Inside a quoted-string, `\X` represents the literal character X for any X.
/// Allocates only when a backslash is present.
fn unquote(inner: &str) -> String {
    if !inner.contains('\\') {
        return inner.to_string();
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // \X -> X; a trailing lone '\' is kept literal
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn parse_content_disposition(header: &str) -> ParsedContentDisposition {
    let params = parse_param_content(header);
    let disposition = parse_disposition_type(&params.value);
    ParsedContentDisposition { disposition, params: params.params }
}

/// Used to store params for content-type and content-disposition
struct ParamContent {
    value: String,
    params: BTreeMap<String, String>,
}

/// Split on semicolons, but respect quoted strings and quoted-pair escapes.
/// RFC 6266 Section 4.1: semicolons inside quoted-string values must not split parameters.
/// RFC 7230 Section 3.2.6: inside a quoted-string, a backslash escapes the next
/// character (so `\"` does not terminate the string, and `\\` is a literal backslash).
fn split_semicolon_aware(content: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escape = false;

    for (i, ch) in content.char_indices() {
        if escape {
            // Previous char inside a quoted-string was a backslash;
            // consume this char literally regardless of what it is.
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escape = true,
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                parts.push(&content[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    // Don't forget the last segment
    parts.push(&content[start..]);
    parts
}

fn parse_param_content(content: &str) -> ParamContent {
    let mut tokens = split_semicolon_aware(content).into_iter();
    // There must be at least one token produced, even if it's empty.
    let value = tokens.next().unwrap_or("").trim();
    let mut map: BTreeMap<String, String> = tokens
        .filter_map(|kv| {
            kv.find('=').map(|idx| {
                let key = kv[0..idx].trim().to_lowercase();
                let raw = kv[idx + 1..].trim();
                // RFC 7230 §3.2.6: a quoted-string strips outer DQUOTE and
                // resolves quoted-pair escapes (\X -> X) inside the body.
                let value = if raw.starts_with('"') && raw.ends_with('"') && raw.len() > 1 {
                    unquote(&raw[1..raw.len() - 1])
                } else {
                    raw.to_string()
                };
                (key, value)
            })
        })
        .collect();

    // Decode charset encoding, as described in RFC 2184, Section 4.
    let decode_key_list: Vec<String> =
        map.keys().filter_map(|k| k.strip_suffix('*')).map(String::from).collect();

    let encodings = compute_parameter_encodings(&map, &decode_key_list);

    for (k, (e, strip)) in encodings {
        let key = format!("{}*", k);
        // Ensure we remove the extended key whether the charset is recognized or not
        if let Some(percent_encoded_value) = map.remove(&key) {
            let encoded_value = if strip {
                percent_decode(percent_encoded_value.splitn(3, '\'').nth(2).unwrap_or(""))
            } else {
                percent_decode(&percent_encoded_value)
            };

            let decoded_value =
                if let Some(charset) = Charset::for_label_no_replacement(e.as_bytes()) {
                    charset.decode_without_bom_handling(&encoded_value).0.into_owned()
                } else {
                    // Fallback: Default to UTF-8 lossy decoding for unrecognized/missing charsets
                    String::from_utf8_lossy(&encoded_value).into_owned()
                };

            // This insert will now correctly overwrite existing keys (e.g., 'filename')
            map.insert(k, decoded_value);
        }
    }

    // Unwrap parameter value continuations, as described in RFC 2184, Section 3.
    let unwrap_key_list: Vec<String> =
        map.keys().filter_map(|k| k.strip_suffix("*0")).map(String::from).collect();

    for unwrap_key in unwrap_key_list {
        let mut unwrapped_value = String::new();
        let mut index = 0;
        while let Some(wrapped_value_part) = map.remove(&format!("{}*{}", &unwrap_key, index)) {
            index += 1;
            unwrapped_value.push_str(&wrapped_value_part);
        }
        let _old_value = map.insert(unwrap_key, unwrapped_value);
    }

    ParamContent { value: value.into(), params: map }
}

fn compute_parameter_encodings(
    map: &BTreeMap<String, String>,
    decode_key_list: &Vec<String>,
) -> HashMap<String, (String, bool)> {
    let mut encodings: HashMap<String, (String, bool)> = HashMap::new();
    for decode_key in decode_key_list {
        if let Some(unwrap_key) = decode_key.strip_suffix("*0") {
            let encoding =
                map.get(&format!("{}*", decode_key)).unwrap().split('\'').next().unwrap_or("");
            let continuation_prefix = format!("{}*", unwrap_key);
            for continuation_key in decode_key_list {
                if continuation_key.starts_with(&continuation_prefix) {
                    encodings.insert(
                        continuation_key.clone(),
                        (encoding.to_string(), continuation_key == decode_key),
                    );
                }
            }
        } else if !encodings.contains_key(decode_key) {
            let encoding = map
                .get(&format!("{}*", decode_key))
                .unwrap()
                .split('\'')
                .next()
                .unwrap_or("")
                .to_string();
            let old_value = encodings.insert(decode_key.clone(), (encoding, true));
            assert!(old_value.is_none());
        }
    }
    encodings
}

fn percent_decode(encoded: &str) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.bytes();
    let mut next = bytes.next();
    while next.is_some() {
        let b = next.unwrap();
        if b != b'%' {
            decoded.push(b);
            next = bytes.next();
            continue;
        }

        let top = match bytes.next() {
            Some(n) if n.is_ascii_hexdigit() => n,
            n => {
                decoded.push(b);
                next = n;
                continue;
            }
        };
        let bottom = match bytes.next() {
            Some(n) if n.is_ascii_hexdigit() => n,
            n => {
                decoded.push(b);
                decoded.push(top);
                next = n;
                continue;
            }
        };
        let decoded_byte = (hex_to_nybble(top) << 4) | hex_to_nybble(bottom);
        decoded.push(decoded_byte);

        next = bytes.next();
    }
    decoded
}

fn hex_to_nybble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // RFC 6266 Conformance Test Suite
    // ==========================================================================
    //
    // CONFORMANCE SUMMARY:
    //
    // ✓ PASSING (RFC 6266 Compliant):
    //   - Disposition type case insensitivity (Section 4.2)
    //   - Parameter name case insensitivity (Section 4.3)
    //   - filename* takes precedence over filename (Section 4.3)
    //   - RFC 5987 encoding (charset'language'value format)
    //   - RFC 2184 parameter continuations (filename*0, filename*1, etc.)
    //   - Whitespace handling around delimiters (Section 4.1)
    //   - Multiple charset support (UTF-8, ISO-8859-1)
    //   - Extension disposition types
    //   - Semicolons inside quoted strings (Section 4.1)
    //   - All examples from RFC 6266 Section 5
    //
    // ✗ KNOWN NON-CONFORMANCE:
    //   - Backslash escape sequences in quoted strings not handled
    //     (Note: RFC 6266 Appendix D advises avoiding backslashes anyway)
    //
    // ==========================================================================

    // --------------------------------------------------------------------------
    // Section 4.2: Disposition Type (case-insensitive)
    // --------------------------------------------------------------------------

    #[test]
    fn test_disposition_type_inline_lowercase() {
        let dis = parse_content_disposition("inline");
        assert_eq!(dis.disposition, DispositionType::Inline);
    }

    #[test]
    fn test_disposition_type_inline_uppercase() {
        // RFC 6266 Section 4.2: "inline" is case-insensitive
        let dis = parse_content_disposition("INLINE");
        assert_eq!(dis.disposition, DispositionType::Inline);
    }

    #[test]
    fn test_disposition_type_inline_mixed_case() {
        let dis = parse_content_disposition("InLiNe");
        assert_eq!(dis.disposition, DispositionType::Inline);
    }

    #[test]
    fn test_disposition_type_attachment_lowercase() {
        let dis = parse_content_disposition("attachment");
        assert_eq!(dis.disposition, DispositionType::Attachment);
    }

    #[test]
    fn test_disposition_type_attachment_uppercase() {
        // RFC 6266 Section 4.2: "attachment" is case-insensitive
        let dis = parse_content_disposition("ATTACHMENT");
        assert_eq!(dis.disposition, DispositionType::Attachment);
    }

    #[test]
    fn test_disposition_type_attachment_mixed_case() {
        let dis = parse_content_disposition("Attachment");
        assert_eq!(dis.disposition, DispositionType::Attachment);
    }

    #[test]
    fn test_disposition_type_form_data() {
        let dis = parse_content_disposition("form-data");
        assert_eq!(dis.disposition, DispositionType::FormData);
    }

    #[test]
    fn test_disposition_type_form_data_uppercase() {
        let dis = parse_content_disposition("FORM-DATA");
        assert_eq!(dis.disposition, DispositionType::FormData);
    }

    #[test]
    fn test_disposition_type_unknown_extension() {
        // RFC 6266 Section 4.2: Unknown types -> treated as extension
        let dis = parse_content_disposition("custom-type");
        assert_eq!(dis.disposition, DispositionType::Extension("custom-type".to_string()));
    }

    // --------------------------------------------------------------------------
    // Section 4.3: Filename Parameter - Case Insensitivity
    // --------------------------------------------------------------------------

    #[test]
    fn test_parameter_name_case_insensitive_filename() {
        // RFC 6266 Section 4.3: "filename" matched case-insensitively
        let dis = parse_content_disposition(r#"attachment; FILENAME="test.txt""#);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_parameter_name_case_insensitive_filename_mixed() {
        let dis = parse_content_disposition(r#"attachment; FileName="test.txt""#);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_parameter_name_case_insensitive_filename_star() {
        // RFC 6266 Section 4.3: "filename*" matched case-insensitively
        let dis = parse_content_disposition("attachment; FILENAME*=UTF-8''test.txt");
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    // --------------------------------------------------------------------------
    // Section 4.3: filename* Takes Precedence Over filename
    // "When both 'filename' and 'filename*' are present in a single header
    //  field value, recipients SHOULD pick 'filename*' and ignore 'filename'."
    // --------------------------------------------------------------------------

    #[test]
    fn test_filename_asterisk_precedence_standard_order() {
        // filename before filename* (recommended order per Appendix D)
        let header = r#"attachment; filename="fallback.txt"; filename*=UTF-8''preferred.txt"#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"preferred.txt".to_string()));
    }

    #[test]
    fn test_filename_asterisk_precedence_reversed_order() {
        // filename* before filename (less common, but must still work)
        let header = r#"attachment; filename*=UTF-8''preferred.txt; filename="fallback.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"preferred.txt".to_string()));
    }

    #[test]
    fn test_filename_only_no_asterisk() {
        // When only filename is present, use it
        let header = r#"attachment; filename="only_regular.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"only_regular.txt".to_string()));
    }

    #[test]
    fn test_filename_asterisk_only() {
        // When only filename* is present, use it
        let header = "attachment; filename*=UTF-8''only_extended.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"only_extended.txt".to_string()));
    }

    // --------------------------------------------------------------------------
    // RFC 5987 Encoding (ext-value format: charset'language'value)
    // --------------------------------------------------------------------------

    #[test]
    fn test_rfc5987_utf8_encoding() {
        // Basic UTF-8 encoding
        let header = "attachment; filename*=UTF-8''simple.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"simple.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_utf8_lowercase() {
        // Charset is case-insensitive
        let header = "attachment; filename*=utf-8''simple.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"simple.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_percent_encoded_space() {
        // %20 = space
        let header = "attachment; filename*=UTF-8''hello%20world.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"hello world.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_euro_sign() {
        // RFC 6266 Section 5 example: Euro sign U+20AC = %E2%82%AC
        let header = "attachment; filename*=UTF-8''%e2%82%ac%20rates";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"€ rates".to_string()));
    }

    #[test]
    fn test_rfc5987_checkmark() {
        // Checkmark U+2713 = %E2%9C%93
        let header = r#"attachment; filename="old.txt"; filename*=UTF-8''%E2%9C%93.txt"#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"✓.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_with_language_tag() {
        // Format: charset'language'value - language tag is optional
        let header = "attachment; filename*=UTF-8'en'document.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"document.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_iso8859_1() {
        // ISO-8859-1 encoding (Latin-1)
        // é in ISO-8859-1 is 0xE9
        let header = "attachment; filename*=ISO-8859-1''caf%E9.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"café.txt".to_string()));
    }

    #[test]
    fn test_rfc5987_japanese_utf8() {
        // Japanese characters: 日本語 = E6 97 A5 E6 9C AC E8 AA 9E
        let header = "attachment; filename*=UTF-8''%E6%97%A5%E6%9C%AC%E8%AA%9E.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"日本語.txt".to_string()));
    }

    // --------------------------------------------------------------------------
    // Section 5: Examples from RFC 6266
    // --------------------------------------------------------------------------

    #[test]
    fn test_rfc6266_example_1_simple_attachment() {
        // "Content-Disposition: Attachment; filename=example.html"
        let header = "Attachment; filename=example.html";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"example.html".to_string()));
    }

    #[test]
    fn test_rfc6266_example_2_inline_quoted() {
        // "Content-Disposition: INLINE; FILENAME= "an example.html""
        let header = r#"INLINE; FILENAME= "an example.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Inline);
        assert_eq!(dis.params.get("filename"), Some(&"an example.html".to_string()));
    }

    #[test]
    fn test_rfc6266_example_3_euro_sign() {
        // "Content-Disposition: attachment; filename*= UTF-8''%e2%82%ac%20rates"
        let header = "attachment; filename*= UTF-8''%e2%82%ac%20rates";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"€ rates".to_string()));
    }

    #[test]
    fn test_rfc6266_example_4_fallback() {
        // "Content-Disposition: attachment; filename="EURO rates"; filename*=utf-8''%e2%82%ac%20rates"
        let header = r#"attachment; filename="EURO rates"; filename*=utf-8''%e2%82%ac%20rates"#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        // filename* should take precedence
        assert_eq!(dis.params.get("filename"), Some(&"€ rates".to_string()));
    }

    // --------------------------------------------------------------------------
    // Section 4.1: Quoted String Handling
    // --------------------------------------------------------------------------

    #[test]
    fn test_quoted_string_basic() {
        let header = r#"attachment; filename="test file.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test file.txt".to_string()));
    }

    #[test]
    fn test_quoted_string_with_semicolon() {
        // RFC 6266 Section 4.1: Semicolons inside quotes should not split parameters
        let header = r#"attachment; filename="file;name.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"file;name.txt".to_string()));
    }

    #[test]
    fn test_token_value_no_quotes() {
        // Token form (no spaces, no special chars)
        let header = "attachment; filename=simple.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"simple.txt".to_string()));
    }

    #[test]
    fn test_empty_quoted_string() {
        let header = r#"attachment; filename="""#;
        let dis = parse_content_disposition(header);
        // Empty quoted string should result in empty string
        assert_eq!(dis.params.get("filename"), Some(&"".to_string()));
    }

    #[test]
    fn test_quoted_string_with_escaped_quote() {
        // RFC 2616 Section 2.2: Backslash can escape characters in quoted-string
        // Note: RFC 6266 Appendix D advises avoiding backslashes due to poor UA support
        let header = r#"attachment; filename="file\"name.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"file\"name.txt".to_string()));
    }

    #[test]
    fn test_single_quote_in_filename() {
        // Single quotes don't need escaping
        let header = r#"attachment; filename="file'name.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"file'name.txt".to_string()));
    }

    // --------------------------------------------------------------------------
    // Whitespace Handling (Section 4.1: implied LWS)
    // --------------------------------------------------------------------------

    #[test]
    fn test_whitespace_around_semicolon() {
        let header = "attachment ; filename=test.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_whitespace_around_equals() {
        let header = "attachment; filename = test.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_whitespace_before_value() {
        let header = r#"attachment; filename= "test.txt""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_leading_whitespace_disposition() {
        let header = "  attachment; filename=test.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
    }

    // --------------------------------------------------------------------------
    // Multiple Parameters
    // --------------------------------------------------------------------------

    #[test]
    fn test_multiple_parameters() {
        let header =
            r#"attachment; filename="test.txt"; size=1234; creation-date="Thu, 01 Jan 2024""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
        assert_eq!(dis.params.get("size"), Some(&"1234".to_string()));
        assert_eq!(dis.params.get("creation-date"), Some(&"Thu, 01 Jan 2024".to_string()));
    }

    #[test]
    fn test_form_data_with_name() {
        // Common in multipart/form-data
        let header = r#"form-data; name="file"; filename="upload.pdf""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::FormData);
        assert_eq!(dis.params.get("name"), Some(&"file".to_string()));
        assert_eq!(dis.params.get("filename"), Some(&"upload.pdf".to_string()));
    }

    // --------------------------------------------------------------------------
    // Edge Cases and Error Recovery
    // --------------------------------------------------------------------------

    #[test]
    fn test_empty_header() {
        let dis = parse_content_disposition("");
        // Empty disposition type defaults to inline per DispositionType::default()
        assert_eq!(dis.disposition, DispositionType::Extension("".to_string()));
    }

    #[test]
    fn test_disposition_type_only() {
        let dis = parse_content_disposition("inline");
        assert_eq!(dis.disposition, DispositionType::Inline);
        assert!(dis.params.is_empty());
    }

    #[test]
    fn test_trailing_semicolon() {
        let header = "attachment; filename=test.txt;";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"test.txt".to_string()));
    }

    #[test]
    fn test_percent_decoding_edge_cases() {
        // Incomplete percent sequence at end
        let header = "attachment; filename*=UTF-8''test%2";
        let dis = parse_content_disposition(header);
        // Should handle gracefully - the incomplete sequence is preserved
        assert!(dis.params.get("filename").is_some());
    }

    #[test]
    fn test_percent_decoding_invalid_hex() {
        // Invalid hex digits
        let header = "attachment; filename*=UTF-8''test%GG";
        let dis = parse_content_disposition(header);
        // Should handle gracefully
        assert!(dis.params.get("filename").is_some());
    }

    // --------------------------------------------------------------------------
    // RFC 2184/2231 Parameter Value Continuations
    // --------------------------------------------------------------------------

    #[test]
    fn test_parameter_continuation() {
        // RFC 2184 Section 3: parameter value continuations
        let header =
            "attachment; filename*0=\"very\"; filename*1=\"long\"; filename*2=\"name.txt\"";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"verylongname.txt".to_string()));
    }

    #[test]
    fn test_parameter_continuation_with_encoding() {
        // Continuation with RFC 5987 encoding on first part
        let header = "attachment; filename*0*=UTF-8''%C3%A9; filename*1*=lite.txt";
        let dis = parse_content_disposition(header);
        // First part: é (UTF-8 encoded), second part: lite.txt
        assert_eq!(dis.params.get("filename"), Some(&"élite.txt".to_string()));
    }

    // --------------------------------------------------------------------------
    // Original Tests (preserved)
    // --------------------------------------------------------------------------

    #[test]
    fn test_parse_content_disposition() {
        let dis = parse_content_disposition("inline");
        assert_eq!(dis.disposition, DispositionType::Inline);
        assert_eq!(dis.params.get("name"), None);
        assert_eq!(dis.params.get("filename"), None);

        let dis = parse_content_disposition(
            " attachment; x=y; charset=\"fake\" ; x2=y2; name=\"King Joffrey.death\"",
        );
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("name"), Some(&"King Joffrey.death".to_string()));
        assert_eq!(dis.params.get("filename"), None);
    }

    // --------------------------------------------------------------------------
    // tc2231: Path / security-relevant filenames
    //
    // The parser MUST preserve these verbatim. Sanitization (path stripping,
    // Windows reserved names, etc.) is the caller's responsibility.
    // --------------------------------------------------------------------------
    #[test]
    fn test_tc2231_attabspath() {
        // attachment; filename="/foo.html"
        let header = r#"attachment; filename="/foo.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"/foo.html".to_string()));
    }

    #[test]
    fn test_tc2231_attabspathwin() {
        // attachment; filename="\\foo.html"
        // Wire bytes between the quotes are: \ \ f o o . h t m l
        let header = r#"attachment; filename="\\foo.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&r"\foo.html".to_string()));
    }

    #[test]
    fn test_tc2231_attwithfnrawpctenca() {
        // attachment; filename="foo-%41.html"
        // Plain `filename` MUST NOT be percent-decoded (only `filename*` is).
        // Decoding here would let an attacker smuggle bytes past sanitization.
        let header = r#"attachment; filename="foo-%41.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo-%41.html".to_string()));
    }

    #[test]
    fn test_tc2231_attwithfnusingpct() {
        // attachment; filename="50%.html"
        // Lone '%' must not crash anything; plain filename keeps it as-is.
        let header = r#"attachment; filename="50%.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"50%.html".to_string()));
    }

    #[test]
    fn test_tc2231_attwithnamepct() {
        // attachment; name="foo-%41.html"
        // `name` is not `filename`; never decoded.
        let header = r#"attachment; name="foo-%41.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("name"), Some(&"foo-%41.html".to_string()));
        assert_eq!(dis.params.get("filename"), None);
    }

    #[test]
    fn test_tc2231_attwithfnrawpctenclong() {
        // attachment; filename="foo-%c3%a4-%e2%82%ac.html"
        // Plain filename: percent sequences preserved, NOT decoded as UTF-8.
        let header = r#"attachment; filename="foo-%c3%a4-%e2%82%ac.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo-%c3%a4-%e2%82%ac.html".to_string()));
    }

    // --------------------------------------------------------------------------
    // tc2231: Duplicate filename parameter
    //
    // BEHAVIORAL NOTE: Your parser uses BTreeMap::collect, so when the same key
    // appears twice the LAST occurrence wins. Browsers (FF, IE, Safari, Chrome)
    // take the FIRST. tc2231 marks the "first wins" behavior as `warn`. Your
    // current behavior is also acceptable per RFC (header is invalid either way).
    // This test pins down the current choice; change it deliberately if at all.
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attwith2filenames_last_wins() {
        let header = r#"attachment; filename="foo.html"; filename="bar.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"bar.html".to_string()));
    }

    // --------------------------------------------------------------------------
    // tc2231: Token-form quirks (tolerant parsing of technically-invalid input)
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attwithfntokensq() {
        // attachment; filename='foo.bar'
        // Single quotes are not the same as double quotes; they stay in the value.
        let header = "attachment; filename='foo.bar'";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"'foo.bar'".to_string()));
    }

    #[test]
    fn test_tc2231_attwithtokfncommanq() {
        // attachment; filename=foo,bar.html
        // Invalid (comma not allowed in token form), but parser accepts it.
        let header = "attachment; filename=foo,bar.html";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo,bar.html".to_string()));
    }

    #[test]
    fn test_tc2231_attemptyparam() {
        // attachment; ;filename=foo
        // Empty segment between the two ; is silently skipped.
        let header = "attachment; ;filename=foo";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"foo".to_string()));
    }

    #[test]
    fn test_tc2231_attconfusedparam() {
        // attachment; xfilename=foo.html
        // 'xfilename' is not 'filename'; should NOT be treated as a filename.
        let header = "attachment; xfilename=foo.html";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), None);
        assert_eq!(dis.params.get("xfilename"), Some(&"foo.html".to_string()));
    }

    // --------------------------------------------------------------------------
    // tc2231: RFC 5987 ext-value malformed inputs
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attwithfn2231noc() {
        // attachment; filename*=''foo-%c3%a4-%e2%82%ac.html
        // No charset between the single quotes.
        // Expected: Previously failed/ignored, now successfully falls back to UTF-8 decoding.
        let header = "attachment; filename*=''foo-%c3%a4-%e2%82%ac.html";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo-ä-€.html".to_string()));
    }

    #[test]
    fn test_rfc5987_iso8859_15() {
        // ISO-8859-15 encoding (Latin-9)
        // 'é' is 0xE9.
        // The Euro sign '€' is 0xA4 (which uniquely distinguishes it from ISO-8859-1, where 0xA4 is '¤').
        let header = "attachment; filename*=ISO-8859-15''caf%E9_%A4.txt";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"café_€.txt".to_string()));
    }

    #[test]
    fn test_tc2231_attwithfn2231ws2() {
        // attachment; filename*=UTF-8''foo-a.html  (no extra whitespace, baseline)
        // Then a whitespace variant tc2231 calls "ws2": filename* =UTF-8''foo-a.html
        let header = "attachment; filename* =UTF-8''foo-a.html";
        let dis = parse_content_disposition(header);
        // Whitespace BEFORE '=' should still let the param be recognized.
        assert_eq!(dis.params.get("filename"), Some(&"foo-a.html".to_string()));
    }

    #[test]
    fn test_tc2231_attwithfn2231ws3() {
        // attachment; filename*= UTF-8''foo-a.html
        // Whitespace AFTER '=' before the value.
        let header = "attachment; filename*= UTF-8''foo-a.html";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo-a.html".to_string()));
    }

    // --------------------------------------------------------------------------
    // tc2231: Continuation edge cases (RFC 2231 Section 3)
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attfncontnc() {
        // attachment; filename*0="foo"; filename*2="bar"
        // Gap in continuation indices: only the *0 part is taken; *2 is lost.
        let header = r#"attachment; filename*0="foo"; filename*2="bar""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo".to_string()));
    }

    #[test]
    fn test_tc2231_attfnconts1() {
        // attachment; filename*1="foo."; filename*2="html"
        // No filename*0 — current parser produces no `filename` key (only *0 triggers
        // unwrapping). Verifies we don't accidentally synthesize a filename here.
        let header = r#"attachment; filename*1="foo."; filename*2="html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), None);
    }

    // --------------------------------------------------------------------------
    // tc2231: Known non-conformances — track but don't fail the suite
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attwithasciifnescapedchar() {
        // attachment; filename="f\oo.html"  -> tc2231 expects "foo.html"
        let header = r#"attachment; filename="f\oo.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo.html".to_string()));
    }

    #[test]
    fn test_tc2231_attwithfilenameandextparamescaped() {
        // attachment; foo="\"\\";filename="foo.html"
        // tc2231 expects filename to be "foo.html"; our splitter sees the \"
        // as an unescaped quote toggle and never reaches a clean delimiter.
        let header = r#"attachment; foo="\"\\";filename="foo.html""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"foo.html".to_string()));
    }

    #[test]
    fn test_tc2231_inlonlyquoted_should_be_ignored() {
        // "inline"  (quoted disposition type — invalid)
        // RFC says ignore the header. Our parser produces Extension("\"inline\"").
        // Current callers only act on Inline/Attachment/FormData so this is benign,
        // but if you ever switch to "if any disposition is set, use the filename"
        // semantics, this would matter.
        let dis = parse_content_disposition(r#""inline""#);
        assert_ne!(dis.disposition, DispositionType::Inline);
    }

    // --------------------------------------------------------------------------
    // tc2231: RFC 2047 encoded-words MUST NOT be decoded
    //
    // RFC 2047 encoded-words ("=?CHARSET?ENC?DATA?=") are defined for mail
    // headers (RFC 5322), not for HTTP. RFC 6266 explicitly does not adopt them;
    // the only HTTP-supported non-ASCII mechanism is RFC 5987 ext-value
    // (filename*=charset'lang'pct-encoded). A parser that decodes encoded-words
    // would violate RFC 6266 and accept input that real HTTP clients reject.
    //
    // These tests verify the parser preserves the raw bytes verbatim.
    // --------------------------------------------------------------------------

    #[test]
    fn test_tc2231_attrfc2047token() {
        // attachment; filename==?ISO-8859-1?Q?foo-=E4.html?=
        // Token form (no quotes) containing what looks like an encoded-word.
        // Expected: preserved as-is. NOT decoded to "foo-ä.html".
        //
        // Note the parser splits on the first '=': key="filename", and the
        // value starts at the second '=' which begins the encoded-word.
        let header = "attachment; filename==?ISO-8859-1?Q?foo-=E4.html?=";
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"=?ISO-8859-1?Q?foo-=E4.html?=".to_string()));
    }

    #[test]
    fn test_tc2231_attrfc2047quoted() {
        // attachment; filename="=?ISO-8859-1?Q?foo-=E4.html?="
        // Quoted-string form containing an encoded-word.
        // Expected: outer quotes stripped, inner content preserved verbatim.
        let header = r#"attachment; filename="=?ISO-8859-1?Q?foo-=E4.html?=""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.disposition, DispositionType::Attachment);
        assert_eq!(dis.params.get("filename"), Some(&"=?ISO-8859-1?Q?foo-=E4.html?=".to_string()));
    }

    #[test]
    fn test_rfc2047_utf8_qencoded_not_decoded() {
        // Extra paranoia case: =?UTF-8?Q?...?= in a properly quoted filename.
        // If some future change adds RFC 2047 decoding, this catches it.
        let header = r#"attachment; filename="=?UTF-8?Q?caf=C3=A9.txt?=""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"=?UTF-8?Q?caf=C3=A9.txt?=".to_string()));
        // And specifically NOT the decoded form:
        assert_ne!(dis.params.get("filename"), Some(&"café.txt".to_string()));
    }

    #[test]
    fn test_rfc2047_base64_not_decoded() {
        // =?CHARSET?B?base64?= form — also must not be decoded.
        // "Zm9vLmh0bWw=" is base64 for "foo.html".
        let header = r#"attachment; filename="=?UTF-8?B?Zm9vLmh0bWw=?=""#;
        let dis = parse_content_disposition(header);
        assert_eq!(dis.params.get("filename"), Some(&"=?UTF-8?B?Zm9vLmh0bWw=?=".to_string()));
        assert_ne!(dis.params.get("filename"), Some(&"foo.html".to_string()));
    }
}
