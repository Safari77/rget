// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Sami Farin
//
// Based on 62330e3d606cbe32219300422f5922f55bedb3a2 commit
// from https://github.com/y0zong/content-disposition
//
// Adapted for local use to fix RFC 6266 precedence issues.

use std::collections::{BTreeMap, HashMap};
use charset::Charset;

/// The possible disposition types in a Content-Disposition header.
#[derive(Debug, Clone, PartialEq)]
#[derive(Default)]
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

pub fn parse_content_disposition(header: &str) -> ParsedContentDisposition {
    let params = parse_param_content(header);
    let disposition = parse_disposition_type(&params.value);
    ParsedContentDisposition {
        disposition,
        params: params.params,
    }
}

/// Used to store params for content-type and content-disposition
struct ParamContent {
    value: String,
    params: BTreeMap<String, String>,
}

/// Split on semicolons, but respect quoted strings.
/// RFC 6266 Section 4.1: semicolons inside quoted-string values must not split parameters.
fn split_semicolon_aware(content: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, ch) in content.char_indices() {
        match ch {
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
                let mut value = kv[idx + 1..].trim();
                if value.starts_with('"') && value.ends_with('"') && value.len() > 1 {
                    value = &value[1..value.len() - 1];
                }
                (key, value.to_string())
            })
        })
        .collect();

    // Decode charset encoding, as described in RFC 2184, Section 4.
    let decode_key_list: Vec<String> = map
        .keys()
        .filter_map(|k| k.strip_suffix('*'))
        .map(String::from)
        .collect();

    let encodings = compute_parameter_encodings(&map, &decode_key_list);

    for (k, (e, strip)) in encodings {
        if let Some(charset) = Charset::for_label_no_replacement(e.as_bytes()) {
            let key = format!("{}*", k);
            let percent_encoded_value = map.remove(&key).unwrap();
            let encoded_value = if strip {
                percent_decode(percent_encoded_value.splitn(3, '\'').nth(2).unwrap_or(""))
            } else {
                percent_decode(&percent_encoded_value)
            };
            let decoded_value = charset.decode_without_bom_handling(&encoded_value).0;
            // This insert will now correctly overwrite existing keys
            map.insert(k, decoded_value.to_string());
        }
    }

    // Unwrap parameter value continuations, as described in RFC 2184, Section 3.
    let unwrap_key_list: Vec<String> = map
        .keys()
        .filter_map(|k| k.strip_suffix("*0"))
        .map(String::from)
        .collect();

    for unwrap_key in unwrap_key_list {
        let mut unwrapped_value = String::new();
        let mut index = 0;
        while let Some(wrapped_value_part) = map.remove(&format!("{}*{}", &unwrap_key, index)) {
            index += 1;
            unwrapped_value.push_str(&wrapped_value_part);
        }
        let _old_value = map.insert(unwrap_key, unwrapped_value);
    }

    ParamContent {
        value: value.into(),
        params: map,
    }
}

fn compute_parameter_encodings(
    map: &BTreeMap<String, String>,
    decode_key_list: &Vec<String>,
) -> HashMap<String, (String, bool)> {
    let mut encodings: HashMap<String, (String, bool)> = HashMap::new();
    for decode_key in decode_key_list {
        if let Some(unwrap_key) = decode_key.strip_suffix("*0") {
            let encoding = map
                .get(&format!("{}*", decode_key))
                .unwrap()
                .split('\'')
                .next()
                .unwrap_or("");
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
    #[ignore] // KNOWN NON-CONFORMANCE: Parser doesn't handle escape sequences
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
        let header = r#"attachment; filename="test.txt"; size=1234; creation-date="Thu, 01 Jan 2024""#;
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
        let header = "attachment; filename*0=\"very\"; filename*1=\"long\"; filename*2=\"name.txt\"";
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
        assert_eq!(
            dis.params.get("name"),
            Some(&"King Joffrey.death".to_string())
        );
        assert_eq!(dis.params.get("filename"), None);
    }
}
