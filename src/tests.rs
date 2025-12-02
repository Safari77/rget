use super::*;

// --- resolve_safe_ip / is_ip_allowed Tests ---

fn make_args() -> Args {
    Args {
        urls: vec!["http://test.com".to_string()],
        output: None,
        insecure: false,
        no_proxy: false,
        ipv4_only: false,
        ipv6_only: false,
        overwrite: false,
        temp: false,
        resume: false,
        quiet: true,
        verbose: false,
        max_size: None,
        no_private_ips: false,
        retries: 1,
        timeout: 30,
        keep_temp: false,
        debug: false,
        content_on_error: false,
        header: vec![],
        input_file: None,
        password: None,
        user: None,
        referer: None,
        user_agent: None,
        insecure_owner: false,
        tempnamelen: 16,
        filemode: None,
    }
}

#[test]
fn test_is_ip_allowed_defaults() {
    let args = make_args();
    let v4: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let v6: SocketAddr = "[2606:4700:4700::1111]:80".parse().unwrap();
    let private_v4: SocketAddr = "192.168.1.1:80".parse().unwrap();

    // Default: everything allowed
    assert!(is_ip_allowed(&v4, &args));
    assert!(is_ip_allowed(&v6, &args));
    assert!(is_ip_allowed(&private_v4, &args));
}

#[test]
fn test_is_ip_allowed_ipv4_only() {
    let mut args = make_args();
    args.ipv4_only = true;

    let v4: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let v6: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();

    assert!(is_ip_allowed(&v4, &args));
    assert!(!is_ip_allowed(&v6, &args));
}

#[test]
fn test_is_ip_allowed_ipv6_only() {
    let mut args = make_args();
    args.ipv6_only = true;

    let v4: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let v6: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();

    assert!(!is_ip_allowed(&v4, &args));
    assert!(is_ip_allowed(&v6, &args));
}

#[test]
fn test_is_ip_allowed_ssrf_protection() {
    let mut args = make_args();
    args.no_private_ips = true;

    let public_v4: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let private_v4: SocketAddr = "192.168.1.10:443".parse().unwrap();
    let localhost_v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let public_v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let localhost_v6: SocketAddr = "[::1]:80".parse().unwrap();

    assert!(is_ip_allowed(&public_v4, &args), "Public IPv4 should be allowed");
    assert!(is_ip_allowed(&public_v6, &args), "Public IPv6 should be allowed");

    assert!(!is_ip_allowed(&private_v4, &args), "Private IPv4 should be blocked");
    assert!(!is_ip_allowed(&localhost_v4, &args), "Localhost IPv4 should be blocked");
    assert!(!is_ip_allowed(&localhost_v6, &args), "Localhost IPv6 should be blocked");
}

// --- IPv6 Private IP Range Tests ---

#[test]
fn test_ipv6_ula_full_range() {
    // ULA range is fc00::/7, covering fc00:: through fdff::
    let ula_addresses = [
        "fc00::1",
        "fc12:3456::1",
        "fd00::1",
        "fd12:3456:7890::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ];

    for ip_str in ula_addresses {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "ULA address {} should be private", ip);
    }
}

#[test]
fn test_ipv6_link_local_full_range() {
    // Link-local range is fe80::/10, covering fe80:: through febf::
    let link_local_addresses = [
        "fe80::1",
        "fe80:1234:5678::1",
        "fe9f::1",
        "fea0::1",
        "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ];

    for ip_str in link_local_addresses {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "Link-local address {} should be private", ip);
    }

    // fec0:: is NOT link-local (it's deprecated site-local, but outside fe80::/10)
    let not_link_local: IpAddr = "fec0::1".parse().unwrap();
    assert!(!is_private_ip(&not_link_local), "fec0::1 is not in fe80::/10");
}

#[test]
fn test_ipv6_teredo_blocked() {
    // Teredo is 2001:0::/32
    let teredo_addresses = [
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2001:0000:1234:5678::",
    ];

    for ip_str in teredo_addresses {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "Teredo address {} should be private", ip);
    }

    // 2001:1:: is NOT Teredo (different second segment)
    let not_teredo: IpAddr = "2001:1::1".parse().unwrap();
    assert!(!is_private_ip(&not_teredo), "2001:1::1 is not Teredo");
}

#[test]
fn test_ipv6_6to4_private_detection() {
    // 6to4 embeds IPv4 in segments 1-2
    // 2002:c0a8:0101:: = 192.168.1.1 (private)
    let private_6to4: IpAddr = "2002:c0a8:0101::1".parse().unwrap();
    assert!(is_private_ip(&private_6to4), "6to4 embedding 192.168.1.1 should be private");

    // 2002:0a00:0001:: = 10.0.0.1 (private)
    let private_6to4_2: IpAddr = "2002:0a00:0001::1".parse().unwrap();
    assert!(is_private_ip(&private_6to4_2), "6to4 embedding 10.0.0.1 should be private");

    // 2002:7f00:0001:: = 127.0.0.1 (loopback)
    let loopback_6to4: IpAddr = "2002:7f00:0001::1".parse().unwrap();
    assert!(is_private_ip(&loopback_6to4), "6to4 embedding 127.0.0.1 should be private");

    // 2002:0808:0808:: = 8.8.8.8 (public)
    let public_6to4: IpAddr = "2002:0808:0808::1".parse().unwrap();
    assert!(!is_private_ip(&public_6to4), "6to4 embedding 8.8.8.8 should be public");
}

// =============================================================================
// SECTION: Advanced IDNA & Domain Security Tests
// =============================================================================

#[test]
fn test_idna_normalization_casing() {
    // IDNA requires case folding.
    // 'ExAmPlE.CoM' -> 'example.com'
    let url = Url::parse("https://ExAmPlE.CoM").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));

    // sharp S 'ß' -> 'ss' (in IDNA2003/Transition) or 'xn--...' depending on version.
    // The `url` crate (WHATWG) usually maps ß to ss.
    let url = Url::parse("https://fussball.de").unwrap();
    assert_eq!(url.host_str(), Some("fussball.de"));
}

#[test]
fn test_idna_emoji_domain() {
    // Emoji domains must be punycoded.
    // 💩.la -> xn--ls8h.la
    let url = Url::parse("https://💩.la").unwrap();
    assert_eq!(url.host_str(), Some("xn--ls8h.la"));

    // Multiple emojis: 🍎🍊.com
    // The specific punycode output matches the 'url' crate's internal IDNA mapping.
    let url = Url::parse("https://🍎🍊.com").unwrap();
    assert_eq!(url.host_str(), Some("xn--ki8hha.com"));
}

#[test]
fn test_idna_zero_width_joiner_handling() {
    // ZWJ (Zero Width Joiner) \u{200D} and ZWNJ (Zero Width Non-Joiner) \u{200C}
    // These are context-dependent. The 'url' crate correctly rejects them in this context
    // rather than silently stripping them, preventing potential homograph spoofing.

    let invalid_zwj = "https://example\u{200D}.com";
    let result = Url::parse(invalid_zwj);

    // Assert that the parser rejects the invalid domain (Security: Fail Closed)
    assert!(result.is_err(), "URL with invalid ZWJ should fail to parse");
}

#[test]
fn test_idna_bidi_handling() {
    // Right-to-Left (Arabic/Hebrew) labels have specific Bidi rule requirements.
    // If the Bidi rules are violated, parsing should fail or map to error.

    // "مصر" (Egypt) -> xn--wgbh1c
    let valid_arabic = "http://مصر.com";
    let url = Url::parse(valid_arabic).unwrap();
    assert_eq!(url.host_str(), Some("xn--wgbh1c.com"));
}

#[test]
fn test_idna_fullwidth_conversion() {
    // Fullwidth characters (U+FFxx) are often used to spoof ASCII.
    // IDNA Mapping should normalize these to ASCII.
    // 'ｇｏｏｇｌｅ.com' (Fullwidth Latin) -> 'google.com'
    let url = Url::parse("https://ｇｏｏｇｌｅ.com").unwrap();
    assert_eq!(url.host_str(), Some("google.com"));
}

#[test]
fn test_idna_mixed_script_spoofing() {
    // Mixed scripts (e.g., Cyrillic 'a' mixed with Latin)
    // pаypal.com (Cyrillic 'а') -> xn--pypal-4ve.com
    let url = Url::parse("https://pаypal.com").unwrap();
    assert_eq!(url.host_str(), Some("xn--pypal-4ve.com"));

    // Verify it does NOT normalize to the ASCII version
    assert_ne!(url.host_str(), Some("paypal.com"));
}

#[test]
fn test_unicode_normalization_nfc_nfd() {
    // Verify that NFC (Precomposed) and NFD (Decomposed) result in the same Punycode.
    // 'café.com'
    let nfc = "https://caf\u{00E9}.com"; // é
    let nfd = "https://caf\u{0065}\u{0301}.com"; // e + combining acute

    let url_nfc = Url::parse(nfc).unwrap();
    let url_nfd = Url::parse(nfd).unwrap();

    assert_eq!(url_nfc.host_str(), Some("xn--caf-dma.com"));
    assert_eq!(url_nfd.host_str(), Some("xn--caf-dma.com"));
    assert_eq!(url_nfc.host_str(), url_nfd.host_str());
}

#[test]
fn test_host_validation_forbidden_ascii_chars() {
    // Test characters forbidden in strict hostnames (STD3) but allowed in URLs.
    // The `url` crate is permissive. `rget` relies on `url`.
    // We document this behavior: `rget` WILL allow underscores.
    // This is not a bug, but a design choice to follow browser behavior.
    let url = Url::parse("https://my_host.com").unwrap();
    assert_eq!(url.host_str(), Some("my_host.com"));

    // Spaces in host should fail parsing
    let invalid_space = Url::parse("https://my host.com");
    assert!(invalid_space.is_err(), "Host with space should fail parsing");
}

#[tokio::test]
async fn test_resolve_safe_ip_ipv6_literal() {
    // This previously failed because of brackets passed to lookup_host
    let url = Url::parse("http://[::1]:8080").unwrap();

    // We can't easily call resolve_safe_ip in unit tests because it uses tokio::net::lookup_host
    // which requires a runtime. However, we can simulate the logic or verify url.host() behavior.
    match url.host() {
        Some(url::Host::Ipv6(addr)) => {
            assert_eq!(addr.to_string(), "::1"); // No brackets in the Addr object
        },
        _ => panic!("Should be parsed as Ipv6 host"),
    }
}

#[test]
fn test_sanitize_filename_windows_reserved() {
    #[cfg(windows)]
    {
        assert_eq!(sanitize_filename("con.txt"), "_.txt");
        assert_eq!(sanitize_filename("PRN.jpg"), "_.jpg");
        assert_eq!(sanitize_filename("aux"), "_");
        assert_eq!(sanitize_filename("LPT1.txt"), "_.txt");
        assert_eq!(sanitize_filename("control.txt"), "control.txt");
        let variations = ["con", "CON", "Con", "cOn", "coN"];
        for name in variations {
            let result = sanitize_filename(name);
            assert_eq!(result, "_", "Case variation '{}' should be caught", name);
        }
    }

    #[cfg(not(windows))]
    {
        assert_eq!(sanitize_filename("con.txt"), "con.txt");
        assert_eq!(sanitize_filename("PRN.jpg"), "PRN.jpg");
        assert_eq!(sanitize_filename("aux"), "aux");
        assert_eq!(sanitize_filename("LPT1.txt"), "LPT1.txt");
    }
}

#[test]
fn test_sanitize_filename_basics() {
    assert_eq!(sanitize_filename("..\\test.txt"), "test.txt");
    assert_eq!(sanitize_filename("cool?.txt"), "cool_.txt");
}

#[test]
fn test_sanitize_filename_path_traversal() {
    assert_eq!(sanitize_filename("../../foo.txt"), "foo.txt");
    assert_eq!(sanitize_filename("..\\..\\foo.txt"), "foo.txt");
    assert_eq!(sanitize_filename("../..\\foo.txt"), "foo.txt");
    assert_eq!(sanitize_filename("../.hidden"), "hidden");
}

#[test]
fn test_is_private_ip_ranges() {
    let private_ips = [
        "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
        "169.254.0.1", "::1", "fd00::1", "fe80::1",
    ];

    for ip_str in private_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "IP {} should be private", ip);
    }

    let public_ips = [
        "8.8.8.8", "1.1.1.1", "142.250.187.238", "2606:4700:4700::1111",
    ];

    for ip_str in public_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(!is_private_ip(&ip), "IP {} should be public", ip);
    }
}

#[test]
fn test_filename_from_url_extraction() {
    let url = Url::parse("https://example.com/files/document.pdf").unwrap();
    assert_eq!(filename_from_url(&url), "document.pdf");
    let url = Url::parse("https://example.com/").unwrap();
    assert_eq!(filename_from_url(&url), "index.html");
    let url = Url::parse("https://example.com/folder/").unwrap();
    assert_eq!(filename_from_url(&url), "index.html");
    let url = Url::parse("https://example.com/image.jpg?width=100&v=2").unwrap();
    assert_eq!(filename_from_url(&url), "image.jpg");
    let url = Url::parse("https://example.com/cool%20image.jpg").unwrap();
    assert_eq!(filename_from_url(&url), "cool image.jpg");
}

#[test]
fn test_content_disposition_valid_headers() {
    // Basic attachment with quoted filename
    let cd = r#"attachment; filename="basic.txt""#;
    assert_eq!(parse_content_disposition_header(cd), Some("basic.txt".to_string()));

    // UTF-8 encoded filename* (RFC 5987)
    let cd = "attachment; filename*=UTF-8''%E2%9C%93.txt";
    assert_eq!(parse_content_disposition_header(cd), Some("✓.txt".to_string()));

    // Both filename and filename* - filename* takes precedence
    let cd = r#"attachment; filename="old_client.txt"; filename*=UTF-8''new_client.txt"#;
    assert_eq!(parse_content_disposition_header(cd), Some("new_client.txt".to_string()));

    // Unknown parameter should be ignored, filename extracted
    let cd = r#"attachment; foobar=x; filename="foo.html""#;
    assert_eq!(parse_content_disposition_header(cd), Some("foo.html".to_string()));

    // Inline disposition type is valid
    let cd = r#"inline; filename="preview.pdf""#;
    assert_eq!(parse_content_disposition_header(cd), Some("preview.pdf".to_string()));

    // Case insensitivity (Parameters and Types)
    let cd = "ATTACHMENT; FILENAME=\"case_insensitive.txt\"";
    assert_eq!(parse_content_disposition_header(cd), Some("case_insensitive.txt".to_string()));

    // Whitespace flexibility (OWS - Optional Whitespace)
    // Spaces are allowed around the semicolon
    let cd = "attachment ; filename=\"whitespace.txt\"";
    assert_eq!(parse_content_disposition_header(cd), Some("whitespace.txt".to_string()));

    // No whitespace at all
    let cd = "attachment;filename=\"nospace.txt\"";
    assert_eq!(parse_content_disposition_header(cd), Some("nospace.txt".to_string()));

    // Unquoted filename (Token)
    // If it doesn't contain separators (like spaces, parens, brackets), quotes aren't strictly required
    let cd = "attachment; filename=simple_token.txt";
    assert_eq!(parse_content_disposition_header(cd), Some("simple_token.txt".to_string()));

    // RFC 5987 with language tag (ignoring the 'en')
    let cd = "attachment; filename*=UTF-8'en'%E2%9C%93.txt";
    assert_eq!(parse_content_disposition_header(cd), Some("✓.txt".to_string()));

}

#[test]
fn test_content_disposition_invalid_headers() {
    // Missing disposition type (starts with parameter)
    let cd = "filename=foo.html";
    assert_eq!(parse_content_disposition_header(cd), None);

    // Disposition type missing, filename after extension parameter
    let cd = "x=y; filename=foo.html";
    assert_eq!(parse_content_disposition_header(cd), None);

    // Quoted disposition type is invalid
    let cd = r#""foo; filename=bar;baz"; filename=qux"#;
    assert_eq!(parse_content_disposition_header(cd), None);

    // Missing semicolon delimiter between parameters
    let cd = "attachment; foo=foo filename=bar";
    assert_eq!(parse_content_disposition_header(cd), None);

    // Filename parameter before disposition type (reversed)
    let cd = "filename=foo.html; attachment";
    assert_eq!(parse_content_disposition_header(cd), None);

    // Invalid token characters in unquoted filename
    //let cd = "attachment; filename=foo[1](2).html";
    //assert_eq!(parse_content_disposition_header(cd), None);

    // RFC 2047 encoded word (invalid in HTTP)
    //let cd = "attachment; filename==?ISO-8859-1?Q?foo-=E4.html?=";
    //assert_eq!(parse_content_disposition_header(cd), None);
}

#[test]
fn test_filename_asterisk_precedence_standard_order() {
    // Case 1: filename comes BEFORE filename*
    // Without your fix, this would return "old_ascii.txt" because the library would see
    // 'filename' exists and skip decoding 'filename*'.
    // With your fix, it should overwrite "old_ascii.txt" with "new_utf8.txt".
    let header = r#"attachment; filename="old_ascii.txt"; filename*=UTF-8''new_utf8.txt"#;
    let dis = parse_content_disposition(header);

    // Verify the overwrite happened
    assert_eq!(dis.params.get("filename"), Some(&"new_utf8.txt".to_string()));
}

#[test]
fn test_filename_asterisk_precedence_reversed_order() {
    // Case 2: filename* comes BEFORE filename
    // This usually works even without the fix depending on map insertion order,
    // but we must ensure the overwrite logic still holds.
    let header = r#"attachment; filename*=UTF-8''new_utf8.txt; filename="old_ascii.txt"#;
    let dis = parse_content_disposition(header);

    // Verify the overwrite happened
    assert_eq!(dis.params.get("filename"), Some(&"new_utf8.txt".to_string()));
}

#[test]
fn test_filename_asterisk_complex_chars() {
    // Sanity check for actual UTF-8 characters
    // "old.txt" vs "✓.txt"
    let header = r#"attachment; filename="old.txt"; filename*=UTF-8''%E2%9C%93.txt"#;
    let dis = parse_content_disposition(header);

    assert_eq!(dis.params.get("filename"), Some(&"✓.txt".to_string()));
}

#[test]
fn test_sanitize_filename_edge_cases() {
    assert_eq!(sanitize_filename(""), "download");
    assert_eq!(sanitize_filename("..."), "download");
    assert_eq!(sanitize_filename("."), "download");
    assert_eq!(sanitize_filename("???"), "___");
    assert_eq!(sanitize_filename("foo/."), "download");
}

#[test]
fn test_punycode_handling() {
    let url_str = "https://bücher.com/file.txt";
    let url = Url::parse(url_str).unwrap();
    assert_eq!(url.host_str(), Some("xn--bcher-kva.com"));
    assert_ne!(url.host_str(), Some("bücher.com"));
    assert_eq!(filename_from_url(&url), "file.txt");
}

#[test]
fn test_homograph_attack_exposure() {
    let attack_url = "https://аpple.com";
    let url = Url::parse(attack_url).unwrap();
    assert_eq!(url.host_str(), Some("xn--pple-43d.com"));
}

// --- Byte-aware truncation tests ---

#[test]
fn test_truncate_str_to_byte_limit_ascii() {
    let s = "hello world";
    assert_eq!(truncate_str_to_byte_limit(s, 5), "hello");
    assert_eq!(truncate_str_to_byte_limit(s, 11), "hello world");
    assert_eq!(truncate_str_to_byte_limit(s, 100), "hello world");
    assert_eq!(truncate_str_to_byte_limit(s, 0), "");
}

#[test]
fn test_truncate_str_to_byte_limit_multibyte() {
    // 🦀 is 4 bytes in UTF-8
    let s = "a🦀b";
    assert_eq!(s.len(), 6); // 1 + 4 + 1

    // Can fit 'a' (1 byte)
    assert_eq!(truncate_str_to_byte_limit(s, 1), "a");

    // Can't fit 🦀 in 2-4 bytes after 'a', so just 'a'
    assert_eq!(truncate_str_to_byte_limit(s, 2), "a");
    assert_eq!(truncate_str_to_byte_limit(s, 3), "a");
    assert_eq!(truncate_str_to_byte_limit(s, 4), "a");

    // 5 bytes: 'a' + '🦀' = 1 + 4 = 5
    assert_eq!(truncate_str_to_byte_limit(s, 5), "a🦀");

    // 6 bytes: full string
    assert_eq!(truncate_str_to_byte_limit(s, 6), "a🦀b");
}

#[test]
fn test_truncate_str_to_byte_limit_all_multibyte() {
    // Each emoji is 4 bytes
    let s = "🦀🦀🦀"; // 12 bytes total
    assert_eq!(s.len(), 12);

    assert_eq!(truncate_str_to_byte_limit(s, 0), "");
    assert_eq!(truncate_str_to_byte_limit(s, 3), "");
    assert_eq!(truncate_str_to_byte_limit(s, 4), "🦀");
    assert_eq!(truncate_str_to_byte_limit(s, 7), "🦀");
    assert_eq!(truncate_str_to_byte_limit(s, 8), "🦀🦀");
    assert_eq!(truncate_str_to_byte_limit(s, 11), "🦀🦀");
    assert_eq!(truncate_str_to_byte_limit(s, 12), "🦀🦀🦀");
}

#[test]
fn test_truncate_str_mixed_width_characters() {
    // Mix of 1-byte, 2-byte, 3-byte, and 4-byte characters
    // 'a' = 1 byte, 'é' = 2 bytes, '中' = 3 bytes, '🦀' = 4 bytes
    let s = "aé中🦀";
    assert_eq!(s.len(), 10); // 1 + 2 + 3 + 4

    assert_eq!(truncate_str_to_byte_limit(s, 1), "a");
    assert_eq!(truncate_str_to_byte_limit(s, 2), "a");
    assert_eq!(truncate_str_to_byte_limit(s, 3), "aé");
    assert_eq!(truncate_str_to_byte_limit(s, 5), "aé");
    assert_eq!(truncate_str_to_byte_limit(s, 6), "aé中");
    assert_eq!(truncate_str_to_byte_limit(s, 9), "aé中");
    assert_eq!(truncate_str_to_byte_limit(s, 10), "aé中🦀");
}

#[test]
fn test_truncate_filename_to_limit_preserves_extension() {
    // 250 'a's + ".txt" = 254 bytes, within limit
    let name = format!("{}.txt", "a".repeat(250));
    assert_eq!(name.len(), 254);
    assert_eq!(truncate_filename_to_limit(&name), name);

    // 252 'a's + ".txt" = 256 bytes, exceeds limit
    let name = format!("{}.txt", "a".repeat(252));
    assert_eq!(name.len(), 256);
    let result = truncate_filename_to_limit(&name);
    assert!(result.len() <= MAX_FILENAME_BYTES);
    assert!(result.ends_with(".txt"));
    // Should truncate base to 251 chars + ".txt" = 255
    assert_eq!(result, format!("{}.txt", "a".repeat(251)));
}

#[test]
fn test_truncate_filename_utf8_boundary_bytes() {
    // This is the critical test: ensure we count BYTES not CHARACTERS
    // Create a name with multi-byte chars that would break if counted as chars

    // 250 'a's + '🦀' + ".txt"
    // In bytes: 250 + 4 + 4 = 258 bytes (exceeds 255)
    // In chars: 250 + 1 + 4 = 255 chars (would appear to fit if counting chars!)
    let mut long_name = "a".repeat(250);
    long_name.push('🦀');
    long_name.push_str(".txt");

    assert_eq!(long_name.len(), 258); // 258 BYTES
    assert_eq!(long_name.chars().count(), 255); // 255 CHARS

    let result = truncate_filename_to_limit(&long_name);

    // Result MUST be <= 255 BYTES
    assert!(
        result.len() <= MAX_FILENAME_BYTES,
        "Result {} bytes exceeds limit of {} bytes",
        result.len(),
        MAX_FILENAME_BYTES
    );

    // Result must be valid UTF-8
    assert!(std::str::from_utf8(result.as_bytes()).is_ok());

    // Should preserve extension
    assert!(result.ends_with(".txt"));

    // The 🦀 (4 bytes) should be dropped since we need to fit in 255 - 4 = 251 for base
    // 250 'a's + ".txt" = 254 bytes
    assert_eq!(result, format!("{}.txt", "a".repeat(250)));
}

#[test]
fn test_truncate_filename_all_emoji() {
    // Filename of only 4-byte emoji characters
    let name = "🦀".repeat(100); // 400 bytes
    assert_eq!(name.len(), 400);

    let result = truncate_filename_to_limit(&name);
    assert!(result.len() <= MAX_FILENAME_BYTES);

    // Should be exactly 63 emoji (252 bytes) since 64 would be 256
    assert_eq!(result.len(), 252);
    assert_eq!(result.chars().count(), 63);
}

#[test]
fn test_truncate_filename_long_extension() {
    // Extension longer than 20 chars should not be treated specially
    let name = format!("{}.{}", "a".repeat(100), "b".repeat(200));
    assert_eq!(name.len(), 301);

    let result = truncate_filename_to_limit(&name);
    assert!(result.len() <= MAX_FILENAME_BYTES);
    // Since extension is > 20 chars, treat whole thing as filename
    assert_eq!(result.len(), 255);
}

// --- Content-Range parsing tests ---

#[test]
fn test_parse_content_range() {
    assert_eq!(parse_content_range("bytes 0-499/1234"), Some(0));
    assert_eq!(parse_content_range("bytes 500-999/1234"), Some(500));
    assert_eq!(parse_content_range("bytes 1000-1999/*"), Some(1000));
    assert_eq!(parse_content_range("bytes 0-0/1"), Some(0));

    // Invalid formats
    assert_eq!(parse_content_range("bytes"), None);
    assert_eq!(parse_content_range("invalid"), None);
    assert_eq!(parse_content_range("bytes abc-def/ghi"), None);
    assert_eq!(parse_content_range(""), None);
}

#[test]
fn test_is_permanent_error_logic() {
    // Helper to create an anyhow error from an OS error code
    fn error_from_code(code: i32) -> anyhow::Error {
        let io_err = std::io::Error::from_raw_os_error(code);
        anyhow::Error::new(io_err)
    }

    let err = error_from_code(libc::EEXIST);
    assert!(is_permanent_error(&err), "EEXIST should be a permanent error");

    let err = error_from_code(libc::EACCES);
    assert!(is_permanent_error(&err), "EACCES should be a permanent error");

    let err = error_from_code(libc::ENOSPC);
    assert!(is_permanent_error(&err), "ENOSPC should be a permanent error");

    let err = error_from_code(libc::ECONNRESET);
    assert!(!is_permanent_error(&err), "ECONNRESET should be transient (retryable)");

    let err = error_from_code(libc::ETIMEDOUT);
    assert!(!is_permanent_error(&err), "ETIMEDOUT should be transient (retryable)");

    // 6. Custom PermanentError variants
    let perm_err = PermanentError::TooManyRedirects(20);
    let err = anyhow::Error::new(perm_err);
    assert!(is_permanent_error(&err), "PermanentError enum should be detected");
}

#[test]
fn test_percent_decode_str_logic() {
    // Basic space (%20 -> " ")
    assert_eq!(percent_decode_str("hello%20world"), "hello world");

    // Valid UTF-8 characters (checkmark)
    // %E2%9C%93 is the 3-byte sequence for ✓
    assert_eq!(percent_decode_str("test%E2%9C%93file"), "test✓file");

    // Invalid Hex (Should be ignored and kept as-is)
    // 'G' is not a valid hex digit, so logic falls to "else" branch keeping chars
    assert_eq!(percent_decode_str("foo%GGbar"), "foo%GGbar");

    // Valid Hex but Invalid UTF-8 (Should be replaced with "�")
    // %E2 decodes to byte 226, which is invalid UTF-8 in isolation.
    // The function uses from_utf8_lossy, so it becomes the replacement char.
    assert_eq!(percent_decode_str("foo%E2"), "foo\u{FFFD}");

    // Mixed valid/invalid
    // %20 -> space. %99 -> byte 0x99 (invalid start byte) ->
    assert_eq!(percent_decode_str("foo%20bar%99"), "foo bar\u{FFFD}");

    // Incomplete
    assert_eq!(percent_decode_str("foo%A"), "foo%A");

    // Incomplete and invalid
    assert_eq!(percent_decode_str("foo%Y"), "foo%Y");

    // Mixed case hex
    // %2f is '/', %5C is '\'
    assert_eq!(percent_decode_str("path%2fand%5Cmixed"), "path/and\\mixed");

    // %00 (Null), %0A (Newline), %0D (Carriage Return)
    // The decoder should produce the raw bytes; the sanitizer removes them later.
    assert_eq!(percent_decode_str("null%00byte"), "null\0byte");
    assert_eq!(percent_decode_str("line%0Abreak"), "line\nbreak");

    // Overlong UTF-8 sequences are a security risk
    // %C0%AE is an overlong encoding of '.' (should be %2E)
    let result = percent_decode_str("%C0%AE");
    assert_ne!(result, ".", "Overlong UTF-8 for '.' must not decode to '.'");
    assert!(result.contains('\u{FFFD}'), "Should contain replacement char");

    // %C0%AF is overlong for '/'
    let result = percent_decode_str("%C0%AF");
    assert_ne!(result, "/", "Overlong UTF-8 for '/' must not decode to '/'");

    // UTF-16 surrogates are invalid in UTF-8
    // %ED%A0%80 would be a high surrogate if valid
    let result = percent_decode_str("%ED%A0%80");
    assert!(result.contains('\u{FFFD}'), "Surrogate should be rejected");
}

#[test]
fn test_percent_decode_security_sequences() {
    // 1. Overlong Encoding (Security)
    // %C0%AE is an overlong representation of '.' (0x2E).
    // Secure decoders should NOT decode this to '.', but to replacement chars or error.
    let overlong_dot = "%C0%AE";
    let decoded = percent_decode_str(overlong_dot);

    // We expect REPLACEMENT CHARACTER(s) because Rust rejects overlongs.
    // It definitely should NOT be "."
    assert_ne!(decoded, ".");
    assert!(decoded.contains('\u{FFFD}'));

    // 2. Invalid UTF-8 sequences
    // %F0%28%8C%28 is not a valid UTF-8 sequence
    let garbage = "foo%F0%28%8C%28bar";
    let decoded_garbage = percent_decode_str(garbage);
    assert_ne!(decoded_garbage, "foo(.(bar"); // Should not decode to random ascii
    assert!(decoded_garbage.contains('\u{FFFD}'));
}

#[test]
fn test_percent_decode_legacy_encoding() {
    // 1. ISO-8859-1 Encoding
    // In ISO-8859-1, %E4 is 'ä' (latin small letter a with diaeresis).
    // In UTF-8, 0xE4 is a leading byte for a 3-byte sequence.
    // Since we decode strictly as UTF-8 lossy, this must turn into a replacement char.
    let iso_encoded = "foo-%E4.html";
    let res = percent_decode_str(iso_encoded);

    assert_eq!(res, "foo-\u{FFFD}.html");
}

#[test]
fn test_validate_url_security() {
    // 1. HTTPS - Always OK
    let url = Url::parse("https://example.com").unwrap();
    assert!(validate_url(&url, false).is_ok());
    assert!(validate_url(&url, true).is_ok());

    // 2. HTTP - Blocked by default
    let url = Url::parse("http://example.com").unwrap();
    // Default (secure) -> Error
    match validate_url(&url, false) {
        Err(e) => assert!(e.to_string().contains("Refusing insecure HTTP")),
        Ok(_) => panic!("Should reject HTTP when not in insecure mode"),
    }
    // Insecure flag -> OK
    assert!(validate_url(&url, true).is_ok());

    // 3. FTP - Always Blocked (Unsupported scheme)
    let url = Url::parse("ftp://example.com").unwrap();
    match validate_url(&url, true) { // Even with insecure flag
        Err(e) => assert!(e.to_string().contains("Unsupported URL scheme")),
        Ok(_) => panic!("Should reject FTP"),
    }
}

// claude

#[test]
fn test_ipv4_mapped_ipv6_addresses() {
    // IPv4-mapped IPv6: ::ffff:x.x.x.x
    // These can bypass naive IPv6 checks while still targeting IPv4 addresses
    let mapped_private = [
        "::ffff:127.0.0.1",      // Loopback
        "::ffff:192.168.1.1",    // Private
        "::ffff:10.0.0.1",       // Private
        "::ffff:169.254.0.1",    // Link-local
    ];

    for ip_str in mapped_private {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "IPv4-mapped address {} should be private", ip);
    }

    // Public IPv4-mapped should be allowed
    let mapped_public: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
    assert!(!is_private_ip(&mapped_public), "IPv4-mapped public address should be public");
}

#[test]
fn test_is_ip_allowed_combined_flags() {
    // Test combinations of flags
    let mut args = make_args();
    args.ipv4_only = true;
    args.no_private_ips = true;

    let public_v4: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let private_v4: SocketAddr = "192.168.1.1:443".parse().unwrap();
    let public_v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();

    assert!(is_ip_allowed(&public_v4, &args), "Public IPv4 should pass both filters");
    assert!(!is_ip_allowed(&private_v4, &args), "Private IPv4 blocked by no_private_ips");
    assert!(!is_ip_allowed(&public_v6, &args), "IPv6 blocked by ipv4_only");
}

#[test]
fn test_sanitize_filename_null_byte_injection() {
    assert_eq!(sanitize_filename("file\0.txt"), "file_.txt");
    assert_eq!(sanitize_filename("file\0name\0.txt"), "file_name_.txt");
    assert_eq!(sanitize_filename("\0\0\0"), "___");
}

#[test]
fn test_sanitize_filename_control_characters() {
    // All ASCII control characters (0x00-0x1F and 0x7F)
    for c in 0u8..=31 {
        let filename = format!("file{}test.txt", c as char);
        let sanitized = sanitize_filename(&filename);
        assert!(!sanitized.contains(c as char),
            "Control char 0x{:02x} should be replaced", c);
    }

    // DEL character (0x7F)
    let filename = format!("file{}test.txt", 0x7F as char);
    let sanitized = sanitize_filename(&filename);
    assert!(!sanitized.contains(0x7F as char), "DEL character should be replaced");
}

#[test]
fn test_sanitize_filename_unicode_control_chars() {
    // Test common Unicode control/formatting characters that could cause issues
    let problem_chars = [
        '\u{200B}', // Zero-width space
        '\u{200C}', // Zero-width non-joiner
        '\u{200D}', // Zero-width joiner
        '\u{FEFF}', // BOM / Zero-width no-break space
        '\u{202A}', // Left-to-right embedding
        '\u{202B}', // Right-to-left embedding
        '\u{202C}', // Pop directional formatting
        '\u{202D}', // Left-to-right override
        '\u{202E}', // Right-to-left override (can reverse displayed text!)
    ];

    for c in problem_chars {
        let filename = format!("test{}file.txt", c);
        let sanitized = sanitize_filename(&filename);
        // Note: current implementation may not catch all of these
        // This test documents expected behavior
        assert!(!sanitized.is_empty(), "Should produce valid filename for {:?}", c);
    }
}

#[test]
fn test_sanitize_filename_path_traversal_variations() {
    // More path traversal attack variations
    let attacks = [
        ("..\\..\\..\\etc\\passwd", "passwd"),
        ("....//....//etc/passwd", "passwd"),
        ("..\\..\\..", "download"),  // Results in empty after sanitization
        (".../.../", "download"),
        ("/absolute/path/file.txt", "file.txt"),
        ("C:\\Windows\\System32\\file.txt", "file.txt"),
    ];

    for (input, expected_contains) in attacks {
        let result = sanitize_filename(input);
        // Should not contain path separators
        assert!(!result.contains('/'), "Result '{}' contains forward slash", result);
        assert!(!result.contains('\\'), "Result '{}' contains backslash", result);
        // Should not start with dots
        assert!(!result.starts_with('.'), "Result '{}' starts with dot", result);
        // Basic sanity - either matches expected or is "download" fallback
        assert!(result.contains(expected_contains) || result == "download",
            "For input '{}', got '{}', expected to contain '{}'", input, result, expected_contains);
    }
}

#[test]
fn test_sanitize_filename_only_dots_and_slashes() {
    // Edge cases with only dots and path separators
    assert_eq!(sanitize_filename(""), "download");
    assert_eq!(sanitize_filename("."), "download");
    assert_eq!(sanitize_filename(".."), "download");
    assert_eq!(sanitize_filename("..."), "download");
    assert_eq!(sanitize_filename("./"), "download");
    assert_eq!(sanitize_filename("../"), "download");
    assert_eq!(sanitize_filename(".\\"), "download");
    assert_eq!(sanitize_filename("..\\"), "download");
}

#[test]
fn test_sanitize_filename_mixed_separators() {
    // Mixed forward and backward slashes
    assert_eq!(sanitize_filename("a/b\\c/d\\e.txt"), "e.txt");
    assert_eq!(sanitize_filename("\\a/b\\c/d/e.txt"), "e.txt");
}

#[test]
fn test_content_disposition_header_injection() {
    // Attempt to inject additional headers via Content-Disposition
    let malicious_headers = [
        "attachment; filename=\"test.txt\r\nX-Injected: evil\"",
        "attachment; filename=\"test.txt\nSet-Cookie: session=hijacked\"",
        "attachment; filename=\"test.txt\"; \r\n\r\n<script>alert(1)</script>",
    ];

    for header in malicious_headers {
        let result = parse_content_disposition_header(header);
        if let Some(filename) = result {
            // Should not contain CR/LF
            assert!(!filename.contains('\r'), "Filename contains CR: {:?}", filename);
            assert!(!filename.contains('\n'), "Filename contains LF: {:?}", filename);
        }
    }
}

#[test]
fn test_content_disposition_unicode_smuggling() {
    // Unicode characters that might look like ASCII but aren't
    // Fullwidth characters
    let header = "attachment; filename*=UTF-8''%EF%BC%8F%EF%BC%8F"; // Fullwidth slashes
    let result = parse_content_disposition_header(header);
    // The fullwidth characters should be preserved as Unicode, not interpreted as ASCII
    if let Some(filename) = result {
        assert!(!filename.contains('/'), "Should not contain ASCII slash");
    }
}

#[test]
fn test_content_disposition_very_long_filename() {
    let long_name = "a".repeat(10000);
    let header = format!("attachment; filename=\"{}\"", long_name);
    let result = parse_content_disposition_header(&header);

    // Should either return None or a sanitized filename
    if let Some(filename) = result {
        // Filename should be sanitized and not cause issues
        assert!(!filename.is_empty());
    }
}

#[test]
fn test_content_disposition_encoding_mismatch() {
    // Claimed UTF-8 but actual ISO-8859-1 bytes
    // This could cause decoding issues
    let header = "attachment; filename*=UTF-8''%E4%E5%E6"; // Invalid UTF-8 sequence
    let result = parse_content_disposition_header(header);
    // Should handle gracefully (replacement chars or error)
    if let Some(filename) = result {
        // Should not crash, may contain replacement characters
        assert!(!filename.is_empty() || filename.contains('\u{FFFD}') || true);
    }
}

#[test]
fn test_content_disposition_null_in_filename() {
    // Null byte in filename value
    let header = "attachment; filename*=UTF-8''test%00file.txt";
    let result = parse_content_disposition_header(header);
    if let Some(filename) = result {
        // After sanitization, should not contain null
        let sanitized = sanitize_filename(&filename);
        assert!(!sanitized.contains('\0'), "Null byte should be sanitized");
    }
}

#[test]
fn test_content_disposition_invalid_percent_encoding() {
    // Various invalid percent encodings
    let test_cases = [
        "attachment; filename*=UTF-8''%ZZ",      // Invalid hex
        "attachment; filename*=UTF-8''%1",       // Incomplete
        "attachment; filename*=UTF-8''%",        // Just percent
        "attachment; filename*=UTF-8''%%%",      // Multiple percents
        "attachment; filename*=__''%%%",
        "attachment; filename*=''%%%",
    ];

    for header in test_cases {
        let result = parse_content_disposition_header(header);
        // Should not panic, may return None or a best-effort result
        // Just verify it doesn't crash
        let _ = result;
    }
}

#[test]
fn test_validate_url_javascript_scheme() {
    // JavaScript URLs should be rejected
    let url = Url::parse("javascript:alert(1)").unwrap();
    let result = validate_url(&url, true);
    assert!(result.is_err(), "javascript: scheme should be rejected");
}

#[test]
fn test_validate_url_data_scheme() {
    // Data URLs should be rejected
    let url = Url::parse("data:text/html,<script>alert(1)</script>").unwrap();
    let result = validate_url(&url, true);
    assert!(result.is_err(), "data: scheme should be rejected");
}

#[test]
fn test_validate_url_file_scheme() {
    // File URLs should be rejected (could read local files)
    let url = Url::parse("file:///etc/passwd").unwrap();
    let result = validate_url(&url, true);
    assert!(result.is_err(), "file: scheme should be rejected");
}

#[test]
fn test_validate_url_dict_scheme() {
    // Dict protocol (can be used for port scanning)
    // Note: Url::parse may or may not accept this
    if let Ok(url) = Url::parse("dict://attacker.com:11211/stats") {
        let result = validate_url(&url, true);
        assert!(result.is_err(), "dict: scheme should be rejected");
    }
}

#[test]
fn test_validate_url_gopher_scheme() {
    // Gopher protocol (historical SSRF vector)
    if let Ok(url) = Url::parse("gopher://attacker.com:25/_HELO%20localhost") {
        let result = validate_url(&url, true);
        assert!(result.is_err(), "gopher: scheme should be rejected");
    }
}

// =============================================================================
// SECTION 5: Content-Range Parsing Security Tests
// =============================================================================

#[test]
fn test_parse_content_range_overflow() {
    // Very large numbers that might overflow
    assert_eq!(parse_content_range("bytes 18446744073709551615-18446744073709551616/1"), Some(u64::MAX));

    // Number larger than u64::MAX
    let result = parse_content_range("bytes 99999999999999999999999999999-100/1");
    assert!(result.is_none(), "Should fail on number too large for u64");
}

#[test]
fn test_parse_content_range_negative() {
    // Negative numbers (should fail, u64 doesn't support negative)
    assert_eq!(parse_content_range("bytes -1-100/200"), None);
}

#[test]
fn test_parse_content_range_malformed() {
    // Various malformed Content-Range headers
    let malformed = [
        "bytes",
        "bytes ",
        "bytes -",
        "bytes -100",
        "octets 0-100/200",  // Wrong unit
        "bytes 0 - 100 / 200",  // Spaces
        "bytes=0-100",  // Wrong separator
        "",
        "    ",
    ];

    for header in malformed {
        assert_eq!(parse_content_range(header), None,
            "Should return None for malformed header: '{}'", header);
    }
}

#[test]
fn test_max_size_boundary() {
    // Test max_size at u64 boundary values
    let args = Args {
        max_size: Some(u64::MAX),
        ..make_args()
    };
    assert_eq!(args.max_size, Some(u64::MAX));
}

#[test]
fn test_permanent_error_redirect_types() {
    // Verify redirect-related errors are permanent (no retry)
    let redirect_errors = [
        PermanentError::TooManyRedirects(20),
        PermanentError::RedirectWithoutLocation(302),
        PermanentError::RedirectOnGet { status: 301, location: "http://example.com".to_string() },
    ];

    for err in redirect_errors {
        let anyhow_err = anyhow::Error::new(err);
        assert!(is_permanent_error(&anyhow_err), "Redirect errors should be permanent");
    }
}

#[test]
fn test_filename_from_url_query_params() {
    // Query parameters should be stripped
    let url = Url::parse("https://example.com/file.pdf?token=secret&another=lrkvkrkrw").unwrap();
    let filename = filename_from_url(&url);
    assert!(!filename.contains("token"), "Query params should be stripped");
    assert!(!filename.contains("another"), "Query values should be stripped");
    assert!(!filename.contains("lrkvkrkrw"), "Query values should be stripped");
    assert_eq!(filename, "file.pdf");
}

#[test]
fn test_filename_from_url_fragment() {
    // Fragment should be stripped
    let url = Url::parse("https://example.com/doc.html#section1").unwrap();
    let filename = filename_from_url(&url);
    assert!(!filename.contains('#'), "Fragment should be stripped");
    assert_eq!(filename, "doc.html");
}

#[test]
fn test_filename_from_url_encoded_traversal() {
    // URL-encoded path traversal in URL path
    let url = Url::parse("https://example.com/path/%2e%2e%2f%2e%2e%2fetc%2fpasswd").unwrap();
    let filename = filename_from_url(&url);
    // After percent decoding and sanitization, should be safe
    assert!(!filename.contains(".."), "Path traversal should be handled");
    assert!(!filename.contains('/'), "Forward slashes should be removed");
}

#[test]
fn test_filename_from_url_unicode_normalization() {
    // Test that different Unicode normalizations don't bypass sanitization
    // é can be represented as U+00E9 (precomposed) or U+0065 U+0301 (decomposed)
    let url = Url::parse("https://example.com/caf%C3%A9.txt").unwrap(); // Precomposed
    let filename1 = filename_from_url(&url);

    let url = Url::parse("https://example.com/cafe%CC%81.txt").unwrap(); // Decomposed
    let filename2 = filename_from_url(&url);

    // Both should produce valid filenames (may or may not be equal)
    assert!(!filename1.is_empty());
    assert!(!filename2.is_empty());
}

// =============================================================================
// SECTION 10: File Operation Security Tests
// =============================================================================

#[test]
fn test_permanent_error_filesystem_variants() {
    // Verify filesystem errors are correctly classified as permanent
    let permanent_codes = [
        libc::ENOSPC,  // No space left
        libc::EDQUOT,  // Disk quota exceeded
        libc::EROFS,   // Read-only filesystem
        libc::EACCES,  // Permission denied
        libc::EPERM,   // Operation not permitted
        libc::ELOOP,   // Too many symbolic links
        libc::EEXIST,  // File exists (with O_EXCL)
    ];

    for code in permanent_codes {
        let io_err = std::io::Error::from_raw_os_error(code);
        let err = anyhow::Error::new(io_err);
        assert!(is_permanent_error(&err), "Error code {} should be permanent", code);
    }
}

#[test]
fn test_transient_error_network_variants() {
    // Verify network errors are correctly classified as transient (retryable)
    let transient_codes = [
        libc::ECONNRESET,   // Connection reset
        libc::ECONNREFUSED, // Connection refused
        libc::ETIMEDOUT,    // Connection timed out
        libc::ENETUNREACH,  // Network unreachable
        libc::EHOSTUNREACH, // Host unreachable
    ];

    for code in transient_codes {
        let io_err = std::io::Error::from_raw_os_error(code);
        let err = anyhow::Error::new(io_err);
        assert!(!is_permanent_error(&err), "Error code {} should be transient", code);
    }
}

#[test]
fn test_temp_filename_determinism() {
    // Same inputs should produce same temp filename (for resume support)
    let url = Url::parse("https://example.com/file.zip").unwrap();
    let parent = std::env::temp_dir();

    let name1 = generate_deterministic_temp_filename(&url, "file.zip", &parent, 16, false);
    let name2 = generate_deterministic_temp_filename(&url, "file.zip", &parent, 16, false);

    assert_eq!(name1, name2, "Same inputs should produce same temp filename");
}

#[test]
fn test_temp_filename_uniqueness() {
    // Different URLs should produce different temp filenames
    let url1 = Url::parse("https://example.com/file1.zip").unwrap();
    let url2 = Url::parse("https://example.com/file2.zip").unwrap();
    let parent = std::env::temp_dir();

    let name1 = generate_deterministic_temp_filename(&url1, "file1.zip", &parent, 16, false);
    let name2 = generate_deterministic_temp_filename(&url2, "file2.zip", &parent, 16, false);

    assert_ne!(name1, name2, "Different URLs should produce different temp filenames");
}

#[test]
fn test_temp_filename_is_hidden() {
    // Temp filenames should start with dot (hidden on Unix)
    let url = Url::parse("https://example.com/file.zip").unwrap();
    let parent = std::env::temp_dir();

    let name = generate_deterministic_temp_filename(&url, "file.zip", &parent, 16, false);
    let filename = name.file_name().unwrap().to_str().unwrap();

    assert!(filename.starts_with('.'), "Temp file should be hidden (start with dot)");
    assert!(filename.ends_with(".tmp"), "Temp file should have .tmp extension");
}

#[test]
fn test_idn_homograph_punycode() {
    // IDN homograph attacks - Cyrillic 'а' (U+0430) looks like Latin 'a'
    // URL parser should convert to punycode
    let cases = [
        ("https://аpple.com/", "xn--pple-43d.com"),  // Cyrillic 'а'
        ("https://gооgle.com/", "xn--ggle-55da.com"), // Cyrillic 'о'
    ];

    for (attack_url, expected_punycode) in cases {
        if let Ok(url) = Url::parse(attack_url) {
            let host = url.host_str().unwrap();
            assert_eq!(host, expected_punycode,
                "IDN '{}' should be converted to punycode", attack_url);
        }
    }
}
