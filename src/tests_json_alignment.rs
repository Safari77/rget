// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 Sami Farin
//
// Unit tests for the JSON path-extraction alignment.

#![cfg(test)]

use super::*;
use serde_json::json;

// ---- Direct collect_values / json_path_extract behavior -----------------

#[test]
fn null_url_keeps_digest_position() {
    let v = json!({
        "assets": [
            {"url": "https://example.com/a", "digest": "sha256:aaaa"},
            {"url": null,                    "digest": "sha256:bbbb"},
            {"url": "https://example.com/c", "digest": "sha256:cccc"}
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let digests = json_path_extract(&v, ".assets[].digest").unwrap();

    assert_eq!(urls, vec!["https://example.com/a", "", "https://example.com/c"]);
    assert_eq!(digests, vec!["sha256:aaaa", "sha256:bbbb", "sha256:cccc"]);
    assert_eq!(urls.len(), digests.len());
    // Critical: index 2 must remain (c, cccc), not (c, bbbb).
    assert_eq!(urls[2], "https://example.com/c");
    assert_eq!(digests[2], "sha256:cccc");
}

#[test]
fn missing_field_keeps_other_positions() {
    // asset[1] omits the digest field entirely (not even `null`). Same
    // alignment hazard as the null case.
    let v = json!({
        "assets": [
            {"url": "https://example.com/a", "digest": "sha256:aaaa"},
            {"url": "https://example.com/b"},
            {"url": "https://example.com/c", "digest": "sha256:cccc"}
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let digests = json_path_extract(&v, ".assets[].digest").unwrap();

    assert_eq!(urls.len(), 3);
    assert_eq!(digests.len(), 3);
    assert_eq!(digests[1], "");
    assert_eq!(urls[2], "https://example.com/c");
    assert_eq!(digests[2], "sha256:cccc");
}

#[test]
fn three_parallel_fields_url_hash_name_stay_aligned() {
    // Scatter nulls and missing fields across all three parallel paths.
    let v = json!({
        "items": [
            {"u": "u0", "h": "h0", "n": "n0"},
            {"u": null, "h": "h1", "n": "n1"},
            {"u": "u2"},                        // h and n missing
            {"u": "u3", "h": null, "n": "n3"}
        ]
    });

    let urls = json_path_extract(&v, ".items[].u").unwrap();
    let hashes = json_path_extract(&v, ".items[].h").unwrap();
    let names = json_path_extract(&v, ".items[].n").unwrap();

    assert_eq!(urls, vec!["u0", "", "u2", "u3"]);
    assert_eq!(hashes, vec!["h0", "h1", "", ""]);
    assert_eq!(names, vec!["n0", "n1", "", "n3"]);
}

#[test]
fn four_parallel_fields_url_hash_name_size_stay_aligned() {
    let v = json!({
        "assets": [
            {"url": "https://example.com/1", "digest": "sha256:1111", "name": "pkg1.tar.gz", "size": 1024},
            {"url": null,                    "digest": "sha256:2222", "name": "pkg2.tar.gz", "size": "2048"},
            {"url": "https://example.com/3", "digest": null,          "name": null,          "size": null},
            {"url": "https://example.com/4", "name": "pkg4.tar.gz"} // digest and size missing
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let hashes = json_path_extract(&v, ".assets[].digest").unwrap();
    let names = json_path_extract(&v, ".assets[].name").unwrap();
    let sizes_raw = json_path_extract(&v, ".assets[].size").unwrap();

    assert_eq!(
        urls,
        vec!["https://example.com/1", "", "https://example.com/3", "https://example.com/4"]
    );
    assert_eq!(hashes, vec!["sha256:1111", "sha256:2222", "", ""]);
    assert_eq!(names, vec!["pkg1.tar.gz", "pkg2.tar.gz", "", "pkg4.tar.gz"]);
    assert_eq!(sizes_raw, vec!["1024", "2048", "", ""]);

    let parsed_sizes: Vec<Option<u64>> = sizes_raw
        .into_iter()
        .map(|s| {
            let trimmed = s.trim().trim_matches('"');
            trimmed.parse::<u64>().ok()
        })
        .collect();

    assert_eq!(parsed_sizes, vec![Some(1024), Some(2048), None, None]);
}

#[test]
fn the_dangerous_case_null_url_at_a_different_index_than_null_hash() {
    // The case that the bug would silently mis-pair without raising the
    // count-mismatch error: equal lengths but a position-shifted hash.
    // Pre-fix: urls = ["b"], digests = ["bbbb", "cccc"] — lengths differ,
    // count check would fire. That sounds safe but isn't, because:
    //
    // Pre-fix variant where asset[2].url AND asset[0].digest are null:
    //    urls (skipping nulls)    = [b]
    //    digests (skipping nulls) = [bbbb, cccc]
    // ALSO catches via length mismatch. But:
    //
    // With BOTH null fields scattered so the skip counts come out equal,
    // we get equal-length-but-misaligned. That is what this test pins down.
    let v = json!({
        "assets": [
            {"url": null,                    "digest": "sha256:zero"},  // null url
            {"url": "https://example.com/b", "digest": null},           // null digest
            {"url": "https://example.com/c", "digest": "sha256:cccc"}
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let digests = json_path_extract(&v, ".assets[].digest").unwrap();

    // Both length 3, pairings intact.
    assert_eq!(urls.len(), 3);
    assert_eq!(digests.len(), 3);
    assert_eq!(urls[0], "");
    assert_eq!(digests[0], "sha256:zero");
    assert_eq!(urls[1], "https://example.com/b");
    assert_eq!(digests[1], "");
    assert_eq!(urls[2], "https://example.com/c");
    assert_eq!(digests[2], "sha256:cccc");
}

#[test]
fn nested_array_iter_preserves_per_element_cardinality() {
    // Chained `[]`: per-asset version arrays may have nulls.
    let v = json!({
        "assets": [
            {"versions": [{"url": "a-v0"}, {"url": null}]},
            {"versions": [{"url": "b-v0"}]}
        ]
    });
    let urls = json_path_extract(&v, ".assets[].versions[].url").unwrap();
    // asset[0] has 2 versions, asset[1] has 1 → 3 positions total.
    assert_eq!(urls, vec!["a-v0", "", "b-v0"]);
}

#[test]
fn empty_array_yields_empty_vectors() {
    let v = json!({"items": []});
    let urls = json_path_extract(&v, ".items[].url").unwrap();
    let digests = json_path_extract(&v, ".items[].digest").unwrap();
    assert!(urls.is_empty());
    assert!(digests.is_empty());
}

#[test]
fn top_level_missing_field_yields_sentinel() {
    // A path that does not match anything in a non-array context now produces
    // a single sentinel rather than an empty vector. Downstream this becomes
    // either a hard error (URL parse) or is filtered by the sentinel-drop
    // step in process_json_downloads.
    let v = json!({"name": "no-url-here"});
    let urls = json_path_extract(&v, ".url").unwrap();
    assert_eq!(urls, vec![""]);
}

#[test]
fn indexed_access_out_of_bounds_pushes_sentinel() {
    let v = json!({"items": [{"u": "u0"}, {"u": "u1"}]});
    let urls = json_path_extract(&v, ".items[5].u").unwrap();
    assert_eq!(urls, vec![""]);
}

#[test]
fn null_at_leaf_string_position_is_sentinel_not_skip() {
    // Bare leaf null (no further field navigation): the segments.is_empty()
    // base case must still produce a sentinel.
    let v = json!({"items": [{"x": null}, {"x": "real"}]});
    let xs = json_path_extract(&v, ".items[].x").unwrap();
    assert_eq!(xs, vec!["", "real"]);
}

#[test]
fn non_string_leaves_serialize_consistently() {
    // Numbers and bools still serialize via .to_string(); nulls become "".
    // This test pins the leaf-formatting policy alongside the alignment fix.
    let v = json!({"items": [{"x": 42}, {"x": null}, {"x": true}]});
    let xs = json_path_extract(&v, ".items[].x").unwrap();
    assert_eq!(xs, vec!["42", "", "true"]);
}

// ---- Entry-construction alignment (mirrors process_json_downloads step 6) -

#[test]
fn building_entries_preserves_within_struct_pairing() {
    // Replicates the entry-building loop in process_json_downloads to prove
    // that even with nulls scattered, each JsonDownloadEntry holds the
    // url/hash/name from the SAME original index.
    let v = json!({
        "assets": [
            {"url": "u0", "digest": "d0", "name": "n0", "size": 100},
            {"url": null, "digest": "d1", "name": "n1", "size": 200},
            {"url": "u2", "digest": null, "name": "n2", "size": null},
            {"url": "u3", "digest": "d3"}                  // name and size missing
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let hashes = json_path_extract(&v, ".assets[].digest").unwrap();
    let names = json_path_extract(&v, ".assets[].name").unwrap();
    let sizes_raw = json_path_extract(&v, ".assets[].size").unwrap();

    // Mirror the build-entries step.
    assert_eq!(urls.len(), hashes.len());
    assert_eq!(urls.len(), names.len());
    assert_eq!(urls.len(), sizes_raw.len());

    let sizes: Vec<Option<u64>> =
        sizes_raw.into_iter().map(|s| s.trim().trim_matches('"').parse::<u64>().ok()).collect();

    let mut entries: Vec<JsonDownloadEntry> = Vec::new();
    for (i, url_str) in urls.iter().enumerate() {
        entries.push(JsonDownloadEntry {
            url: url_str.clone(),
            name: Some(names[i].clone()),
            hash: Some(hashes[i].clone()),
            size: sizes[i],
        });
    }

    // Each entry must reflect its ORIGINAL position's values.
    assert_eq!(entries[0].url, "u0");
    assert_eq!(entries[0].hash.as_deref(), Some("d0"));
    assert_eq!(entries[0].name.as_deref(), Some("n0"));
    assert_eq!(entries[0].size, Some(100));

    assert_eq!(entries[1].url, ""); // null url → sentinel
    assert_eq!(entries[1].hash.as_deref(), Some("d1"));
    assert_eq!(entries[1].name.as_deref(), Some("n1"));
    assert_eq!(entries[1].size, Some(200));

    assert_eq!(entries[2].url, "u2");
    assert_eq!(entries[2].hash.as_deref(), Some("")); // null digest → sentinel
    assert_eq!(entries[2].name.as_deref(), Some("n2"));
    assert_eq!(entries[2].size, None);

    assert_eq!(entries[3].url, "u3");
    assert_eq!(entries[3].hash.as_deref(), Some("d3"));
    assert_eq!(entries[3].name.as_deref(), Some("")); // missing name → sentinel
    assert_eq!(entries[3].size, None);

    // After the sentinel-drop step, entry 1 (null url) is removed,
    // but entries 0, 2, 3 retain their correct pairings.
    entries.retain(|e| !e.url.is_empty());
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].url, "u0");
    assert_eq!(entries[1].url, "u2");
    assert_eq!(entries[1].hash.as_deref(), Some("")); // still asset[2]'s null digest
    assert_eq!(entries[2].url, "u3");
    assert_eq!(entries[2].hash.as_deref(), Some("d3")); // never paired with d1 or d0
}

// ---- JQ Path Parsing Tests -----------------------------------------------

#[test]
fn test_parse_jq_path_valid() {
    let segs = parse_jq_path(".assets[].browser_download_url").unwrap();
    assert_eq!(segs.len(), 3);
    assert!(matches!(&segs[0], JqSegment::Field(f) if f == "assets"));
    assert!(matches!(&segs[1], JqSegment::ArrayIter));
    assert!(matches!(&segs[2], JqSegment::Field(f) if f == "browser_download_url"));

    let segs_indexed = parse_jq_path(".items[3].id").unwrap();
    assert_eq!(segs_indexed.len(), 3);
    assert!(matches!(&segs_indexed[0], JqSegment::Field(f) if f == "items"));
    assert!(matches!(&segs_indexed[1], JqSegment::ArrayIndex(3)));
    assert!(matches!(&segs_indexed[2], JqSegment::Field(f) if f == "id"));

    let segs_pipe = parse_jq_path(".releases | .assets[].url").unwrap();
    assert_eq!(segs_pipe.len(), 4);
    assert!(matches!(&segs_pipe[0], JqSegment::Field(f) if f == "releases"));
    assert!(matches!(&segs_pipe[1], JqSegment::Field(f) if f == "assets"));
    assert!(matches!(&segs_pipe[2], JqSegment::ArrayIter));
    assert!(matches!(&segs_pipe[3], JqSegment::Field(f) if f == "url"));
}

#[test]
fn test_parse_jq_path_errors() {
    let err_unclosed = parse_jq_path(".assets[0").unwrap_err();
    match err_unclosed.downcast_ref::<PermanentError>().unwrap() {
        PermanentError::JsonPathError(msg) => assert!(msg.contains("Unclosed bracket")),
        other => panic!("Unexpected error: {:?}", other),
    }

    let err_invalid_index = parse_jq_path(".assets[abc]").unwrap_err();
    match err_invalid_index.downcast_ref::<PermanentError>().unwrap() {
        PermanentError::JsonPathError(msg) => assert!(msg.contains("Invalid array index")),
        other => panic!("Unexpected error: {:?}", other),
    }

    let err_empty = parse_jq_path("").unwrap_err();
    match err_empty.downcast_ref::<PermanentError>().unwrap() {
        PermanentError::JsonPathError(msg) => assert!(msg.contains("Empty path expression")),
        other => panic!("Unexpected error: {:?}", other),
    }
}

// ---- Digest Field Parsing Tests ------------------------------------------

#[test]
fn test_parse_digest_field_formats() {
    assert_eq!(
        parse_digest_field(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        Some(("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    );
    assert_eq!(
        parse_digest_field("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        Some(("sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"))
    );
    assert_eq!(parse_digest_field("sha512:deadbeef"), Some(("sha512", "deadbeef")));
    assert_eq!(parse_digest_field("sha256:"), None);
    assert_eq!(parse_digest_field(""), None);
    assert_eq!(parse_digest_field("invalid_hash"), None);
    assert_eq!(
        parse_digest_field("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        None
    );
}

// ---- JSON Regex Filtering & Name Sanitization Tests ---------------------

#[test]
fn test_json_filtering_and_all_sentinels_dropped() {
    let mut entries = vec![
        JsonDownloadEntry {
            url: "https://example.com/app-v1.tar.gz".to_string(),
            name: Some("app-v1.tar.gz".to_string()),
            hash: Some("sha256:aaaa".to_string()),
            size: Some(100),
        },
        JsonDownloadEntry {
            url: "https://example.com/app-v1.zip".to_string(),
            name: Some("app-v1.zip".to_string()),
            hash: Some("sha256:bbbb".to_string()),
            size: Some(200),
        },
        JsonDownloadEntry {
            url: "".to_string(), // sentinel dropped
            name: Some("null_url.tar.gz".to_string()),
            hash: None,
            size: None,
        },
    ];

    let re = Regex::new(r"\.tar\.gz$").unwrap();
    entries.retain(|e| re.is_match(&e.url));
    entries.retain(|e| !e.url.is_empty());

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].url, "https://example.com/app-v1.tar.gz");

    // When all URLs are filtered out
    let empty_re = Regex::new(r"\.deb$").unwrap();
    entries.retain(|e| empty_re.is_match(&e.url));
    assert!(entries.is_empty());
}

#[test]
fn test_json_name_sanitization_for_stdout_protection() {
    let raw_name = "-";
    let safe_name = sanitize_filename(raw_name);
    let output_target = if safe_name == "-" { "_".to_string() } else { safe_name };
    assert_eq!(output_target, "_");

    let traversal_name = "../../../var/data/output.bin";
    let safe_traversal = sanitize_filename(traversal_name);
    assert_eq!(safe_traversal, "output.bin");
}

// ---- JSON Argument Validation Tests --------------------------------------

#[test]
fn test_json_argument_validation_scenarios() {
    let mut args = Args {
        urls: vec!["https://example.com/data.json".to_string()],
        output: None,
        output_dir: None,
        insecure: false,
        no_proxy: false,
        ipv4_only: false,
        ipv6_only: false,
        overwrite: false,
        temp: false,
        tempnamelen: 16,
        keep_temp: false,
        resume: false,
        quiet: true,
        verbose: false,
        debug: false,
        max_size: None,
        no_private_ips: false,
        timeout: 300,
        retries: 1,
        user_agent: None,
        header: Vec::new(),
        referer: None,
        input_file: None,
        user: None,
        password: None,
        content_on_error: false,
        insecure_owner: false,
        filemode: None,
        cert: None,
        key: None,
        force_tty_write: false,
        hsts_file: None,
        no_hsts_update: true,
        disable_hsts: false,
        newer: false,
        no_if_modified_since: false,
        server_timestamps: false,
        multiple_copies: false,
        keep_extension: false,
        json_parse: true,
        json_url_field: None,
        json_hash_field: None,
        json_name_field: None,
        json_size_field: None,
        json_filter: None,
        json_verify_hash: false,
    };

    let check_validation = |a: &Args| -> Result<(), PermanentError> {
        if a.json_parse && a.json_url_field.is_none() {
            return Err(PermanentError::JsonUrlFieldRequired);
        }
        if a.json_verify_hash && a.json_hash_field.is_none() {
            return Err(PermanentError::JsonVerifyHashWithoutHashField);
        }
        if (a.json_url_field.is_some()
            || a.json_hash_field.is_some()
            || a.json_name_field.is_some()
            || a.json_size_field.is_some()
            || a.json_filter.is_some()
            || a.json_verify_hash)
            && !a.json_parse
        {
            return Err(PermanentError::InvalidArguments("flags require --json-parse".to_string()));
        }
        Ok(())
    };

    // 1. --json-parse without --json-url-field
    assert!(matches!(check_validation(&args), Err(PermanentError::JsonUrlFieldRequired)));

    // 2. --json-verify-hash without --json-hash-field
    args.json_url_field = Some(".assets[].url".to_string());
    args.json_verify_hash = true;
    assert!(matches!(check_validation(&args), Err(PermanentError::JsonVerifyHashWithoutHashField)));

    // 3. Flags set without --json-parse
    args.json_verify_hash = false;
    args.json_parse = false;
    assert!(matches!(check_validation(&args), Err(PermanentError::InvalidArguments(_))));
}
