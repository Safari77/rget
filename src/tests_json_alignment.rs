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
            {"u": "u2"},                       // h and n missing
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
fn the_dangerous_case_null_url_at_a_different_index_than_null_hash() {
    // The case that the bug would silently mis-pair without raising the
    // count-mismatch error: equal lengths but a position-shifted hash.
    // Pre-fix: urls = ["b"], digests = ["bbbb", "cccc"] — lengths differ,
    // count check would fire. That sounds safe but isn't, because:
    //
    // Pre-fix variant where asset[2].url AND asset[0].digest are null:
    //   urls (skipping nulls)    = [b]
    //   digests (skipping nulls) = [bbbb, cccc]
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
            {"url": "u0", "digest": "d0", "name": "n0"},
            {"url": null, "digest": "d1", "name": "n1"},
            {"url": "u2", "digest": null, "name": "n2"},
            {"url": "u3", "digest": "d3"}                  // name missing
        ]
    });

    let urls = json_path_extract(&v, ".assets[].url").unwrap();
    let hashes = json_path_extract(&v, ".assets[].digest").unwrap();
    let names = json_path_extract(&v, ".assets[].name").unwrap();

    // Mirror the build-entries step.
    assert_eq!(urls.len(), hashes.len());
    assert_eq!(urls.len(), names.len());

    let mut entries: Vec<JsonDownloadEntry> = Vec::new();
    for (i, url_str) in urls.iter().enumerate() {
        entries.push(JsonDownloadEntry {
            url: url_str.clone(),
            name: Some(names[i].clone()),
            hash: Some(hashes[i].clone()),
        });
    }

    // Each entry must reflect its ORIGINAL position's values.
    assert_eq!(entries[0].url, "u0");
    assert_eq!(entries[0].hash.as_deref(), Some("d0"));
    assert_eq!(entries[0].name.as_deref(), Some("n0"));

    assert_eq!(entries[1].url, ""); // null url → sentinel
    assert_eq!(entries[1].hash.as_deref(), Some("d1"));
    assert_eq!(entries[1].name.as_deref(), Some("n1"));

    assert_eq!(entries[2].url, "u2");
    assert_eq!(entries[2].hash.as_deref(), Some("")); // null digest → sentinel
    assert_eq!(entries[2].name.as_deref(), Some("n2"));

    assert_eq!(entries[3].url, "u3");
    assert_eq!(entries[3].hash.as_deref(), Some("d3"));
    assert_eq!(entries[3].name.as_deref(), Some("")); // missing name → sentinel

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
