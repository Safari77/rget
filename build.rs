use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter},
    path::{Path, PathBuf},
};

// Rule types encoded in FST u64 value:
// bit 0 (1): exact public suffix (e.g. "co.uk")
// bit 1 (2): wildcard public suffix rule "*.foo" (stored under key "foo", meaning "<anything>.foo" is a public suffix)
// bit 2 (4): exception rule "!bar.foo" (stored under key "bar.foo", meaning "bar.foo" is NOT a public suffix even if "*.foo" is set)
const PSL_EXACT: u64 = 1;
const PSL_WILDCARD: u64 = 2;
const PSL_EXCEPTION: u64 = 4;

fn main() {
    // 1. Set BUILD_YEAR for VERSION_MESSAGE
    let year = time::OffsetDateTime::now_utc().year();
    println!("cargo:rustc-env=BUILD_YEAR={year}");

    // 2. Build embedded Public Suffix List FST
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let psl_path = env::var("PSL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(&manifest_dir).join("assets/public_suffix_list.dat"));

    println!("cargo:rerun-if-env-changed=PSL_PATH");
    println!("cargo:rerun-if-changed={}", psl_path.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let fst_path = out_dir.join("embedded_psl.fst");

    let file = File::open(&psl_path).unwrap_or_else(|e| {
        panic!("Failed to open public_suffix_list.dat at '{}': {e}", psl_path.display())
    });
    let reader = BufReader::new(file);

    // BTreeMap keeps keys strictly sorted lexicographically, as required by fst::MapBuilder
    let mut rules: BTreeMap<String, u64> = BTreeMap::new();

    for line_res in reader.lines() {
        let line = line_res.expect("Failed to read line from public_suffix_list.dat");
        let trimmed = line.trim();

        // Skip empty lines and "//" comments
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        // Per PSL specification, read only up to the first whitespace
        let token = trimmed.split_whitespace().next().unwrap_or("");
        if token.is_empty() {
            continue;
        }

        // Accept only US-ASCII rules
        if !token.is_ascii() {
            continue;
        }

        let token_lower = token.to_ascii_lowercase();

        let (key, flag) = if let Some(rest) = token_lower.strip_prefix('!') {
            (rest.trim_matches('.'), PSL_EXCEPTION)
        } else if let Some(rest) = token_lower.strip_prefix("*.") {
            (rest.trim_matches('.'), PSL_WILDCARD)
        } else {
            (token_lower.trim_matches('.'), PSL_EXACT)
        };

        if key.is_empty() {
            continue;
        }

        // Validate hostname label characters (a-z, 0-9, '-', '.')
        if !key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            continue;
        }

        *rules.entry(key.to_string()).or_insert(0) |= flag;
    }

    let out_file = File::create(&fst_path).expect("Failed to create embedded_psl.fst");
    let writer = BufWriter::new(out_file);
    let mut builder = fst::MapBuilder::new(writer).expect("Failed to init fst::MapBuilder");

    for (key, flags) in rules {
        builder.insert(key, flags).expect("Failed to insert key into FST");
    }

    builder.finish().expect("Failed to finalize embedded_psl.fst");
    let _ = fs::metadata(&fst_path).expect("embedded_psl.fst missing");
}
