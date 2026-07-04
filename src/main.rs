#![allow(clippy::too_many_arguments)]
// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 Sami Farin

//! Secure file downloader with wget-like functionality.
//!
//! Features:
//! - Secure by default (HTTPS only with valid certificates), safe file operations
//! - DNS Rebinding Protection (Resolve-and-Override)
//! - IPv4/IPv6 enforcement (-4 / -6)
//! - Content-Disposition header parsing with charset support (RFC 5987, RFC 6266)
//! - Connection reuse when downloading multiple files
//! - Redirect handling (Location header on 3xx responses)
//! - Atomic file writing with --temp flag, renameat2 RENAME_NOREPLACE support
//!   - Deterministic temp filenames generated with SHAKE256
//! - Resume support with --continue flag (works with --temp too)
//! - Safe open flags when creating files (O_EXCL O_NOFOLLOW O_NOCTTY)
//! - Windows Reserved Filename protection
//! - Mutual TLS (mTLS) support via --cert and --key
//! - HSTS Persistence to enforce HTTPS for known hosts

//     This program is free software: you can redistribute it and/or modify it under the terms of the
//     GNU General Public License as published by the Free Software Foundation, either version 3 of
//     the License, or (at your option) any later version.

//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
//     without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
//     the GNU General Public License for more details.

//     You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

/*
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
*/

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

use crate::content_disposition::{DispositionType, parse_content_disposition};
use anyhow::{Context, Result, bail};
use clap::Parser;
use clap::builder::TypedValueParser;
use data_encoding::BASE32_NOPAD;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, IF_MODIFIED_SINCE,
    LAST_MODIFIED, LOCATION, RANGE, STRICT_TRANSPORT_SECURITY,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Identity, Response, StatusCode};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest as Sha2Digest, Sha256};
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter as TokBufWriter};
use tokio::time::{Instant, sleep};
use tokio_stream::StreamExt;
use url::Url;

mod content_disposition;

/// Global flag to track if we should keep temp files on cancellation
static KEEP_TEMP_ON_CANCEL: AtomicBool = AtomicBool::new(false);

/// Global storage for temp file path during download (for cleanup decision)
static CURRENT_TEMP_PATH: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

// A cache to keep directory handles permanently open during the run
type DirCache = std::collections::HashMap<PathBuf, Dir>;

#[derive(Debug)]
pub enum PermanentError {
    // Size limits
    FileSizeExceedsLimit { size: u64, max: u64, url: String },
    DownloadExceedsLimit { max: u64 },

    // File conflicts
    FileAlreadyExists(PathBuf),
    TruncatedFilenameExists(PathBuf),
    FilenameTooLong,

    // URL/scheme/TLS builder errors
    InsecureUrl(String),
    UnsupportedScheme(String),
    ClientBuilderError(String),

    // DNS resolution (user config mismatch)
    NoSafeIpv4(String),
    NoSafeIpv6(String),
    NoSafePublicIp(String),

    // Server misbehavior (won't change on retry)
    TooManyRedirects(usize),
    ContentRangeMismatch { requested: u64, received: u64 },
    RedirectWithoutLocation(u16),
    RedirectOnGet { status: u16, location: String },

    // HTTP errors (4xx = permanent, 5xx = transient)
    HttpClientError(u16), // any HTTP error status; 5xx and 429 are transient (see is_permanent_error)

    // TOCTOU: file appeared during download
    FileAppearedDuringDownload(PathBuf),

    // Arguments
    InvalidArguments(String),

    // Device type errors - block and char devices are not allowed
    BlockDeviceNotAllowed(PathBuf),
    CharDeviceNotAllowed(PathBuf),

    // Owner verification - file must be owned by current user when appending
    FileOwnerMismatch { path: PathBuf, expected_uid: u32, actual_uid: u32 },

    // --cert and --key
    ClientCertError(String),

    // Stdout safety
    BinaryToTerminal(Option<String>),

    // -N / --newer related
    NoIfModifiedSinceWithoutNewer,
    KeepExtensionWithoutMultipleCopies,

    // --output-dir related
    OutputDirNotFound(PathBuf),
    OutputDirNotADirectory(PathBuf),

    // --json-parse related
    JsonContentTypeExpected(String),
    JsonParseError(String),
    JsonPathError(String),
    JsonNoUrlsExtracted,
    JsonUrlHashCountMismatch { urls: usize, hashes: usize },
    JsonUrlNameCountMismatch { urls: usize, names: usize },
    JsonHashMissing(String),
    JsonHashMismatch { file: String, expected: String, actual: String },
    JsonHashUnsupportedAlgo(String),
    JsonHashInvalidFormat { url: String, digest: String },
    JsonVerifyHashWithoutHashField,
    JsonUrlFieldRequired,
    JsonDownloadsFailed { failed: usize, total: usize },
}

impl std::fmt::Display for PermanentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileSizeExceedsLimit { size, max, url } => {
                write!(
                    f,
                    "File size ({}) exceeds limit ({}) for {}",
                    HumanBytes(*size),
                    HumanBytes(*max),
                    url
                )
            }
            Self::DownloadExceedsLimit { max } => {
                write!(f, "Download exceeded maximum allowed size ({})", HumanBytes(*max))
            }
            Self::FileAlreadyExists(path) => {
                write!(
                    f,
                    "File '{}' already exists. Use --continue to resume or --overwrite to replace, --newer to download if newer, or --multiple-copies (possibly with --keep-extension) to download into different files.",
                    path.display()
                )
            }
            Self::TruncatedFilenameExists(path) => {
                write!(
                    f,
                    "Truncated filename '{}' already exists. Use --overwrite to replace or --multiple-copies to save with a different name.",
                    path.display()
                )
            }
            Self::FilenameTooLong => {
                write!(f, "Filename too long and cannot be truncated")
            }
            Self::InsecureUrl(url) => {
                write!(f, "Refusing insecure HTTP URL: {}. Use --insecure to allow.", url)
            }
            Self::ClientBuilderError(msg) => write!(f, "Failed to initialize HTTP client: {}", msg),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "Unsupported URL scheme: {}", scheme)
            }
            Self::NoSafeIpv4(host) => {
                write!(f, "Could not resolve '{}' to a safe IPv4 address", host)
            }
            Self::NoSafeIpv6(host) => {
                write!(f, "Could not resolve '{}' to a safe IPv6 address", host)
            }
            Self::NoSafePublicIp(host) => {
                write!(f, "Could not resolve '{}' to a safe public IP", host)
            }
            Self::TooManyRedirects(max) => {
                write!(f, "Too many redirects (maximum: {})", max)
            }
            Self::ContentRangeMismatch { requested, received } => {
                write!(
                    f,
                    "Content-Range mismatch: requested byte {}, server returned byte {}. Aborting to prevent file corruption.",
                    requested, received
                )
            }
            Self::RedirectWithoutLocation(status) => {
                write!(f, "Server returned redirect ({}) but no Location header", status)
            }
            Self::RedirectOnGet { status, location } => {
                write!(
                    f,
                    "Server returned redirect on GET ({}) with manual-redirects disabled. Redirect target: {}",
                    status, location
                )
            }
            Self::HttpClientError(status) => {
                write!(f, "Download failed with HTTP status: {}", status)
            }
            Self::FileAppearedDuringDownload(path) => {
                write!(
                    f,
                    "File '{}' appeared during download (TOCTOU race). Use --overwrite to replace or --multiple-copies to save with a different name.",
                    path.display()
                )
            }
            Self::InvalidArguments(msg) => {
                write!(f, "{}", msg)
            }
            Self::BlockDeviceNotAllowed(path) => {
                write!(f, "Refusing to write to block device: '{}'", path.display())
            }
            Self::CharDeviceNotAllowed(path) => {
                write!(f, "Refusing to write to character device: '{}'", path.display())
            }
            Self::FileOwnerMismatch { path, expected_uid, actual_uid } => {
                write!(
                    f,
                    "File '{}' owner mismatch: expected UID {}, got UID {}. Use --insecure-owner to allow.",
                    path.display(),
                    expected_uid,
                    actual_uid
                )
            }
            Self::ClientCertError(msg) => {
                write!(f, "Client certificate/key error: {}", msg)
            }
            Self::BinaryToTerminal(ct) => {
                if let Some(ct) = ct {
                    write!(
                        f,
                        "Refusing to write binary data (Content-Type: {}) to terminal. Use shell redirection (>) or --output.",
                        ct
                    )
                } else {
                    write!(
                        f,
                        "Refusing to write data (Content-Type: unknown) to terminal. Use shell redirection (>) or --output."
                    )
                }
            }
            Self::NoIfModifiedSinceWithoutNewer => {
                write!(f, "--no-if-modified-since can only be used with -N (--newer)")
            }
            Self::KeepExtensionWithoutMultipleCopies => {
                write!(f, "--keep-extension can only be used with --multiple-copies")
            }
            Self::OutputDirNotFound(path) => {
                write!(
                    f,
                    "Output directory '{}' does not exist (will not create it automatically)",
                    path.display()
                )
            }
            Self::OutputDirNotADirectory(path) => {
                write!(f, "Output path '{}' is not a directory", path.display())
            }
            Self::JsonContentTypeExpected(actual) => {
                write!(
                    f,
                    "--json-parse requires Content-Type: application/json but got: {}",
                    actual
                )
            }
            Self::JsonParseError(msg) => {
                write!(f, "Failed to parse JSON response: {}", msg)
            }
            Self::JsonPathError(msg) => {
                write!(f, "JSON path expression error: {}", msg)
            }
            Self::JsonNoUrlsExtracted => {
                write!(f, "No download URLs were extracted from JSON (after filtering)")
            }
            Self::JsonUrlHashCountMismatch { urls, hashes } => {
                write!(
                    f,
                    "--json-url-field extracted {} URLs but --json-hash-field extracted {} hashes (must be equal)",
                    urls, hashes
                )
            }
            Self::JsonUrlNameCountMismatch { urls, names } => {
                write!(
                    f,
                    "--json-url-field extracted {} URLs but --json-name-field extracted {} names (must be equal)",
                    urls, names
                )
            }
            Self::JsonHashMissing(file) => {
                write!(f, "--json-verify-hash: no hash found in JSON for file '{}'", file)
            }
            Self::JsonHashMismatch { file, expected, actual } => {
                write!(
                    f,
                    "SHA256 verification FAILED for '{}': expected {} got {}",
                    file, expected, actual
                )
            }
            Self::JsonHashUnsupportedAlgo(algo) => {
                write!(
                    f,
                    "Unsupported hash algorithm in JSON digest field: '{}' (only sha256 supported)",
                    algo
                )
            }
            Self::JsonVerifyHashWithoutHashField => {
                write!(f, "--json-verify-hash requires --json-hash-field")
            }
            Self::JsonUrlFieldRequired => {
                write!(f, "--json-parse requires --json-url-field")
            }
            Self::JsonHashInvalidFormat { url, digest } => {
                write!(f, "--json-verify-hash: unparseable digest field {:?} for {}", digest, url)
            }
            Self::JsonDownloadsFailed { failed, total } => {
                write!(
                    f,
                    "JSON download mode: {} of {} downloads failed (per-entry retries already exhausted)",
                    failed, total
                )
            }
        }
    }
}

impl std::error::Error for PermanentError {}

/// Maximum number of redirects to follow
const MAX_REDIRECTS: usize = 20;

const BUFFER_SIZE: usize = 1024 * 1024;

/// Maximum size of a JSON body fetched with --json-parse. The JSON metadata is
/// parsed fully in memory, so it must be bounded regardless of --max-size
/// (--max-size tightens this cap further when it is smaller).
const MAX_JSON_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Default personalization string if config file doesn't exist
const DEFAULT_PERSONALIZATION: &str = "rget-default-key-v1";

/// Maximum filename length in bytes (POSIX NAME_MAX is typically 255)
const MAX_FILENAME_BYTES: usize = 255;

/// Config file name (placed in platform-specific config directory)
/// - Linux: ~/.config/rget/resumekey.conf
/// - macOS: ~/Library/Application Support/rget/resumekey.conf
/// - Windows: C:\Users\<User>\AppData\Roaming\rget\resumekey.conf
const RESUME_KEY_FILENAME: &str = "resumekey.conf";

/// Check if io::Error is ENAMETOOLONG or equivalent
fn is_name_too_long(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidFilename
}

/// Check if a sync_all() error can be safely ignored.
/// This handles filesystems / targets that don't support fsync:
/// - Unix: EINVAL and ENOTSUP (e.g. /dev/null, some pseudo-fs)
/// - Windows: ERROR_INVALID_FUNCTION (1) and ERROR_NOT_SUPPORTED (50)
fn is_sync_ignorable(e: &std::io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    {
        code == libc::EINVAL || code == libc::ENOTSUP
    }
    #[cfg(windows)]
    {
        // ERROR_INVALID_FUNCTION = 1, ERROR_NOT_SUPPORTED = 50
        code == 1 || code == 50
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// HSTS database filename
const HSTS_DB_FILENAME: &str = "hsts.json";

/// Maximum number of HSTS entries retained in memory and persisted to disk.
/// When an update would push the cache above this cap, the entries with the
/// soonest expiry are evicted first (curl uses a comparable fixed cap).
const MAX_HSTS_ENTRIES: usize = 5000;

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nLicense: ",
    env!("CARGO_PKG_LICENSE"),
    "\nCopyright ",
    env!("BUILD_YEAR"),
    " ",
    env!("CARGO_PKG_AUTHORS"),
);

/// Secure file downloader - works like wget
#[derive(Parser, Debug, Clone)]
#[command(name = env!("CARGO_PKG_NAME"), author, version = VERSION_MESSAGE, about, long_about = None)]
struct Args {
    /// URL(s) to download
    #[arg(required_unless_present = "input_file", help = "URL(s) to download")]
    urls: Vec<String>,

    /// Output filename (optional, derived from URL or Content-Disposition if not specified)
    #[arg(short = 'O', long = "output")]
    output: Option<String>,

    /// Output directory for downloads (must already exist, will not be created)
    #[arg(
        short = 'P',
        long = "output-dir",
        help = "Output directory (must exist, not created automatically)"
    )]
    output_dir: Option<String>,

    /// Allow insecure connections (HTTP and invalid certificates)
    #[arg(long = "insecure", help = "Allow insecure HTTP and invalid certificates")]
    insecure: bool,

    /// Disable system proxy detection
    #[arg(long = "no-proxy", help = "Disable system proxy and use direct connection")]
    no_proxy: bool,

    /// Resolve name to IPv4 address
    #[arg(
        short = '4',
        long = "ipv4",
        conflicts_with = "ipv6_only",
        help = "Connect only to IPv4 addresses"
    )]
    ipv4_only: bool,

    /// Resolve name to IPv6 address
    #[arg(
        short = '6',
        long = "ipv6",
        conflicts_with = "ipv4_only",
        help = "Connect only to IPv6 addresses"
    )]
    ipv6_only: bool,

    /// Overwrite existing file without prompting; forces re-download even if the local file size matches Content-Length
    #[arg(
        long = "overwrite",
        help = "Overwrite existing file (forces re-download even when local size matches server's Content-Length)"
    )]
    overwrite: bool,

    /// Write to a temporary file first, then atomically rename
    #[arg(
        long = "temp",
        help = "Use atomic write via temporary file (supports resuming with --continue, see resumekey.conf)"
    )]
    temp: bool,

    /// Length of the random characters in temporary filename
    #[arg(
        long = "tempnamelen",
        default_value_t = 16,
        value_parser = clap::builder::RangedU64ValueParser::<u64>::new().range(4..=200).map(|v| v as usize),
        help = "Length of temp filename hash when using --temp")]
    tempnamelen: usize,

    /// Keep temporary file on cancellation (CTRL-C)
    #[arg(long = "keep-temp", help = "Keep temporary file if download is cancelled")]
    keep_temp: bool,

    /// Resume a partially downloaded file
    #[arg(short = 'c', long = "continue", help = "Resume partial download")]
    resume: bool,

    /// Quiet mode - minimal output
    #[arg(short = 'q', long = "quiet", conflicts_with = "verbose")]
    quiet: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", conflicts_with = "quiet")]
    verbose: bool,

    /// Debug output (implies --verbose, shows internal details)
    #[arg(long = "debug", conflicts_with = "quiet", help = "Debug output (implies --verbose)")]
    debug: bool,

    /// Maximum file size to download in bytes
    #[arg(long = "max-size")]
    max_size: Option<u64>,

    /// Block connections to private/local IP addresses (SSRF protection)
    #[arg(long = "no-private-ips", help = "Block private/localhost IPs")]
    no_private_ips: bool,

    /// Timeout in seconds if no data is received (default: 300, must be >= 1)
    #[arg(
        long = "timeout",
        default_value_t = 300,
        value_parser = clap::builder::RangedU64ValueParser::<u64>::new().range(1..),
        help = "Timeout in seconds (no data received, must be >= 1)"
    )]
    timeout: u64,

    /// Number of retries on connection failure or timeout (default: 1, 0 = infinite)
    #[arg(long = "retries", default_value_t = 1, help = "Number of retries (0 = infinite)")]
    retries: u64,

    /// Identify as agent-string to the HTTP server
    #[arg(short = 'U', long = "user-agent", help = "Identify as agent-string to the HTTP server")]
    user_agent: Option<String>,

    /// Send header-line along with the rest of the headers
    #[arg(long = "header", help = "Send header-line (e.g. 'Accept-Encoding: gzip')")]
    header: Vec<String>,

    /// Include 'Referer: url' header in HTTP request
    #[arg(long = "referer", help = "Include 'Referer: url' header in HTTP request")]
    referer: Option<String>,

    /// Read URLs from a local file ('-' for stdin); lines starting with '#' are comments
    #[arg(
        short = 'i',
        long = "input-file",
        help = "Read URLs from a local file, '-' for stdin ('#' lines are comments)"
    )]
    input_file: Option<String>,

    /// Specify username for HTTP authentication
    #[arg(long = "user", help = "Specify username for HTTP authentication")]
    user: Option<String>,

    /// Specify password for HTTP authentication
    #[arg(long = "password", help = "Specify password for HTTP authentication")]
    password: Option<String>,

    /// Output content even if server returns error (e.g. 404, 500)
    #[arg(long = "content-on-error", help = "Output content even if server returns error")]
    content_on_error: bool,

    /// Allow appending to files owned by different users
    #[arg(long = "insecure-owner", help = "Allow appending to files not owned by current user")]
    insecure_owner: bool,

    /// Set file permissions (octal, e.g. 644). Default: based on umask.
    #[arg(long = "filemode", help = "Set file permissions (octal, e.g. 644)")]
    filemode: Option<String>,

    /// Client certificate file (PEM) for Mutual TLS
    #[arg(long = "cert", requires = "key", help = "Client certificate file (PEM) for Mutual TLS")]
    cert: Option<String>,

    /// Private key file (PEM) for Mutual TLS
    #[arg(long = "key", requires = "cert", help = "Private key file (PEM) for Mutual TLS")]
    key: Option<String>,

    /// Force writing to terminal even for binary or unknown content types
    #[arg(
        long = "force-tty-write",
        help = "Allow writing binary/unknown content to terminal with -O-"
    )]
    force_tty_write: bool,

    /// HSTS cache file path
    #[arg(
        long = "hsts-file",
        help = "Path to HSTS cache file (default: ~/.config/rget/hsts.json)"
    )]
    hsts_file: Option<String>,

    /// Disable loading, updating, and saving the HSTS database
    #[arg(long = "no-hsts-update", help = "Disable HSTS database persistence and updates")]
    no_hsts_update: bool,

    /// Download only if remote file is newer than local file
    #[arg(short = 'N', long = "newer", help = "Download only if remote file is newer than local")]
    newer: bool,

    /// Do not send If-Modified-Since header in -N mode; send preliminary HEAD request instead
    #[arg(
        long = "no-if-modified-since",
        help = "In -N mode, use HEAD request instead of If-Modified-Since header"
    )]
    no_if_modified_since: bool,

    /// After downloading, set file modification time to server's Last-Modified
    #[arg(
        long = "server-timestamps",
        help = "Set file modification time to server's Last-Modified header"
    )]
    server_timestamps: bool,

    /// Allow multiple copies when same output filename is generated during one execution
    #[arg(
        long = "multiple-copies",
        help = "Rename duplicate filenames with numeric suffix (file.ext.1, file.ext.2, ...)"
    )]
    multiple_copies: bool,

    /// Place number before extension when numbering copies (file.1.ext instead of file.ext.1)
    #[arg(
        long = "keep-extension",
        help = "Place number before extension in --multiple-copies mode"
    )]
    keep_extension: bool,

    /// Parse JSON response and extract download URLs
    #[arg(long = "json-parse", help = "Parse JSON response to extract and download file URLs")]
    json_parse: bool,

    /// JSON path expression to extract download URLs (required with --json-parse)
    /// Uses jq-like dot notation: .assets[].browser_download_url
    #[arg(
        long = "json-url-field",
        help = "JSON path to download URL field (e.g. .assets[].browser_download_url)"
    )]
    json_url_field: Option<String>,

    /// JSON path expression to extract hash digests (parallel to --json-url-field)
    #[arg(
        long = "json-hash-field",
        help = "JSON path to hash digest field (e.g. .assets[].digest)"
    )]
    json_hash_field: Option<String>,

    /// JSON path expression to extract output filenames (parallel to --json-url-field)
    #[arg(
        long = "json-name-field",
        help = "JSON path to output filename field (e.g. .assets[].name)"
    )]
    json_name_field: Option<String>,

    /// Regex to filter URLs extracted from JSON
    #[arg(
        long = "json-filter",
        help = "Regex to filter URLs extracted from JSON (e.g. '\\.mmdb$')"
    )]
    json_filter: Option<String>,

    /// Verify SHA256 hash of downloaded files against JSON hash field
    #[arg(
        long = "json-verify-hash",
        help = "Verify SHA256 of downloaded files against hash from JSON"
    )]
    json_verify_hash: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HstsEntry {
    expiry: u64, // Unix timestamp
    include_subdomains: bool,
}

type HstsMap = HashMap<String, HstsEntry>;

fn get_default_hsts_path() -> PathBuf {
    dirs::config_dir()
        .map(|d| d.join(env!("CARGO_PKG_NAME")).join(HSTS_DB_FILENAME))
        .unwrap_or_else(|| PathBuf::from(HSTS_DB_FILENAME))
}

fn load_hsts_db(path: &Path) -> HstsMap {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return HashMap::new(),
    };
    let reader = BufReader::new(file);

    // Parse JSON
    match serde_json::from_reader::<_, HstsMap>(reader) {
        Ok(mut map) => {
            // Prune expired entries immediately on load
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            map.retain(|_, entry| entry.expiry > now);
            map
        }
        Err(e) => {
            eprintln!(
                "Warning: Failed to parse HSTS cache '{}', starting fresh. Error: {}",
                path.display(),
                e
            );
            HashMap::new()
        }
    }
}

fn save_hsts_db(path: &Path, map: &HstsMap) {
    // Attempt to create parent directories
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("Warning: Failed to create HSTS config directory '{}': {}", parent.display(), e);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // Filter out expired entries before saving
    let valid_entries: HstsMap = map
        .iter()
        .filter(|(_, entry)| entry.expiry > now)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Atomic write via the tempfile crate.
    let parent = safe_parent(path);
    let mut tmp = match tempfile::Builder::new().prefix(".hsts-").suffix(".tmp").tempfile_in(parent)
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to create temp file for HSTS DB in '{}': {}", parent.display(), e);
            return;
        }
    };
    let tmp_path_display = tmp.path().display().to_string();

    {
        let mut writer = BufWriter::new(tmp.as_file_mut());
        if let Err(e) = serde_json::to_writer_pretty(&mut writer, &valid_entries) {
            eprintln!("Failed to serialize HSTS DB to '{}': {}", tmp_path_display, e);
            return;
        }
        if let Err(e) = writer.flush() {
            eprintln!("Failed to flush HSTS DB to '{}': {}", tmp_path_display, e);
            return;
        }
    }

    // Atomically rename the temp file over the target.
    if let Err(e) = tmp.persist(path) {
        eprintln!("Failed to atomically replace HSTS DB '{}': {}", path.display(), e);
    }
}

fn check_hsts(map: &HstsMap, host: &str) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // RFC 6797 §8.3 / §8.1.1: IP-literal hosts are never Known HSTS Hosts and
    // cannot trigger an upgrade.
    let bare = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return false;
    }

    // Normalize trailing dot ('example.com.' is the same FQDN as 'example.com').
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return false;
    }

    // Check exact match
    if let Some(entry) = map.get(host)
        && entry.expiry > now
    {
        return true;
    }

    // Check superdomains if they have includeSubDomains set.
    // Walk down stripping the leftmost label, but stop before the TLD
    // (a 1-label "superdomain" is the TLD; no HSTS pinning happens there).
    let mut parts: Vec<&str> = host.split('.').collect();
    while parts.len() > 2 {
        parts.remove(0); // Remove subdomain
        let superdomain = parts.join(".");
        if let Some(entry) = map.get(&superdomain)
            && entry.include_subdomains
            && entry.expiry > now
        {
            return true;
        }
    }

    false
}

fn update_hsts(map: &mut HstsMap, url: &Url, headers: &HeaderMap, debug: bool) {
    // HeaderMap::get returns the first value for repeated header names, which
    // already satisfies RFC 6797 §8.1: "process only the first such header field".
    let Some(hsts_val) = headers.get(STRICT_TRANSPORT_SECURITY) else {
        return;
    };
    let Ok(hsts_str) = hsts_val.to_str() else {
        return;
    };

    // RFC 6797 §8.1.1: an IP-literal authority MUST NOT be noted as an HSTS host.
    // Url::host() returns a typed enum, distinguishing Domain from Ipv4/Ipv6 cleanly.
    let host_raw = match url.host() {
        Some(url::Host::Domain(d)) => d,
        Some(_) => {
            if debug {
                eprintln!("[DEBUG] HSTS: ignoring STS header for IP-literal host");
            }
            return;
        }
        None => return,
    };

    // Strip a trailing dot so 'example.com.' and 'example.com' resolve to one entry.
    let host = host_raw.strip_suffix('.').unwrap_or(host_raw);
    if host.is_empty() {
        return;
    }

    // RFC 6797 §6.1 rule 2: each directive MUST appear only once.
    // RFC 6797 §6.1 rule 4: a header that does not conform to the syntax
    // MUST be ignored in its entirety. Track duplicates and bail on a violation.
    let mut max_age: Option<u64> = None;
    let mut include_subdomains = false;
    let mut seen_max_age = false;
    let mut seen_isd = false;

    for part in hsts_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            // An empty fragment between two ';'s is permitted by the ABNF
            // [ directive ] *( ";" [ directive ] ); skip it.
            continue;
        }

        if part.eq_ignore_ascii_case("includeSubDomains") {
            if seen_isd {
                if debug {
                    eprintln!("[DEBUG] HSTS: duplicate includeSubDomains, ignoring header");
                }
                return;
            }
            seen_isd = true;
            include_subdomains = true;
        } else if let Some((key, val)) = part.split_once('=') {
            let key = key.trim();
            if key.eq_ignore_ascii_case("max-age") {
                if seen_max_age {
                    if debug {
                        eprintln!("[DEBUG] HSTS: duplicate max-age, ignoring header");
                    }
                    return;
                }
                seen_max_age = true;
                // RFC 6797 §6.1 grammar: directive-value = token | quoted-string.
                // Strip one surrounding pair of double quotes if present.
                let mut v = val.trim();
                if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                    v = &v[1..v.len() - 1];
                }
                match v.parse::<u64>() {
                    Ok(age) => max_age = Some(age),
                    Err(_) => {
                        if debug {
                            eprintln!("[DEBUG] HSTS: malformed max-age '{}', ignoring header", val);
                        }
                        return;
                    }
                }
            }
            // Unknown directive with a value: RFC §6.1 rule 5 says ignore
            // unrecognized directives but still process the recognized ones.
        } else {
            // Unknown valueless directive: ignore (RFC §6.1 rule 5).
        }
    }

    // max-age is REQUIRED (RFC §6.1.1). Its absence makes the header malformed.
    let Some(age) = max_age else {
        if debug {
            eprintln!("[DEBUG] HSTS: max-age missing, ignoring header");
        }
        return;
    };

    // RFC 6797 §8.1: max-age=0 means delete the cached policy (or do not
    // store one if it was not already present). The includeSubDomains
    // directive is explicitly ignored in this case (RFC §6.1.1 NOTE).
    if age == 0 {
        if map.remove(host).is_some() && debug {
            eprintln!("[DEBUG] HSTS: removed entry for '{}' (max-age=0)", host);
        }
        return;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let expiry = now.saturating_add(age);

    map.insert(host.to_string(), HstsEntry { expiry, include_subdomains });

    // Cap the cache so a hostile actor controlling many subdomains cannot grow
    // it without bound. When over the cap, evict the entries with the soonest
    // expiry, but never evict the entry we just stored (otherwise a server with
    // a small max-age could be silently dropped on every visit).
    if map.len() > MAX_HSTS_ENTRIES {
        let excess = map.len() - MAX_HSTS_ENTRIES;
        let mut by_expiry: Vec<(String, u64)> = map
            .iter()
            .filter(|(k, _)| k.as_str() != host)
            .map(|(k, v)| (k.clone(), v.expiry))
            .collect();
        by_expiry.sort_by_key(|(_, e)| *e);
        for (k, _) in by_expiry.into_iter().take(excess) {
            map.remove(&k);
        }
    }

    if debug {
        eprintln!(
            "[DEBUG] HSTS: Added/Updated entry for '{}' (max-age={}, includeSubDomains={})",
            host, age, include_subdomains
        );
    }
}

/// Safely extracts the parent directory from a path.
/// If the path is just a filename (e.g., "ur.bin"), it returns "." instead of "".
fn safe_parent(path: &Path) -> &Path {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() { Path::new(".") } else { parent }
}

/// Build the TLS ClientConfig once per invocation.
/// Returns None in --insecure mode (no rustls config needed).
fn build_tls_config(args: &Args) -> Result<Option<ClientConfig>> {
    if args.insecure {
        return Ok(None);
    }

    let tls_builder = ClientConfig::builder();

    // Try platform verifier, fallback to WebPKI roots if failed.
    // On Android, we explicitly skip platform verifier to avoid panics in CLI environments (missing JNI).
    #[cfg(not(target_os = "android"))]
    let tls_builder = match tls_builder.with_platform_verifier() {
        Ok(builder) => builder,
        Err(e) => {
            if args.debug || args.verbose {
                eprintln!(
                    "Warning: Platform verifier unavailable ({}). Falling back to WebPKI roots.",
                    e
                );
            }
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder().with_root_certificates(root_store)
        }
    };

    #[cfg(target_os = "android")]
    let tls_builder = {
        if args.debug {
            eprintln!(
                "[DEBUG] Android detected: Skipping platform verifier (requires JNI), using bundled WebPKI roots."
            );
        }
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder().with_root_certificates(root_store)
    };

    let client_config = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        if args.debug {
            eprintln!("[DEBUG] Loading client certificate (platform-verifier): {}", cert_path);
        }
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        tls_builder.with_client_auth_cert(certs, key).context("Failed to configure client auth")?
    } else {
        tls_builder.with_no_client_auth()
    };

    Ok(Some(client_config))
}

fn build_client(
    args: &Args,
    resolve_override: Option<(&str, SocketAddr)>,
    tls_config: &Option<ClientConfig>,
) -> Result<Client> {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none()) // Manual redirects
        .user_agent(args.user_agent.as_deref().unwrap_or(concat!(env!("CARGO_PKG_NAME"), "/1.0")))
        .connect_timeout(Duration::from_secs(30))
        .no_gzip()
        .no_brotli()
        .no_deflate();

    // Handle Proxy
    if args.no_proxy {
        builder = builder.no_proxy();
    }

    // Handle Security & mTLS
    if args.insecure {
        // Insecure Path: Allow invalid certs, use default identity handling
        builder = builder.danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true);

        if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
            if args.debug {
                eprintln!("[DEBUG] Loading client certificate (insecure mode): {}", cert_path);
            }

            let cert_pem = fs::read(cert_path).map_err(|e| {
                PermanentError::ClientCertError(format!(
                    "Failed to read certificate file '{}': {}",
                    cert_path, e
                ))
            })?;

            let key_pem = fs::read(key_path).map_err(|e| {
                PermanentError::ClientCertError(format!(
                    "Failed to read key file '{}': {}",
                    key_path, e
                ))
            })?;

            // Combine cert and key for reqwest/rustls identity (Identity::from_pem handles both)
            let mut combined_pem = cert_pem;
            combined_pem.push(b'\n');
            combined_pem.extend_from_slice(&key_pem);

            let identity = Identity::from_pem(&combined_pem)
                .context("Failed to parse client certificate/key (PEM format required)")?;

            builder = builder.identity(identity);
        }
    } else {
        // Secure Path: reuse the pre-built TLS config (platform verifier + mTLS)
        let config = tls_config.as_ref().expect("secure mode requires cached TLS config");
        builder = builder.use_preconfigured_tls(config.clone());
    }

    // Handle Custom Headers
    let mut headers = HeaderMap::new();
    if let Some(ref ref_url) = args.referer {
        if let Ok(val) = HeaderValue::from_str(ref_url) {
            headers.insert(reqwest::header::REFERER, val);
        } else {
            eprintln!("Warning: Invalid referer URL ignored");
        }
    }
    for h in &args.header {
        if let Some((k, v)) = h.split_once(':') {
            if let (Ok(k_name), Ok(v_val)) =
                (HeaderName::from_bytes(k.trim().as_bytes()), HeaderValue::from_str(v.trim()))
            {
                headers.insert(k_name, v_val);
            } else {
                eprintln!("Warning: Invalid header ignored: {}", h);
            }
        } else {
            eprintln!("Warning: Invalid header format (missing colon): {}", h);
        }
    }
    if !headers.is_empty() {
        builder = builder.default_headers(headers);
    }

    // Handle DNS Resolve-and-Override
    if let Some((host, addr)) = resolve_override {
        builder = builder.resolve(host, addr);
    }

    builder
        .build()
        .map_err(|e| PermanentError::ClientBuilderError(format!("TLS/Builder error: {}", e)).into())
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow::anyhow!("Failed to open cert file '{}': {}", path, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid certificate in '{}': {}", path, e))
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_file(path)
        .map_err(|e| anyhow::anyhow!("Invalid or missing private key in '{}': {}", path, e))
}

async fn resolve_final_url_and_client(
    initial_url: Url,
    args: &Args,
    client_cache: &mut HashMap<String, Client>,
    hsts_db: &mut HstsMap,
    tls_config: &Option<ClientConfig>,
) -> Result<(Client, Url, Option<u64>, Option<String>, Option<String>, bool)> {
    // CLI policy: validate the URL the user actually supplied BEFORE any HSTS
    // rewriting. Without this, 'http://example.com' would silently succeed
    // whenever 'example.com' happens to be in the HSTS DB (the in-loop upgrade
    // rewrites it to https:// before validate_url sees it) but fail otherwise --
    // behaviour that depends on persistent state the user is not necessarily
    // aware of. We require a user-supplied 'http://' URL to be paired with
    // --insecure regardless of HSTS state. HSTS upgrade still applies to
    // redirect targets returned by the server (handled inside the loop below),
    // which preserves HSTS's anti-TLS-stripping purpose on redirect chains.
    validate_url(&initial_url, args.insecure)?;

    // Remember the host the user actually asked for: HTTP credentials are only
    // ever sent to this host. A redirect that changes the host must not receive
    // the credentials (matching curl's default without --location-trusted).
    let initial_host = initial_url.host_str().map(|h| h.to_string());

    let mut current_url = initial_url;
    let mut redirect_count = 0;

    loop {
        // HSTS Upgrade Check
        if current_url.scheme() == "http"
            && let Some(host) = current_url.host_str()
            && check_hsts(hsts_db, host)
        {
            if args.verbose {
                eprintln!("HSTS: Upgrading insecure request to {}", host);
            }
            // RFC 6797 §8.3: when upgrading to https, an explicit port of 80
            // MUST be converted to 443; any other explicit port is preserved;
            // and if no explicit port is present, none is added. url::Url's
            // set_scheme does not touch the port for us, so do it here.
            if current_url.port() == Some(80) {
                let _ = current_url.set_port(Some(443));
            }
            let _ = current_url.set_scheme("https");
        }
        if redirect_count >= MAX_REDIRECTS {
            return Err(PermanentError::TooManyRedirects(MAX_REDIRECTS).into());
        }

        validate_url(&current_url, args.insecure)?;

        if args.verbose {
            eprintln!("-> Requesting: {}", current_url);
        }

        let client = if !args.no_proxy
            && (std::env::var("HTTP_PROXY").is_ok()
                || std::env::var("HTTPS_PROXY").is_ok()
                || std::env::var("http_proxy").is_ok()
                || std::env::var("https_proxy").is_ok())
        {
            build_client(args, None, tls_config)?
        } else {
            let host = current_url.host_str().ok_or_else(|| anyhow::anyhow!("No host in URL"))?;

            // Include port in cache key to separate HTTP (80) and HTTPS (443) clients
            let port = current_url.port_or_known_default().unwrap_or(443);
            let cache_key = format!("{}:{}", host, port);

            if let Some(cached_client) = client_cache.get(&cache_key) {
                if args.verbose {
                    eprintln!("   Reusing connection for {}", host);
                }
                cached_client.clone()
            } else {
                let safe_ip = resolve_safe_ip(&current_url, args).await?;
                if !args.quiet {
                    eprintln!("Connecting to {} ({})", host, safe_ip.ip());
                }
                let new_client = build_client(args, Some((host, safe_ip)), tls_config)?;
                client_cache.insert(cache_key, new_client.clone());
                new_client
            }
        };

        // Only send credentials to the originally requested host, never to a
        // host reached through a redirect.
        let same_host = current_url.host_str() == initial_host.as_deref();

        let mut request = client.head(current_url.clone());
        if let Some(ref u) = args.user {
            if same_host {
                request = request.basic_auth(u, args.password.as_deref());
            } else if args.verbose {
                eprintln!(
                    "   Not sending credentials to '{}' (host differs from original URL)",
                    current_url.host_str().unwrap_or("<none>")
                );
            }
        }

        let mut response = request.send().await.context("Failed to send HEAD request")?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            if args.debug {
                eprintln!("[DEBUG] HEAD status: 405 Method Not Allowed. Retrying with GET...");
            }
            let mut get_request = client.get(current_url.clone());
            if let Some(ref u) = args.user
                && same_host
            {
                get_request = get_request.basic_auth(u, args.password.as_deref());
            }
            response = get_request.send().await.context("Failed to send GET request")?;
        }

        if !args.no_hsts_update && current_url.scheme() == "https" {
            // RFC 6797 §8.1: STS headers received over insecure (http) transport MUST be ignored.
            update_hsts(hsts_db, &current_url, response.headers(), args.debug);
        }

        if args.debug {
            eprintln!("[DEBUG] HTTP version: {:#?} {}", response.version(), response.status());
            eprintln!("[DEBUG] All headers:");
            // Sometimes Google CDN sends 'age: "0"' and no content-length or etag
            for (name, value) in response.headers().iter() {
                eprintln!("[DEBUG]   {}: {:?}", name, value);
            }
            if response.headers().contains_key("transfer-encoding") {
                eprintln!(
                    "[DEBUG]   WARNING: Transfer-Encoding detected. Content-Length might be missing."
                );
            }
        }

        let status = response.status();
        let headers = response.headers().clone();

        if status.is_redirection()
            && let Some(location) = headers.get(LOCATION)
        {
            let location_str = location.to_str().context("Invalid Location header")?;
            let next_url =
                current_url.join(location_str).context("Failed to resolve redirect URL")?;
            if args.verbose {
                eprintln!("   Redirecting to: {}", next_url);
            }
            current_url = next_url;
            redirect_count += 1;
            continue;
        }

        let content_length = headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let content_disposition =
            headers.get(CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

        let last_modified =
            headers.get(LAST_MODIFIED).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

        if status.is_success() || status.is_client_error() || status.is_server_error() {
            return Ok((
                client,
                current_url,
                content_length,
                content_disposition,
                last_modified,
                same_host,
            ));
        }

        bail!("Unexpected status code: {}", status);
    }
}

async fn run_with_args(args: Args, hsts_db: &mut HstsMap) -> Result<()> {
    let mut all_urls = args.urls.clone();

    let mut log_builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off"));
    if args.debug {
        log_builder.filter_level(log::LevelFilter::Debug);
    }
    log_builder.init();

    if let Some(ref input_path) = args.input_file {
        let reader: Box<dyn BufRead> = if input_path == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            let f = File::open(input_path).context("Failed to open input file")?;
            Box::new(BufReader::new(f))
        };

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            // Skip blank lines and '#' comment lines (a URL cannot start with '#')
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                all_urls.push(trimmed.to_string());
            }
        }
    }

    // Deduplicate URLs automatically if --output is not specified
    let urls: Vec<String> = if args.output.is_none() {
        let mut seen = HashSet::new();
        all_urls.iter().filter(|url| seen.insert(*url)).cloned().collect()
    } else {
        all_urls
    };

    if args.output.is_some() && urls.len() > 1 && !args.json_parse {
        return Err(PermanentError::InvalidArguments(
            "--output cannot be used with multiple URLs".to_string(),
        )
        .into());
    }

    // Validate --no-if-modified-since requires -N
    if args.no_if_modified_since && !args.newer {
        return Err(PermanentError::NoIfModifiedSinceWithoutNewer.into());
    }

    // Validate --keep-extension requires --multiple-copies
    if args.keep_extension && !args.multiple_copies {
        return Err(PermanentError::KeepExtensionWithoutMultipleCopies.into());
    }

    // Validate --filemode
    if let Some(ref mode_str) = args.filemode
        && u32::from_str_radix(mode_str, 8).is_err()
    {
        return Err(PermanentError::InvalidArguments(format!(
            "Invalid octal file mode: '{}'",
            mode_str
        ))
        .into());
    }

    // Validate --json-parse requirements
    if args.json_parse && args.json_url_field.is_none() {
        return Err(PermanentError::JsonUrlFieldRequired.into());
    }
    if args.json_verify_hash && args.json_hash_field.is_none() {
        return Err(PermanentError::JsonVerifyHashWithoutHashField.into());
    }
    // --json-hash-field, --json-name-field, --json-filter, --json-verify-hash imply --json-parse
    if (args.json_url_field.is_some()
        || args.json_hash_field.is_some()
        || args.json_name_field.is_some()
        || args.json_filter.is_some()
        || args.json_verify_hash)
        && !args.json_parse
    {
        return Err(PermanentError::InvalidArguments(
            "--json-url-field, --json-hash-field, --json-name-field, --json-filter, and --json-verify-hash require --json-parse".to_string()
        ).into());
    }

    if let Err(e) = apply_security_sandbox() {
        eprintln!("Failed to apply seccomp filter: {}", e);
        std::process::exit(1);
    }

    // Validate --output-dir: must exist and be a directory (never create it)
    if let Some(ref dir_str) = args.output_dir {
        let dir_path = Path::new(dir_str);
        match fs::metadata(dir_path) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(
                        PermanentError::OutputDirNotADirectory(dir_path.to_path_buf()).into()
                    );
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(PermanentError::OutputDirNotFound(dir_path.to_path_buf()).into());
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Cannot access output directory '{}': {}",
                    dir_path.display(),
                    e
                ));
            }
        }
    }

    // Validate --output-dir + --output=-  is contradictory
    if args.output_dir.is_some() && args.output.as_deref() == Some("-") {
        return Err(PermanentError::InvalidArguments(
            "--output-dir cannot be used with --output - (stdout)".to_string(),
        )
        .into());
    }

    let mut client_cache: HashMap<String, Client> = HashMap::new();
    let mut overall_success = true;
    let max_retries = if args.retries == 0 { u64::MAX } else { args.retries };

    // Track used output filenames for --multiple-copies
    let mut used_filenames: HashMap<PathBuf, u32> = HashMap::new();
    let mut dir_cache = DirCache::default();

    // Pre-populate DirCache with --output-dir handle so all downloads reuse it
    if let Some(ref dir_str) = args.output_dir {
        let dir_path = Path::new(dir_str);

        // Use standard Dir and standard Path
        let dir_handle = Dir::open_ambient_dir(dir_path, ambient_authority()).map_err(|e| {
            anyhow::anyhow!("Failed to open output directory '{}': {}", dir_path.display(), e)
        })?;
        dir_cache.insert(normalize_path_lexically(dir_path), dir_handle);
    }

    // Build TLS config once (platform verifier + mTLS) and reuse for all clients.
    // This avoids re-running rustls_platform_verifier for every new connection.
    let tls_config = build_tls_config(&args)?;

    for url_str in &urls {
        let url = match Url::parse(url_str) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("Error parsing URL '{}': {}", url_str, e);
                overall_success = false;
                continue;
            }
        };

        if !args.quiet {
            eprintln!("Starting download: {}", url);
        }

        // JSON parse mode: fetch JSON, extract URLs, download them
        if args.json_parse {
            let mut attempt = 0;
            loop {
                let current_args = args.clone();
                // Snapshot the filename cache before the attempt — process_json_downloads
                // mutates it as individual downloads succeed. Without this snapshot, a
                // retry of the whole JSON flow would see successful entries' filenames
                // as "used" and (with --multiple-copies) write numbered duplicates.
                let mut attempt_used_filenames = used_filenames.clone();

                let result = async {
                    match resolve_final_url_and_client(
                        url.clone(),
                        &current_args,
                        &mut client_cache,
                        hsts_db,
                        &tls_config,
                    )
                    .await
                    {
                        Ok((
                            client,
                            final_url,
                            _content_length,
                            _content_disposition,
                            _last_modified,
                            send_auth,
                        )) => {
                            if current_args.verbose && final_url != url {
                                eprintln!("Final URL: {}", final_url);
                            }
                            process_json_downloads(
                                &client,
                                &final_url,
                                &current_args,
                                &mut client_cache,
                                hsts_db,
                                &mut attempt_used_filenames,
                                &mut dir_cache,
                                &tls_config,
                                send_auth,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
                .await;

                match result {
                    Ok(()) => {
                        // Commit the cache only on full success
                        used_filenames = attempt_used_filenames;
                        break;
                    }
                    Err(e) => {
                        if is_permanent_error(&e) {
                            eprintln!("Failed: {:#}", e);
                            overall_success = false;
                            break;
                        }
                        if attempt >= max_retries {
                            eprintln!("Failed: {:#}", e);
                            overall_success = false;
                            break;
                        }
                        eprintln!(
                            "Error: {}. Retrying (attempt {}/{})...",
                            e,
                            attempt + 1,
                            if current_args.retries == 0 {
                                "\u{221e}".to_string()
                            } else {
                                current_args.retries.to_string()
                            }
                        );
                        attempt += 1;
                        let delay = 1u64 << attempt.clamp(0, 6);
                        sleep(Duration::from_secs(delay)).await;
                    }
                }
            }
            if !args.quiet && urls.len() > 1 {
                eprintln!();
            }
            continue;
        }

        // Normal (non-JSON) download mode
        let mut attempt = 0;
        // Output path pinned by the first attempt; retries reuse it so the
        // auto-set resume flag cannot re-route the download into a different
        // pre-existing file (see download_file).
        let mut resolved_output: Option<PathBuf> = None;
        loop {
            let mut current_args = args.clone();
            if attempt > 0 {
                current_args.resume = true;
            }
            // 1. Snapshot the cache before the attempt begins
            let mut attempt_used_filenames = used_filenames.clone();

            // Pass the cache to be used/updated
            let result = async {
                match resolve_final_url_and_client(
                    url.clone(),
                    &current_args,
                    &mut client_cache,
                    hsts_db,
                    &tls_config,
                )
                .await
                {
                    Ok((
                        client,
                        final_url,
                        content_length,
                        content_disposition,
                        last_modified,
                        send_auth,
                    )) => {
                        if current_args.verbose && final_url != url {
                            eprintln!("Final URL: {}", final_url);
                        }

                        if let (Some(max), Some(size)) = (current_args.max_size, content_length)
                            && size > max
                        {
                            return Err(PermanentError::FileSizeExceedsLimit {
                                size,
                                max,
                                url: final_url.to_string(),
                            }
                            .into());
                        }
                        download_file(
                            &client,
                            &final_url,
                            &current_args,
                            content_length,
                            content_disposition.as_deref(),
                            last_modified.as_deref(),
                            &mut attempt_used_filenames,
                            None,
                            &mut dir_cache,
                            &mut resolved_output,
                            send_auth,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            .await;

            match result {
                Ok(()) => {
                    // 3. Commit the cache ONLY if the download was successful
                    used_filenames = attempt_used_filenames;
                    break;
                }
                Err(e) => {
                    if is_permanent_error(&e) {
                        eprintln!("Failed to download {}: {:#}", url, e);
                        overall_success = false;
                        break;
                    }
                    if attempt >= max_retries {
                        eprintln!("Failed to download {}: {:#}", url, e);
                        overall_success = false;
                        break;
                    }
                    eprintln!(
                        "Error: {}. Retrying (attempt {}/{})...",
                        e,
                        attempt + 1,
                        if current_args.retries == 0 {
                            "\u{221e}".to_string()
                        } else {
                            current_args.retries.to_string()
                        }
                    );
                    attempt += 1;

                    // Exponential backoff: 2^attempt (capped at 64s)
                    let delay = 1u64 << attempt.clamp(0, 6);
                    sleep(Duration::from_secs(delay)).await;
                }
            }
        }
        if !args.quiet && urls.len() > 1 {
            eprintln!();
        }
    }

    if overall_success { Ok(()) } else { bail!("One or more downloads failed") }
}

/// Truncate a string to fit within a maximum byte limit, respecting UTF-8 boundaries.
/// Returns a slice of the original string.
fn truncate_str_to_byte_limit(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }

    // Find the longest prefix that fits within max_bytes
    let mut end = 0;
    for (idx, c) in s.char_indices() {
        let next_end = idx + c.len_utf8();
        if next_end <= max_bytes {
            end = next_end;
        } else {
            break;
        }
    }

    &s[..end]
}

/// Truncate a filename to fit within MAX_FILENAME_BYTES, preserving extension if possible.
fn truncate_filename_to_limit(filename: &str) -> String {
    if filename.len() <= MAX_FILENAME_BYTES {
        return filename.to_string();
    }

    let (base, ext) = if let Some(dot_pos) = filename.rfind('.') {
        // Only treat as extension if it's reasonable (not at start, not too long)
        if dot_pos > 0 && filename.len() - dot_pos <= 20 {
            (&filename[..dot_pos], &filename[dot_pos..])
        } else {
            (filename, "")
        }
    } else {
        (filename, "")
    };

    let ext_bytes = ext.len();
    let max_base_bytes = MAX_FILENAME_BYTES.saturating_sub(ext_bytes);

    if max_base_bytes == 0 {
        // Extension alone is too long or equal to limit, just truncate the whole thing
        return truncate_str_to_byte_limit(filename, MAX_FILENAME_BYTES).to_string();
    }

    let truncated_base = truncate_str_to_byte_limit(base, max_base_bytes);
    format!("{}{}", truncated_base, ext)
}

fn resolve_output_path(original_path: &Path) -> Result<PathBuf> {
    let filename = original_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid filename in path"))?;

    if filename.len() <= MAX_FILENAME_BYTES {
        return Ok(original_path.to_path_buf());
    }

    let truncated = truncate_filename_to_limit(filename);
    let parent = original_path.parent().unwrap_or(Path::new("."));
    Ok(parent.join(&truncated))
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_unspecified()
                || ipv4.is_documentation()
                // "This network" (RFC 6890): 0.0.0.0/8 - on Linux these
                // addresses can reach localhost, a classic SSRF bypass
                || ipv4.octets()[0] == 0
                // Shared Address Space (RFC 6598): 100.64.0.0/10
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
                // IETF Protocol Assignments: 192.0.0.0/24
                || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0)
                // Benchmarking (RFC 2544): 198.18.0.0/15
                || (ipv4.octets()[0] == 198 && (ipv4.octets()[1] & 0xFE) == 18)
                // Multicast (RFC 5771): 224.0.0.0/4
                || ipv4.is_multicast()
                // Reserved for future use (RFC 1112 §4): 240.0.0.0/4
                || ((ipv4.octets()[0] & 0xf0) == 0xf0)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                // Multicast: ff00::/8
                || ipv6.is_multicast()
                // Link-local: fe80::/10 (first 10 bits are 1111111010)
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
                // Unique Local Address (ULA): fc00::/7 (first 7 bits are 1111110)
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                // Documentation: 2001:db8::/32
                || (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0db8)
                // Teredo: 2001:0::/32 - tunneling mechanism that can reach private IPv4
                || (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0000)
                // 6to4: 2002::/16 - embeds IPv4 address, check if embedded IP is private
                || is_6to4_private(ipv6)
                // NAT64: 64:ff9b::/96 (RFC 6052) embeds IPv4; 64:ff9b:1::/48 (RFC 8215)
                || is_nat64_private(ipv6)
                // IPv4-mapped IPv6: ::ffff:x.x.x.x
                || ipv6
                    .to_ipv4_mapped()
                    .map(|v4| is_private_ip(&IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

/// Check if a 6to4 address (2002::/16) embeds a private IPv4 address
fn is_6to4_private(ipv6: &std::net::Ipv6Addr) -> bool {
    if ipv6.segments()[0] != 0x2002 {
        return false;
    }
    // 6to4 embeds IPv4 in segments 1-2: 2002:AABB:CCDD::
    // where IPv4 is AA.BB.CC.DD
    let seg1 = ipv6.segments()[1];
    let seg2 = ipv6.segments()[2];
    let ipv4 = std::net::Ipv4Addr::new(
        (seg1 >> 8) as u8,
        (seg1 & 0xff) as u8,
        (seg2 >> 8) as u8,
        (seg2 & 0xff) as u8,
    );
    is_private_ip(&IpAddr::V4(ipv4))
}

/// Check if a NAT64 address maps to private address space.
/// Covers the well-known prefix 64:ff9b::/96 (RFC 6052), which embeds an IPv4
/// address in the last 32 bits, and the local-use prefix 64:ff9b:1::/48
/// (RFC 8215), which is reserved for operator-internal translation.
fn is_nat64_private(ipv6: &std::net::Ipv6Addr) -> bool {
    let s = ipv6.segments();
    if s[0] != 0x0064 || s[1] != 0xff9b {
        return false;
    }
    // 64:ff9b:1::/48 is local-use; treat the whole prefix as private.
    if s[2] == 0x0001 {
        return true;
    }
    // Well-known prefix 64:ff9b::/96: IPv4 is embedded in segments 6-7.
    if s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        let ipv4 = std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        return is_private_ip(&IpAddr::V4(ipv4));
    }
    false
}

/// Helper function to validate an IP against the CLI arguments
/// Extracted for easier unit testing of the security logic
fn is_ip_allowed(addr: &SocketAddr, args: &Args) -> bool {
    // IP Version Filtering
    if args.ipv4_only && !addr.is_ipv4() {
        return false;
    }
    if args.ipv6_only && !addr.is_ipv6() {
        return false;
    }

    // SSRF Protection
    if args.no_private_ips && is_private_ip(&addr.ip()) {
        return false;
    }

    true
}

/// Resolve DNS manually to handle SSRF protection, DNS rebinding, and IP version enforcement
async fn resolve_safe_ip(url: &Url, args: &Args) -> Result<SocketAddr> {
    let port = url.port_or_known_default().unwrap_or(443);

    // Helper to generate consistent error messages
    let make_error = |host_str: &str| {
        if args.ipv4_only {
            PermanentError::NoSafeIpv4(host_str.to_string()).into()
        } else if args.ipv6_only {
            PermanentError::NoSafeIpv6(host_str.to_string()).into()
        } else {
            PermanentError::NoSafePublicIp(host_str.to_string()).into()
        }
    };

    match url.host() {
        // 1. Handle Domain Names (DNS Lookup)
        Some(url::Host::Domain(host_str)) => {
            let addrs = tokio::net::lookup_host((host_str, port))
                .await
                .context("Failed to resolve hostname")?;

            for addr in addrs {
                if is_ip_allowed(&addr, args) {
                    return Ok(addr);
                }
            }
            Err(make_error(host_str))
        }

        // 2. Handle IPv4 Literals directly (No DNS)
        Some(url::Host::Ipv4(addr)) => {
            let sa = SocketAddr::new(std::net::IpAddr::V4(addr), port);
            if is_ip_allowed(&sa, args) { Ok(sa) } else { Err(make_error(&addr.to_string())) }
        }

        // 3. Handle IPv6 Literals directly
        Some(url::Host::Ipv6(addr)) => {
            let sa = SocketAddr::new(std::net::IpAddr::V6(addr), port);
            if is_ip_allowed(&sa, args) { Ok(sa) } else { Err(make_error(&addr.to_string())) }
        }

        None => Err(anyhow::anyhow!("URL has no host")),
    }
}

/// Parse Content-Disposition header and extract filename if valid.
/// Returns None for invalid headers (per RFC 6266, invalid headers should be ignored).
/// The content_disposition crate handles RFC 6266 and RFC 5987 properly, including:
/// - Validating disposition type exists and is valid
/// - Prioritizing filename* over filename
/// - Proper charset decoding for extended parameters
fn parse_content_disposition_header(header_value: &str) -> Option<String> {
    let data = parse_content_disposition(header_value);

    // 1. Validate Type
    match data.disposition {
        DispositionType::Attachment | DispositionType::Inline => {}
        _ => return None,
    }

    // 2. Extract 'filename'
    // The parser internally resolves 'filename*' vs 'filename' precedence,
    // handles charset decoding, and provides UTF-8 fallback on unrecognized encoding.
    if let Some(name) = data.params.get("filename") {
        return Some(sanitize_filename(name));
    }

    None
}

// Percent-decode a string. Wraps the percent_encoding crate (already a transitive
// dep via the url crate). Returns a String for caller convenience.
// Lossy UTF-8 conversion is used so invalid byte sequences become U+FFFD instead
// of erroring — matches the prior behavior.
fn percent_decode_str(input: &str) -> String {
    percent_encoding::percent_decode(input.as_bytes()).decode_utf8_lossy().into_owned()
}

fn sanitize_filename(filename: &str) -> String {
    // 1. Manually handle both / and \ as separators for cross-platform robustness
    let filename = filename.rsplit(['/', '\\']).next().unwrap_or(filename);

    // 2. Basic Character Sanitization
    let mut sanitized: String = filename
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();

    // Remove leading dots
    sanitized = sanitized.trim_start_matches('.').to_string();

    // 3. Windows Reserved Name Check and trailing dot/space stripping (Windows Only)
    #[cfg(windows)]
    {
        // Windows silently strips trailing dots and spaces, which both breaks
        // round-tripping and can resurrect reserved names ("CON." -> "CON"),
        // so strip them ourselves before the reserved-name check.
        sanitized = sanitized.trim_end_matches(['.', ' ']).to_string();

        // Windows reserves device names based on the part before the FIRST dot
        // ("CON.tar.gz" is still the CON device), so split there instead of
        // using file_stem(), which only strips the last extension. Trailing
        // spaces in the stem ("CON .txt") are also ignored by Windows.
        let stem = sanitized.split('.').next().unwrap_or("").trim_end().to_uppercase();

        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "COM0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
            "LPT9", "LPT0",
        ];

        if reserved_names.contains(&stem.as_str()) {
            // Replace ONLY the reserved word with '_', preserving everything
            // after the first dot
            sanitized = match sanitized.split_once('.') {
                Some((_, rest)) => format!("_.{}", rest),
                None => "_".to_string(),
            };
        }
    }

    if sanitized.is_empty() { "download".to_string() } else { sanitized }
}

fn filename_from_url(url: &Url) -> String {
    // Pick the last raw path segment BEFORE percent-decoding: decoding first
    // would let an encoded '/' (%2F) change which segment is chosen. Note that
    // url.path() never contains the query or fragment, so there is nothing to
    // split off at '?' or '#'; splitting after decoding used to truncate
    // legitimate filenames containing encoded '?' or '#' (sanitize_filename
    // neutralizes those characters instead).
    let raw_segment =
        url.path().rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("index.html");
    let decoded = percent_decode_str(raw_segment);
    sanitize_filename(&decoded)
}

/// Read the personalization key from config file
/// Returns the key content or default if file doesn't exist
///
/// Config file location:
/// - Linux: ~/.config/rget/resumekey.conf
/// - macOS: ~/Library/Application Support/rget/resumekey.conf
/// - Windows: C:\Users\<User>\AppData\Roaming\rget\resumekey.conf
fn read_personalization_key() -> String {
    let config_path =
        dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join(RESUME_KEY_FILENAME));

    let Some(path) = config_path else {
        return DEFAULT_PERSONALIZATION.to_string();
    };

    match fs::read_to_string(&path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                DEFAULT_PERSONALIZATION.to_string()
            } else {
                trimmed.to_string()
            }
        }
        Err(_) => DEFAULT_PERSONALIZATION.to_string(),
    }
}

/// Generate a deterministic temporary filename using SHAKE256
///
/// The filename is derived from:
/// - User's personalization key (from config file)
/// - The URL
/// - Optional content-disposition header
///
/// This allows `--temp --continue` to work by generating the same temp filename
/// for the same download across multiple runs.
///
/// Format: .{base32hash}.{pkg_name}.tmp (e.g., .oibepluzpwwjsyvf.rget.tmp)
fn generate_deterministic_temp_filename(
    url: &Url,
    actual_filename: &str,
    parent_dir: &Path,
    temp_name_len: usize,
    debug: bool,
) -> PathBuf {
    let personalization_key = read_personalization_key();
    let domain_version = "temp-filename-v1";

    if debug {
        eprintln!("[DEBUG] SHAKE256 inputs for temp filename:");
        eprintln!(
            "[DEBUG]   [domain separation]: {:?} {:?}",
            env!("CARGO_PKG_NAME"),
            domain_version
        );
        eprintln!("[DEBUG]   personalization_key: {:?}", personalization_key);
        eprintln!("[DEBUG]   target length: {}", temp_name_len);
        eprintln!("[DEBUG]   url: {:?}", url.as_str());
        eprintln!("[DEBUG]   filename: {:?}", actual_filename);
    }

    let mut hasher = Shake256::default();
    hasher.update(env!("CARGO_PKG_NAME").as_bytes());
    hasher.update(b"\x00");
    hasher.update(domain_version.as_bytes());
    hasher.update(b"\x00");
    hasher.update(personalization_key.as_bytes());
    hasher.update(b"\x00");
    hasher.update(&(temp_name_len as u64).to_be_bytes());
    hasher.update(b"\x00");
    hasher.update(url.as_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(actual_filename.as_bytes());

    let bytes_needed = (temp_name_len * 5).div_ceil(8);
    let mut output = vec![0u8; bytes_needed];
    let mut reader = hasher.finalize_xof();
    XofReader::read(&mut reader, &mut output);

    // Encode as lowercase base32 (no padding)
    let encoded = BASE32_NOPAD.encode(&output).to_lowercase();
    // Truncate to the exact requested length
    // (since byte alignment might produce slightly more chars than requested)
    let final_hash =
        if encoded.len() > temp_name_len { &encoded[..temp_name_len] } else { &encoded };

    let filename = format!(".{}.{}.tmp", final_hash, env!("CARGO_PKG_NAME"));

    if debug {
        eprintln!(
            "[DEBUG]   output hash (hex): {}",
            output.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        );
        eprintln!("[DEBUG]   temp filename: {}", filename);
    }

    parent_dir.join(filename)
}

/// Check if a Content-Type indicates textual content that is safe to write to a terminal.
/// Matches text/* and common textual application types like application/json, application/xml, etc.
fn is_text_content_type(content_type: Option<&str>) -> bool {
    let ct = match content_type {
        Some(ct) => ct,
        None => return false,
    };

    // Extract the media type (before any parameters like charset)
    let media_type = ct.split(';').next().unwrap_or("").trim().to_lowercase();

    if media_type.starts_with("text/") {
        return true;
    }

    // Common textual application types
    matches!(
        media_type.as_str(),
        "application/json"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/javascript"
            | "application/ecmascript"
            | "application/x-javascript"
            | "application/ld+json"
            | "application/manifest+json"
            | "application/schema+json"
            | "application/vnd.api+json"
            | "application/graphql"
            | "application/x-www-form-urlencoded"
            | "application/x-ndjson"
            | "application/x-yaml"
            | "application/yaml"
            | "application/toml"
            | "application/sql"
            | "application/atom+xml"
            | "application/rss+xml"
            | "application/soap+xml"
            | "application/svg+xml"
            | "application/mathml+xml"
    ) || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

fn validate_url(url: &Url, insecure: bool) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            if insecure {
                Ok(())
            } else {
                Err(PermanentError::InsecureUrl(url.to_string()).into())
            }
        }
        scheme => Err(PermanentError::UnsupportedScheme(scheme.to_string()).into()),
    }
}

fn determine_filename(args: &Args, url: &Url, content_disposition: Option<&str>) -> String {
    if let Some(ref output) = args.output {
        if args.debug {
            eprintln!("[DEBUG] Filename source: --output argument");
        }
        return output.clone();
    }
    if let Some(cd) = content_disposition
        && let Some(filename) = parse_content_disposition_header(cd)
    {
        if args.debug {
            eprintln!("[DEBUG] Filename source: Content-Disposition ('{}')", filename);
        }
        return filename;
    }

    let url_name = filename_from_url(url);
    if args.debug {
        eprintln!("[DEBUG] Filename source: URL path ('{}')", url_name);
    }
    url_name
}

/// Check if a file mode indicates a block or character device.
/// Returns Some("block") or Some("char") if it's a device, None otherwise.
/// Pipes (FIFOs) are allowed and return None.
#[cfg(unix)]
fn is_block_or_char_device(mode: u32) -> Option<&'static str> {
    use libc::{S_IFBLK, S_IFCHR, S_IFMT};
    let file_type = mode & S_IFMT;
    if file_type == S_IFBLK {
        Some("block")
    } else if file_type == S_IFCHR {
        Some("char")
    } else {
        None
    }
}

/// Post-open check: fstat() the open file descriptor for TOCTOU protection.
/// Verifies the file is not a block/char device after opening.
/// When appending, also verifies the file owner matches the current process UID
/// (unless insecure_owner is true).
#[cfg(unix)]
fn check_file_after_open(
    file: &File,
    path: &Path,
    check_owner: bool,
    insecure_owner: bool,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;

    if let Some(device_type) = is_block_or_char_device(metadata.mode()) {
        return if device_type == "block" {
            Err(PermanentError::BlockDeviceNotAllowed(path.to_path_buf()).into())
        } else {
            Err(PermanentError::CharDeviceNotAllowed(path.to_path_buf()).into())
        };
    }

    // Check owner when appending (unless --insecure-owner)
    if check_owner && !insecure_owner {
        let file_uid = metadata.uid();
        let process_uid = rustix::process::getuid().as_raw();

        if file_uid != process_uid {
            return Err(PermanentError::FileOwnerMismatch {
                path: path.to_path_buf(),
                expected_uid: process_uid,
                actual_uid: file_uid,
            }
            .into());
        }
    }

    Ok(())
}

/// File metadata obtained through the DirCache (avoids AT_FDCWD stat calls).
struct FileInfo {
    size: u64,
    modified: Option<SystemTime>,
}

/// Stat a file through the DirCache, using fstatat on the pinned directory fd.
/// Returns None if the file does not exist.
fn stat_file_via_cache(
    path: &Path,
    cache: &mut DirCache,
) -> Result<Option<FileInfo>, std::io::Error> {
    let parent = safe_parent(path);
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Path has no filename")
    })?;

    let dir = get_cached_dir(cache, parent)?;

    match dir.symlink_metadata(filename) {
        Ok(metadata) => {
            let modified = metadata.modified().ok().map(|t| t.into_std());
            Ok(Some(FileInfo { size: metadata.len(), modified }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// Windows stub for post-open checks
#[cfg(not(unix))]
fn check_file_after_open(
    _file: &File,
    _path: &Path,
    _check_owner: bool,
    _insecure_owner: bool,
) -> Result<()> {
    Ok(())
}

fn check_path_before_open(path: &Path, cache: &mut DirCache) -> Result<bool> {
    let mut parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        parent = Path::new(".");
    }
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Path has no filename")
    })?;
    let filename_str = filename.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Filename is not valid UTF-8")
    })?;

    // PIN DIRECTORY GLOBALLY
    let dir = get_cached_dir(cache, parent)?;

    // Check metadata universally to determine if the file exists
    match dir.symlink_metadata(filename_str) {
        Ok(_metadata) => {
            // Only check for block/char devices on Unix
            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                if let Some(device_type) = is_block_or_char_device(_metadata.mode()) {
                    return if device_type == "block" {
                        Err(PermanentError::BlockDeviceNotAllowed(path.to_path_buf()).into())
                    } else {
                        Err(PermanentError::CharDeviceNotAllowed(path.to_path_buf()).into())
                    };
                }
            }
            Ok(true) // File exists and is safe
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        // Propagate other errors (permission denied, EIO, etc.) instead of pretending the file
        // doesn't exist — masking them led to confusing downstream "already exists" diagnostics.
        Err(e) => Err(e.into()),
    }
}

/// Normalizes a path purely lexically (no disk I/O).
/// Strips out `.` and resolves `..` where possible.
fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(..) | Component::RootDir | Component::Normal(..) => {
                normalized.push(component);
            }
            Component::CurDir => {} // Ignore `.`
            Component::ParentDir => {
                // Pop the last component if it's a normal directory.
                // After a RootDir, drop the `..` entirely — can't go above filesystem root.
                // For paths starting with `..` (no anchor), preserve the `..`.
                match normalized.components().next_back() {
                    Some(Component::Normal(_)) => {
                        normalized.pop();
                    }
                    Some(Component::RootDir) => {
                        // No-op: "/.." resolves to "/"
                    }
                    _ => {
                        normalized.push(component);
                    }
                }
            }
        }
    }

    // If the path was just `.` or resolved to empty, return `.`
    if normalized.as_os_str().is_empty() { PathBuf::from(".") } else { normalized }
}

/// Get (or open and cache) the Dir handle for `parent`, keyed by its lexical
/// normalization so "./a", "a/../a", etc. all map to one cache entry.
fn get_cached_dir<'a>(cache: &'a mut DirCache, parent: &Path) -> std::io::Result<&'a Dir> {
    let key = normalize_path_lexically(parent);
    if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(key.clone()) {
        let dir = Dir::open_ambient_dir(e.key(), cap_std::ambient_authority())?;
        e.insert(dir);
    }
    Ok(cache.get(&key).unwrap())
}

fn open_file_securely(
    path: &Path,
    args: &Args,
    start_byte: u64,
    force_truncate: bool,
    cache: &mut DirCache,
) -> Result<(std::fs::File, bool)> {
    let parent = safe_parent(path);
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Path has no filename")
    })?;

    let dir = get_cached_dir(cache, parent)?;

    let mut file_existed = false;
    let mut existing_is_regular = false;
    match dir.symlink_metadata(filename) {
        Ok(_metadata) => {
            file_existed = true;
            existing_is_regular = _metadata.file_type().is_file();

            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                if let Some(device_type) = is_block_or_char_device(_metadata.mode()) {
                    return if device_type == "block" {
                        Err(PermanentError::BlockDeviceNotAllowed(path.to_path_buf()).into())
                    } else {
                        Err(PermanentError::CharDeviceNotAllowed(path.to_path_buf()).into())
                    };
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let is_append = start_byte > 0;
    let mut opts = OpenOptions::new();
    opts.write(true);

    if is_append {
        opts.append(true);
    } else if file_existed
        && existing_is_regular
        && (args.overwrite || args.resume || args.newer || force_truncate)
    {
        // Existing regular file that we are authorized to replace (--overwrite,
        // -N, --continue resuming from 0 bytes, or a forced restart; a plain
        // pre-existing file without those flags was already rejected upstream with
        // FileAlreadyExists). Delete and recreate it fresh via O_EXCL rather than
        // truncating in place, so the replacement works regardless of the file's
        // ownership (unlinking needs write access to the parent directory, not
        // ownership of the file).
        match dir.remove_file(filename) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        opts.create_new(true);
    } else if file_existed {
        // Existing entry we will not unlink: a symlink, FIFO, or other non-regular
        // object (or, defensively, a regular file reached without an authorizing
        // flag). Open with O_TRUNC (no O_EXCL); combined with O_NOFOLLOW set below
        // this makes a symlink fail with ELOOP (preserving the anti-symlink
        // guarantee), while a FIFO opens for writing into the pipe.
        opts.create(true).truncate(true);
    } else {
        // Nothing exists yet: create a brand-new file (O_EXCL keeps it
        // TOCTOU-safe against a file appearing between the stat and the open).
        opts.create_new(true);
    }

    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;

        let custom_flags = libc::O_NOCTTY | libc::O_NOFOLLOW;
        opts.custom_flags(custom_flags);

        if let Some(ref mode_str) = args.filemode
            && let Ok(m) = u32::from_str_radix(mode_str, 8)
        {
            opts.mode(m);
        }
    }

    let cap_file = dir.open_with(filename, &opts)?;
    let std_file = cap_file.into_std();

    // Post-open TOCTOU check only matters when appending: we verify the real fd
    // is not a device and (unless --insecure-owner) is owned by us. Overwrite and
    // create-new paths produce a brand-new file we just created via O_EXCL, so no
    // owner check applies there.
    if is_append {
        check_file_after_open(&std_file, path, true, args.insecure_owner)?;
    }

    Ok((std_file, file_existed))
}

/// Because cap-std does not expose Linux's renameat2 (with RENAME_NOREPLACE), we use a hybrid
/// approach here. We extract the raw file descriptors from our cap-std handles to pass to rustix
/// on Linux. For macOS and Windows, we use cap-std's sandboxed .hard_link() and .rename().
fn perform_atomic_move(
    temp_path: &Path,
    target_path: &Path,
    args: &Args,
    cache: &mut DirCache,
) -> Result<PathBuf, anyhow::Error> {
    // Internal helper to perform the move using Dir handles
    let try_move = |src: &Path, dst: &Path, cache: &mut DirCache| -> std::io::Result<()> {
        let parent_from = safe_parent(src);
        let parent_to = safe_parent(dst);
        let file_from = src.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing source filename")
        })?;
        let file_to = dst.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing destination filename")
        })?;

        // Populate cache sequentially so mutable borrows don't overlap
        let _ = get_cached_dir(cache, parent_from)?;
        let _ = get_cached_dir(cache, parent_to)?;

        let key_from = normalize_path_lexically(parent_from);
        let key_to = normalize_path_lexically(parent_to);

        // Now borrow immutably concurrently
        let dir_from = cache.get(&key_from).unwrap();
        let dir_to = cache.get(&key_to).unwrap();

        let overwrite_or_resume = args.overwrite || args.resume;

        // LINUX FAST-PATH: Use rustix for RENAME_NOREPLACE using the cap-std file descriptors
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::RenameFlags;
            use std::os::fd::AsFd;

            let flags =
                if overwrite_or_resume { RenameFlags::empty() } else { RenameFlags::NOREPLACE };

            match rustix::fs::renameat_with(
                dir_from.as_fd(),
                file_from,
                dir_to.as_fd(),
                file_to,
                flags,
            ) {
                Ok(_) => return Ok(()),
                Err(e) if e == rustix::io::Errno::EXIST => return Err(std::io::Error::from(e)),
                Err(_) => {} // Fallthrough to std fallbacks for EXDEV / unsupported NOREPLACE
            }
        }

        // CROSS-PLATFORM / FALLBACK PATH using cap-std
        if overwrite_or_resume {
            // Atomic replace
            dir_from.rename(file_from, dir_to, file_to)
        } else {
            // Safe fallback for NOREPLACE: hardlink then remove
            match dir_from.hard_link(file_from, dir_to, file_to) {
                Ok(()) => {
                    let _ = dir_from.remove_file(file_from);
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
                Err(_) => {
                    // Last resort: check existence and standard rename
                    if dir_to.symlink_metadata(file_to).is_ok() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "Destination exists",
                        ));
                    }
                    dir_from.rename(file_from, dir_to, file_to)
                }
            }
        }
    };

    // The rest of your logic handles retries and ENAMETOOLONG
    match try_move(temp_path, target_path, cache) {
        Ok(_) => Ok(target_path.to_path_buf()),

        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if args.overwrite || args.resume {
                Err(e.into())
            } else {
                // The pre-download existence checks already passed for this
                // target, so AlreadyExists at rename time means the file
                // appeared during the download (TOCTOU race).
                Err(PermanentError::FileAppearedDuringDownload(target_path.to_path_buf()).into())
            }
        }

        Err(e) if is_name_too_long(&e) => {
            let truncated = resolve_output_path(target_path)?;

            if truncated == target_path {
                return Err(PermanentError::FilenameTooLong.into());
            }

            if !args.quiet {
                eprintln!("Filename too long, retrying with: {}", truncated.display());
            }

            match try_move(temp_path, &truncated, cache) {
                Ok(_) => Ok(truncated),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(PermanentError::TruncatedFilenameExists(truncated).into())
                }
                Err(e) => Err(e).context("Failed to rename to truncated path"),
            }
        }

        Err(e) => Err(e).context("Failed to rename temp file"),
    }
}

/// Parse Content-Range header to extract the start byte
/// Format: "bytes START-END/TOTAL" or "bytes START-END/*"
fn parse_content_range(header_value: &str) -> Option<u64> {
    let header_value = header_value.trim();
    if !header_value.starts_with("bytes ") {
        return None;
    }
    let range_part = &header_value[6..]; // Skip "bytes "
    let dash_pos = range_part.find('-')?;
    let start_str = &range_part[..dash_pos];
    start_str.parse::<u64>().ok()
}

/// Check if an error is permanent (should not be retried)
fn is_permanent_error(err: &anyhow::Error) -> bool {
    // 1. Check our custom permanent errors
    if let Some(pe) = err.downcast_ref::<PermanentError>() {
        // HttpClientError carries any HTTP error status. 5xx server errors and
        // 429 Too Many Requests are transient and should be retried; every other
        // 4xx is permanent. All other PermanentError variants are permanent.
        if let PermanentError::HttpClientError(code) = pe {
            return *code < 500 && *code != 429;
        }
        return true;
    }

    // 2. Walk the entire error chain to catch nested errors
    for cause in err.chain() {
        // --- TLS / Certificate Errors ---
        // Catch explicit rustls errors
        if cause.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }

        // Platform verifiers sometimes wrap TLS errors in opaque IO errors.
        // We catch them by sniffing the error message.
        let msg = cause.to_string().to_lowercase();
        if msg.contains("invalid peer certificate")
            || msg.contains("certificate expired")
            || msg.contains("unknown issuer")
            || msg.contains("unrecognized name") // SNI error
            || msg.contains("cert is not valid")
        {
            return true;
        }

        // --- Reqwest Errors ---
        if let Some(req_err) = cause.downcast_ref::<reqwest::Error>() {
            if req_err.is_builder() {
                return true;
            }
            if let Some(status) = req_err.status() {
                // 4xx errors are permanent (except 429 Too Many Requests)
                if status.is_client_error() && status.as_u16() != 429 {
                    return true;
                }
            }
        }

        // --- IO Errors ---
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            #[cfg(unix)]
            if let Some(os_err) = io_err.raw_os_error()
                && (os_err == libc::ELOOP
                    || os_err == libc::ENOTDIR
                    || os_err == libc::EISDIR
                    || os_err == libc::ENOSYS)
            {
                return true;
            }

            if matches!(
                io_err.kind(),
                ErrorKind::InvalidInput
                    | ErrorKind::NotFound
                    | ErrorKind::PermissionDenied
                    | ErrorKind::AlreadyExists
                    | ErrorKind::ReadOnlyFilesystem
                    | ErrorKind::FileTooLarge
                    | ErrorKind::NotSeekable
                    | ErrorKind::IsADirectory
                    | ErrorKind::StorageFull
                    | ErrorKind::BrokenPipe
                    | ErrorKind::QuotaExceeded // | ErrorKind::FilesystemLoop // https://github.com/rust-lang/rust/issues/86442
            ) {
                return true;
            }
        }
    }

    false
}

/// Parse an HTTP-date string into a SystemTime.
/// Supports the three formats listed in RFC 9110 §5.6.7:
/// - IMF-fixdate (RFC 1123): "Sun, 06 Nov 1994 08:49:37 GMT"
/// - RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT"
/// - asctime(): "Sun Nov  6 08:49:37 1994"
fn parse_http_date(s: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(s.trim()).ok()
}

/// Format a SystemTime as an HTTP-date string (RFC 1123).
fn format_http_date(time: SystemTime) -> Option<String> {
    Some(httpdate::fmt_http_date(time))
}

/// Apply server timestamp (Last-Modified) to a local file.
/// Silently does nothing if the header is missing or unparseable.
///
/// On Unix: uses utimensat on the pinned DirCache fd with AT_SYMLINK_NOFOLLOW.
///   No file reopen — operates directly on the directory fd + filename.
/// On Windows: reopens the file via std and uses FileTimes.
fn apply_server_timestamp(
    path: &Path,
    last_modified: Option<&str>,
    debug: bool,
    cache: &mut DirCache,
) {
    let Some(lm_str) = last_modified else {
        if debug {
            eprintln!("[DEBUG] No Last-Modified header, not setting file timestamp");
        }
        return;
    };

    let Some(server_time) = parse_http_date(lm_str) else {
        if debug {
            eprintln!("[DEBUG] Could not parse Last-Modified header: {:?}", lm_str);
        }
        return;
    };

    match set_file_mtime(path, server_time, cache) {
        Ok(()) => {
            if debug {
                eprintln!("[DEBUG] Set file modification time to: {}", lm_str);
            }
        }
        Err(e) => {
            if debug {
                eprintln!("[DEBUG] Failed to set file timestamp: {}", e);
            }
        }
    }
}

/// Set file mtime via utimensat using the DirCache dir handle + AT_SYMLINK_NOFOLLOW.
/// No file descriptor is opened for the file itself — purely metadata operation.
#[cfg(unix)]
fn set_file_mtime(path: &Path, server_time: SystemTime, cache: &mut DirCache) -> Result<()> {
    use rustix::fs::{AtFlags, Timespec, Timestamps};
    use std::os::fd::AsFd;

    let dur =
        server_time.duration_since(UNIX_EPOCH).context("Server timestamp is before Unix epoch")?;
    let times = Timestamps {
        last_access: Timespec { tv_sec: 0, tv_nsec: rustix::fs::UTIME_OMIT as _ },
        last_modification: Timespec {
            tv_sec: dur.as_secs() as _,
            tv_nsec: dur.subsec_nanos() as _,
        },
    };

    let mut parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        parent = Path::new(".");
    }
    let filename = path.file_name().ok_or_else(|| anyhow::anyhow!("Path has no filename"))?;

    let dir = get_cached_dir(cache, parent)?;

    rustix::fs::utimensat(dir.as_fd(), filename, &times, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;

    Ok(())
}

/// Windows fallback: reopen the file securely via DirCache and use std FileTimes.
#[cfg(not(unix))]
fn set_file_mtime(path: &Path, server_time: SystemTime, cache: &mut DirCache) -> Result<()> {
    let mut parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        parent = Path::new(".");
    }
    let filename = path.file_name().ok_or_else(|| anyhow::anyhow!("Path has no filename"))?;

    // 1. Ensure parent directory handle is securely in the cache
    let dir = get_cached_dir(cache, parent)?;

    // 2. Setup OpenOptions for write access
    let mut opts = cap_std::fs::OpenOptions::new();
    opts.write(true);

    // 3. Open the file SECURELY through the pinned directory handle, avoiding symlink/junction TOCTOU
    let cap_file = dir.open_with(filename, &opts)?;
    let file = cap_file.into_std();

    // 4. Apply the modified time
    let times = std::fs::FileTimes::new().set_modified(server_time);
    file.set_times(times)?;

    Ok(())
}

/// Apply mtime directly on an open file descriptor via futimens(2).
/// Called after fsync but before close — avoids reopening the file entirely.
fn set_mtime_on_fd(file: &std::fs::File, mtime: SystemTime) -> Result<()> {
    let times = std::fs::FileTimes::new().set_modified(mtime);
    file.set_times(times).map_err(|e| -> anyhow::Error { e.into() })
}

/// Generate a numbered filename to avoid collisions.
/// With keep_extension=false: file.ext -> file.ext.1
/// With keep_extension=true: file.ext -> file.1.ext
fn generate_numbered_filename(path: &Path, number: u32, keep_extension: bool) -> PathBuf {
    let parent = path.parent().unwrap_or(Path::new("."));
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("download");

    let new_name = if keep_extension {
        if let Some(dot_pos) = filename.rfind('.') {
            let base = &filename[..dot_pos];
            let ext = &filename[dot_pos..]; // includes the dot
            format!("{}.{}{}", base, number, ext)
        } else {
            format!("{}.{}", filename, number)
        }
    } else {
        format!("{}.{}", filename, number)
    };

    parent.join(new_name)
}

/// Resolve a unique output path, handling --multiple-copies numbering.
/// Returns the path to use and whether it was renamed.
fn resolve_unique_output_path(
    output_path: &Path,
    args: &Args,
    used_filenames: &mut HashMap<PathBuf, u32>,
    dir_cache: &mut DirCache,
) -> Result<(PathBuf, bool)> {
    let canonical_key = output_path.to_path_buf();

    if args.multiple_copies {
        // Check if this filename was already used in this execution
        if let Some(counter) = used_filenames.get_mut(&canonical_key) {
            // Already used, find the next available numbered variant
            loop {
                let numbered =
                    generate_numbered_filename(output_path, *counter, args.keep_extension);
                if stat_file_via_cache(&numbered, dir_cache)?.is_none() {
                    *counter += 1;
                    return Ok((numbered, true));
                }
                *counter += 1;
            }
        }

        // First use of this filename in this execution
        // Check if it already exists on disk
        if stat_file_via_cache(output_path, dir_cache)?.is_some()
            && !args.overwrite
            && !args.resume
            && !args.newer
        {
            let mut counter = 1u32;
            loop {
                let numbered =
                    generate_numbered_filename(output_path, counter, args.keep_extension);
                if stat_file_via_cache(&numbered, dir_cache)?.is_none() {
                    used_filenames.insert(canonical_key, counter + 1);
                    return Ok((numbered, true));
                }
                counter += 1;
            }
        }

        // File doesn't exist yet or overwrite/resume/newer is set, use as-is
        used_filenames.insert(canonical_key, 1);
        Ok((output_path.to_path_buf(), false))
    } else {
        // No --multiple-copies: just track usage
        if used_filenames.contains_key(&canonical_key) {
            return Err(PermanentError::FileAlreadyExists(output_path.to_path_buf()).into());
        }
        used_filenames.insert(canonical_key, 1);
        Ok((output_path.to_path_buf(), false))
    }
}

/// Evaluate a simplified jq-like path expression against a serde_json::Value.
/// Supports: .field, .field[], .field[].subfield, .field[N], chained paths.
/// Returns a list of matching leaf values as strings.
fn json_path_extract(value: &serde_json::Value, path: &str) -> Result<Vec<String>> {
    let path = path.trim();
    if path.is_empty() || path == "." {
        return match value {
            serde_json::Value::String(s) => Ok(vec![s.clone()]),
            other => Ok(vec![other.to_string()]),
        };
    }

    // Parse the path into segments
    let segments = parse_jq_path(path)?;
    let mut results = Vec::new();
    collect_values(value, &segments, &mut results);
    Ok(results)
}

#[derive(Debug)]
enum JqSegment {
    Field(String),
    ArrayIter,         // []
    ArrayIndex(usize), // [N]
}

/// Parse a jq-like path into segments.
/// Examples:
///   ".assets[].browser_download_url" -> [Field("assets"), ArrayIter, Field("browser_download_url")]
///   ".digest" -> [Field("digest")]
///   ".data[0].url" -> [Field("data"), ArrayIndex(0), Field("url")]
fn parse_jq_path(path: &str) -> Result<Vec<JqSegment>> {
    let path = path.strip_prefix('.').unwrap_or(path);
    let mut segments = Vec::new();
    let mut chars = path.chars().peekable();
    let mut current_field = String::new();

    while let Some(&ch) = chars.peek() {
        match ch {
            '.' => {
                // Flush current field
                if !current_field.is_empty() {
                    segments.push(JqSegment::Field(current_field.clone()));
                    current_field.clear();
                }
                chars.next();
            }
            '[' => {
                // Flush current field
                if !current_field.is_empty() {
                    segments.push(JqSegment::Field(current_field.clone()));
                    current_field.clear();
                }
                chars.next(); // consume '['
                let mut bracket_content = String::new();
                while let Some(&bc) = chars.peek() {
                    if bc == ']' {
                        chars.next(); // consume ']'
                        break;
                    }
                    bracket_content.push(bc);
                    chars.next();
                }
                if bracket_content.is_empty() {
                    segments.push(JqSegment::ArrayIter);
                } else if let Ok(idx) = bracket_content.parse::<usize>() {
                    segments.push(JqSegment::ArrayIndex(idx));
                } else {
                    return Err(PermanentError::JsonPathError(format!(
                        "Invalid array index: [{}]",
                        bracket_content
                    ))
                    .into());
                }
            }
            '|' => {
                // Pipe operator: treat as segment separator (skip whitespace around it)
                if !current_field.is_empty() {
                    segments.push(JqSegment::Field(current_field.clone()));
                    current_field.clear();
                }
                chars.next(); // consume '|'
                // Skip whitespace after pipe
                while let Some(&wc) = chars.peek() {
                    if wc.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Skip leading dot after pipe if present
                if let Some(&'.') = chars.peek() {
                    chars.next();
                }
            }
            c if c.is_whitespace() => {
                chars.next(); // skip whitespace
            }
            c => {
                current_field.push(c);
                chars.next();
            }
        }
    }

    // Flush remaining field
    if !current_field.is_empty() {
        segments.push(JqSegment::Field(current_field));
    }

    if segments.is_empty() {
        return Err(PermanentError::JsonPathError("Empty path expression".to_string()).into());
    }

    Ok(segments)
}

/// Recursively collect string values matching the segment path.
///
/// Missing fields and JSON nulls produce an empty-string sentinel rather than being
/// silently skipped. This is required so that parallel extractions of different
/// fields from the same array (e.g. `.assets[].url`, `.assets[].digest`,
/// `.assets[].name`) stay positionally aligned — otherwise a hash extracted from
/// one entry could be verified against the bytes of another entry, which is a
/// security issue with `--json-verify-hash`.
fn collect_values(value: &serde_json::Value, segments: &[JqSegment], results: &mut Vec<String>) {
    if segments.is_empty() {
        match value {
            serde_json::Value::String(s) => results.push(s.clone()),
            // Null → sentinel, preserving alignment.
            serde_json::Value::Null => results.push(String::new()),
            other => results.push(other.to_string()),
        }
        return;
    }

    match &segments[0] {
        JqSegment::Field(name) => match value.get(name.as_str()) {
            Some(child) => collect_values(child, &segments[1..], results),
            // Missing field → sentinel, preserving alignment.
            None => results.push(String::new()),
        },
        JqSegment::ArrayIter => {
            if let serde_json::Value::Array(arr) = value {
                for item in arr {
                    collect_values(item, &segments[1..], results);
                }
            }
        }
        JqSegment::ArrayIndex(idx) => {
            if let serde_json::Value::Array(arr) = value {
                match arr.get(*idx) {
                    Some(item) => collect_values(item, &segments[1..], results),
                    None => results.push(String::new()),
                }
            }
        }
    }
}

/// Parse a digest field like "sha256:3f79a2a5..." into (algorithm, hex_hash).
fn parse_digest_field(digest: &str) -> Option<(&str, &str)> {
    let digest = digest.trim();
    if let Some(colon_pos) = digest.find(':') {
        let algo = &digest[..colon_pos];
        let hash = &digest[colon_pos + 1..];
        if !hash.is_empty() {
            return Some((algo, hash));
        }
    }
    // If no colon, treat entire string as a bare SHA256 hex hash (if it looks like one)
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(("sha256", digest));
    }
    None
}

/// Compute SHA256 hex digest of a file.
/// Uses DirCache for TOCTOU-safe reopening on Linux.
fn sha256_file(path: &Path, cache: &mut DirCache) -> Result<String> {
    let mut file =
        open_for_read(path, cache).context("Failed to open file for hash verification")?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

/// Open a file read-only using the DirCache for TOCTOU safety.
/// Unified across all operating systems using cap-std.
fn open_for_read(path: &Path, cache: &mut DirCache) -> std::io::Result<std::fs::File> {
    let parent = safe_parent(path);
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Path has no filename")
    })?;

    // 1. Ensure the directory is securely cached
    let dir = get_cached_dir(cache, parent)?;

    // 2. Set up OpenOptions for read-only
    let mut opts = OpenOptions::new();
    opts.read(true);

    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOCTTY | libc::O_NOFOLLOW);
    }

    // 3. Perform the sandboxed open and convert back to std::fs::File
    let cap_file = dir.open_with(filename, &opts)?;

    Ok(cap_file.into_std())
}

/// Verify SHA256 of a file against an expected hex hash.
/// Returns Ok(()) on match, PermanentError::JsonHashMismatch on mismatch.
fn verify_sha256_file(
    path: &Path,
    expected_hex: &str,
    quiet: bool,
    cache: &mut DirCache,
) -> Result<()> {
    if !quiet {
        eprintln!("Verifying SHA256 for '{}'...", path.display());
    }
    let actual_hash = sha256_file(path, cache)?;
    let expected_lower = expected_hex.to_lowercase();
    if actual_hash != expected_lower {
        return Err(PermanentError::JsonHashMismatch {
            file: path.display().to_string(),
            expected: expected_lower,
            actual: actual_hash,
        }
        .into());
    }
    if !quiet {
        eprintln!("SHA256 OK: {} {}", actual_hash, path.display());
    }
    Ok(())
}

/// Represents a single download entry extracted from JSON.
#[derive(Debug)]
struct JsonDownloadEntry {
    url: String,
    name: Option<String>,
    hash: Option<String>, // raw digest field value
}

/// Fetch JSON body from a URL (using existing client/redirect infrastructure).
async fn fetch_json_body(
    client: &Client,
    url: &Url,
    args: &Args,
    send_auth: bool,
) -> Result<String> {
    let mut request = client.get(url.clone());
    if send_auth && let Some(ref u) = args.user {
        request = request.basic_auth(u, args.password.as_deref());
    }

    let response = request.send().await.context("Failed to send GET request for JSON")?;
    let status = response.status();

    // Check for redirect on GET
    if status.is_redirection() {
        if let Some(location) = response.headers().get(LOCATION) {
            let location_str = location.to_str().unwrap_or("<invalid>");
            return Err(PermanentError::RedirectOnGet {
                status: status.as_u16(),
                location: location_str.to_string(),
            }
            .into());
        }
        return Err(PermanentError::RedirectWithoutLocation(status.as_u16()).into());
    }

    if !status.is_success() {
        return Err(PermanentError::HttpClientError(status.as_u16()).into());
    }

    // Validate Content-Type: application/json
    let content_type =
        response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");

    let media_type = content_type.split(';').next().unwrap_or("").trim().to_lowercase();
    if media_type != "application/json" {
        return Err(PermanentError::JsonContentTypeExpected(content_type.to_string()).into());
    }

    // The JSON body is parsed fully in memory, so cap it instead of reading
    // unbounded data (--max-size tightens the cap when it is smaller).
    let limit = args.max_size.map_or(MAX_JSON_BODY_BYTES, |m| m.min(MAX_JSON_BODY_BYTES));
    if let Some(len) = response.content_length()
        && len > limit
    {
        return Err(PermanentError::FileSizeExceedsLimit {
            size: len,
            max: limit,
            url: url.to_string(),
        }
        .into());
    }

    let mut body_bytes: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read JSON response body")?;
        if body_bytes.len() as u64 + chunk.len() as u64 > limit {
            return Err(PermanentError::DownloadExceedsLimit { max: limit }.into());
        }
        body_bytes.extend_from_slice(&chunk);
    }

    // JSON is UTF-8 (RFC 8259 §8.1); reject anything else instead of guessing.
    String::from_utf8(body_bytes).context("JSON response body is not valid UTF-8")
}

/// Process JSON mode: parse JSON, extract entries, download each, optionally verify hashes.
async fn process_json_downloads(
    client: &Client,
    json_url: &Url,
    args: &Args,
    client_cache: &mut HashMap<String, Client>,
    hsts_db: &mut HstsMap,
    used_filenames: &mut HashMap<PathBuf, u32>,
    dir_cache: &mut DirCache,
    tls_config: &Option<ClientConfig>,
    send_auth: bool,
) -> Result<()> {
    let json_url_field = args.json_url_field.as_ref().expect("--json-url-field required");

    // 1. Fetch JSON body
    if args.verbose {
        eprintln!("Fetching JSON from: {}", json_url);
    }
    let body = fetch_json_body(client, json_url, args, send_auth).await?;

    if args.debug {
        eprintln!("[DEBUG] JSON response body length: {} bytes", body.len());
    }

    // 2. Parse JSON
    let json_value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| PermanentError::JsonParseError(e.to_string()))?;

    // 3. Extract URLs
    let urls = json_path_extract(&json_value, json_url_field)?;
    if args.debug {
        eprintln!("[DEBUG] Extracted {} URL(s) from JSON path '{}':", urls.len(), json_url_field);
        for (i, u) in urls.iter().enumerate() {
            eprintln!("[DEBUG]   [{}] {}", i, u);
        }
    }

    // 4. Extract hashes (if specified)
    let hashes: Option<Vec<String>> = if let Some(ref hash_field) = args.json_hash_field {
        let h = json_path_extract(&json_value, hash_field)?;
        if args.debug {
            eprintln!("[DEBUG] Extracted {} hash(es) from JSON path '{}':", h.len(), hash_field);
            for (i, hv) in h.iter().enumerate() {
                eprintln!("[DEBUG]   [{}] {}", i, hv);
            }
        }
        if h.len() != urls.len() {
            return Err(PermanentError::JsonUrlHashCountMismatch {
                urls: urls.len(),
                hashes: h.len(),
            }
            .into());
        }
        Some(h)
    } else {
        None
    };

    // 5. Extract names (if specified)
    let names: Option<Vec<String>> = if let Some(ref name_field) = args.json_name_field {
        let n = json_path_extract(&json_value, name_field)?;
        if args.debug {
            eprintln!("[DEBUG] Extracted {} name(s) from JSON path '{}':", n.len(), name_field);
            for (i, nv) in n.iter().enumerate() {
                eprintln!("[DEBUG]   [{}] {}", i, nv);
            }
        }
        if n.len() != urls.len() {
            return Err(PermanentError::JsonUrlNameCountMismatch {
                urls: urls.len(),
                names: n.len(),
            }
            .into());
        }
        Some(n)
    } else {
        None
    };

    // 6. Build entries
    let mut entries: Vec<JsonDownloadEntry> = Vec::new();
    for (i, url_str) in urls.iter().enumerate() {
        entries.push(JsonDownloadEntry {
            url: url_str.clone(),
            name: names.as_ref().map(|n| n[i].clone()),
            hash: hashes.as_ref().map(|h| h[i].clone()),
        });
    }

    // 7. Apply regex filter
    if let Some(ref filter_pattern) = args.json_filter {
        let re = Regex::new(filter_pattern).map_err(|e| {
            PermanentError::InvalidArguments(format!(
                "Invalid --json-filter regex '{}': {}",
                filter_pattern, e
            ))
        })?;

        let before_count = entries.len();
        entries.retain(|e| re.is_match(&e.url));
        if args.debug {
            eprintln!(
                "[DEBUG] --json-filter '{}': {} -> {} entries",
                filter_pattern,
                before_count,
                entries.len()
            );
        }
    }

    // 7b. Drop entries whose URL is the empty-string sentinel produced when a
    // .url field is null or missing in the JSON. The parallel fields (hash/name)
    // are still aligned within each JsonDownloadEntry, so dropping by entry is safe.
    let before_sentinel_drop = entries.len();
    entries.retain(|e| !e.url.is_empty());
    if args.debug && entries.len() != before_sentinel_drop {
        eprintln!(
            "[DEBUG] Dropped {} entries with null/missing URL",
            before_sentinel_drop - entries.len()
        );
    }

    if entries.is_empty() {
        return Err(PermanentError::JsonNoUrlsExtracted.into());
    }

    // 8. Print summary
    if !args.quiet {
        eprintln!("JSON: {} file(s) to download:", entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let display_name = entry.name.as_deref().unwrap_or("(from URL)");
            eprintln!("  [{}] {} ({})", i + 1, display_name, entry.url);
            if let Some(ref hash) = entry.hash {
                eprintln!("      hash: {}", hash);
            }
        }
    }

    // 9. Download each entry. Per-entry retries are bounded internally; the outer
    // retry around process_json_downloads must NOT retry these (it would re-fetch
    // JSON and duplicate already-successful downloads), so any failure here is
    // wrapped in PermanentError::JsonDownloadsFailed before returning.
    let max_retries = if args.retries == 0 { u64::MAX } else { args.retries };
    let total = entries.len();
    let mut failed_count: usize = 0;

    for entry in &entries {
        let url = match Url::parse(&entry.url) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("Error parsing URL '{}': {}", entry.url, e);
                failed_count += 1;
                continue;
            }
        };

        if !args.quiet {
            eprintln!();
            eprintln!("Starting download: {}", url);
        }

        // Build per-entry args: set --output if json-name-field was provided
        // Clear json_parse to prevent any accidental re-entry
        let mut entry_args = args.clone();
        entry_args.json_parse = false;
        if let Some(ref name) = entry.name {
            // An empty name sentinel (null/missing in JSON) should not become the output filename
            if !name.is_empty() {
                // The name comes from server-controlled JSON: sanitize it like a
                // Content-Disposition filename so it can neither traverse
                // directories nor become '-' (which --output reserves for stdout).
                let safe_name = sanitize_filename(name);
                entry_args.output =
                    Some(if safe_name == "-" { "_".to_string() } else { safe_name });
            }
        }

        // Pre-parse and validate digest before download attempt.
        // When --json-verify-hash is set, missing/empty/unparseable digests are HARD failures
        // (silently downloading without verification would defeat the flag's purpose).
        let parsed_sha256: Option<String> = if args.json_verify_hash {
            let digest_opt = entry.hash.as_deref().filter(|s| !s.is_empty());
            if let Some(digest_str) = digest_opt {
                if let Some((algo, hex_hash)) = parse_digest_field(digest_str) {
                    if algo != "sha256" {
                        eprintln!(
                            "Failed: {}",
                            PermanentError::JsonHashUnsupportedAlgo(algo.to_string())
                        );
                        failed_count += 1;
                        continue;
                    }
                    Some(hex_hash.to_lowercase())
                } else {
                    eprintln!(
                        "Failed: {}",
                        PermanentError::JsonHashInvalidFormat {
                            url: entry.url.clone(),
                            digest: digest_str.to_string(),
                        }
                    );
                    failed_count += 1;
                    continue;
                }
            } else {
                eprintln!("Failed: {}", PermanentError::JsonHashMissing(entry.url.clone()));
                failed_count += 1;
                continue;
            }
        } else {
            None
        };

        let mut attempt: u64 = 0;
        // Output path pinned by the first attempt; retries reuse it so the
        // auto-set resume flag cannot re-route the download (see download_file).
        let mut resolved_output: Option<PathBuf> = None;
        let entry_failed = loop {
            let mut current_args = entry_args.clone();
            if attempt > 0 {
                current_args.resume = true;
            }
            let mut attempt_used_filenames = used_filenames.clone();

            let result = async {
                match resolve_final_url_and_client(
                    url.clone(),
                    &current_args,
                    client_cache,
                    hsts_db,
                    tls_config,
                )
                .await
                {
                    Ok((
                        dl_client,
                        final_url,
                        content_length,
                        content_disposition,
                        last_modified,
                        entry_send_auth,
                    )) => {
                        if current_args.verbose && final_url != url {
                            eprintln!("Final URL: {}", final_url);
                        }

                        if let (Some(max), Some(size)) = (current_args.max_size, content_length)
                            && size > max
                        {
                            return Err(PermanentError::FileSizeExceedsLimit {
                                size,
                                max,
                                url: final_url.to_string(),
                            }
                            .into());
                        }
                        download_file(
                            &dl_client,
                            &final_url,
                            &current_args,
                            content_length,
                            content_disposition.as_deref(),
                            last_modified.as_deref(),
                            &mut attempt_used_filenames,
                            parsed_sha256.as_deref(),
                            dir_cache,
                            &mut resolved_output,
                            entry_send_auth,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            .await;

            match result {
                Ok(()) => {
                    // Commit the cache
                    *used_filenames = attempt_used_filenames;
                    break false;
                }
                Err(e) => {
                    if is_permanent_error(&e) {
                        eprintln!("Failed to download {}: {:#}", url, e);
                        break true;
                    }
                    if attempt >= max_retries {
                        eprintln!("Failed to download {}: {:#}", url, e);
                        break true;
                    }
                    eprintln!(
                        "Error: {}. Retrying (attempt {}/{})...",
                        e,
                        attempt + 1,
                        if current_args.retries == 0 {
                            "\u{221e}".to_string()
                        } else {
                            current_args.retries.to_string()
                        }
                    );
                    attempt += 1;
                    let delay = 1u64 << attempt.clamp(0, 6);
                    sleep(Duration::from_secs(delay)).await;
                }
            }
        };
        if entry_failed {
            failed_count += 1;
        }
    }

    if failed_count == 0 {
        Ok(())
    } else {
        Err(PermanentError::JsonDownloadsFailed { failed: failed_count, total }.into())
    }
}

async fn download_file(
    client: &Client,
    url: &Url,
    args: &Args,
    expected_length: Option<u64>,
    content_disposition: Option<&str>,
    head_last_modified: Option<&str>,
    used_filenames: &mut HashMap<PathBuf, u32>,
    expected_sha256: Option<&str>,
    dir_cache: &mut DirCache,
    resolved_output: &mut Option<PathBuf>,
    send_auth: bool,
) -> Result<()> {
    // True when a previous attempt already resolved (pinned) the output path;
    // this attempt must reuse it instead of re-deriving/re-numbering it.
    let output_pinned = resolved_output.is_some();

    // 1. Determine filenames first
    let mut final_filename = determine_filename(args, url, content_disposition);
    // The pre-numbering filename, used to detect a *real* Content-Disposition
    // change on GET. Comparing against final_filename would misfire after
    // --multiple-copies collision numbering ("a.txt" vs "a.txt.1") and
    // re-number the output on every loop iteration.
    let mut head_filename = final_filename.clone();
    let mut output_path = if let Some(ref output) = args.output {
        PathBuf::from(output)
    } else {
        PathBuf::from(&final_filename)
    };

    // '-' means stdout only when explicitly requested with --output. A filename
    // derived from the URL or a server-supplied Content-Disposition must never
    // be able to flip the download into stdout mode.
    let is_stdout = args.output.as_deref() == Some("-");

    // Apply --output-dir: prefix relative paths with the output directory
    if !is_stdout
        && let Some(ref dir_str) = args.output_dir
        && output_path.is_relative()
    {
        output_path = Path::new(dir_str).join(&output_path);
        // Update final_filename to reflect the new path
        if let Some(fname) = output_path.file_name().and_then(|s| s.to_str()) {
            final_filename = fname.to_string();
        }
    }

    // Handle --multiple-copies: resolve unique output path before any file checks.
    // On retry attempts the path pinned by the first attempt is reused:
    // re-resolving with the auto-set resume flag would skip collision numbering
    // and append the resumed download into an unrelated pre-existing file.
    if !is_stdout {
        if let Some(prev) = resolved_output.as_ref() {
            output_path = prev.clone();
            if let Some(fname) = output_path.file_name().and_then(|s| s.to_str()) {
                final_filename = fname.to_string();
            }
        } else {
            let (resolved_path, was_renamed) =
                resolve_unique_output_path(&output_path, args, used_filenames, dir_cache)?;
            if was_renamed && !args.quiet {
                eprintln!(
                    "Filename collision: '{}' -> '{}'",
                    output_path.display(),
                    resolved_path.display()
                );
            }
            output_path = resolved_path;
            // Update final_filename if path changed
            if let Some(fname) = output_path.file_name().and_then(|s| s.to_str()) {
                final_filename = fname.to_string();
            }
            *resolved_output = Some(output_path.clone());
        }
    }

    if !is_stdout {
        check_path_before_open(&output_path, dir_cache)?;
    }

    // Stat output file through DirCache for size/mtime checks below
    let output_info = if !is_stdout { stat_file_via_cache(&output_path, dir_cache)? } else { None };

    // Handle -N (--newer) mode: check if remote file is newer than local file
    if args.newer
        && !is_stdout
        && let Some(ref out_info) = output_info
        && args.no_if_modified_since
    {
        // --no-if-modified-since: Use the HEAD response's Last-Modified we already have
        if let Some(lm_str) = head_last_modified
            && let Some(server_time) = parse_http_date(lm_str)
        {
            if let Some(local_mtime) = out_info.modified {
                if server_time <= local_mtime {
                    if !args.quiet {
                        eprintln!(
                            "Server file is not newer than local file '{}', skipping.",
                            output_path.display()
                        );
                    }
                    return Ok(());
                }
                if args.verbose {
                    eprintln!("Server file is newer than local file, proceeding with download.");
                }
            }
        } else if args.debug {
            eprintln!(
                "[DEBUG] -N --no-if-modified-since: No Last-Modified from HEAD, proceeding with download"
            );
        }
    }
    // If not --no-if-modified-since, we'll add If-Modified-Since to the GET request below

    // 2. Prepare Temp Path (using sanitized filename)
    let mut temp_path = if args.temp && !is_stdout {
        let parent = output_path.parent().unwrap_or(Path::new("."));
        Some(generate_deterministic_temp_filename(
            url,
            &final_filename, // Use the sanitized filename for hash
            parent,
            args.tempnamelen,
            args.debug,
        ))
    } else {
        None
    };

    // Stat temp file through DirCache
    let temp_info =
        if let Some(ref tp) = temp_path { stat_file_via_cache(tp, dir_cache)? } else { None };

    let mut start_byte: u64 = 0;
    // Handle existing file (NOT writing to stdout)
    if !is_stdout {
        // For temp mode, check if temp file exists for resume
        if let Some(ref tp) = temp_path {
            if let Some(ref t_info) = temp_info
                && args.resume
            {
                start_byte = t_info.size;

                if args.debug {
                    eprintln!(
                        "[DEBUG] Found existing temp file. Size: {}. Resume: true. New Start Byte: {}",
                        start_byte, start_byte
                    );
                }
                if let Some(total) = expected_length {
                    // --continue: skip if server file is smaller than local
                    if start_byte > total {
                        if !args.quiet {
                            eprintln!(
                                "Local temp file ({}) is larger than server file ({}), skipping.",
                                HumanBytes(start_byte),
                                HumanBytes(total)
                            );
                        }
                        return Ok(());
                    }
                    if start_byte >= total {
                        if !args.quiet {
                            eprintln!(
                                "Temp file '{}' already fully downloaded, finalizing...",
                                tp.display()
                            );
                        }
                        // Verify before finalizing: a temp file left behind by an
                        // earlier run (e.g. after a failed verification with
                        // --keep-temp) must not be promoted unchecked.
                        if let Some(expected) = expected_sha256 {
                            verify_sha256_file(tp, expected, args.quiet, dir_cache)?;
                        }
                        perform_atomic_move(tp, &output_path, args, dir_cache)?;
                        if args.server_timestamps {
                            apply_server_timestamp(
                                &output_path,
                                head_last_modified,
                                args.debug,
                                dir_cache,
                            );
                        }
                        return Ok(());
                    }
                    if !args.quiet {
                        eprintln!(
                            "Resuming temp file '{}' from byte {} ({:.1}%)",
                            tp.display(),
                            start_byte,
                            (start_byte as f64 / total as f64) * 100.0
                        );
                        eprintln!("Remaining to download: {}", HumanBytes(total - start_byte));
                    }
                } else if !args.quiet {
                    eprintln!("Resuming temp file '{}' from byte {}", tp.display(), start_byte);
                }
            } else if temp_info.is_some() && !args.resume && !args.overwrite {
                // Temp file exists but --continue not specified
                // We'll overwrite it since it's our temp file
                if !args.quiet {
                    eprintln!(
                        "Existing temp file '{}' found, starting fresh (use --continue to resume)",
                        tp.display()
                    );
                }
            } else if args.debug {
                eprintln!(
                    "[DEBUG] Temp file state: Exists={}, Resume={}, Overwrite={}. Start Byte: 0",
                    temp_info.is_some(),
                    args.resume,
                    args.overwrite
                );
            }

            // Also check if output file already exists (for temp mode)
            if let Some(ref out_info) = output_info {
                let existing_size = out_info.size;

                // Check if file is already complete
                if let Some(total) = expected_length
                    && existing_size >= total
                    && !args.newer
                    && !args.overwrite
                {
                    if !args.quiet {
                        eprintln!("File already fully downloaded.");
                    }
                    // --json-verify-hash must still check a pre-existing file
                    if let Some(expected) = expected_sha256 {
                        verify_sha256_file(&output_path, expected, args.quiet, dir_cache)?;
                    }
                    return Ok(());
                }

                // Output file exists but is incomplete
                if !args.resume && !args.overwrite && !args.newer {
                    return Err(PermanentError::FileAlreadyExists(output_path.to_path_buf()).into());
                }
                // With --resume or --overwrite or --newer, we proceed (download to temp, then rename)
                // Note: we don't resume from the output file in temp mode, we use the temp file
            }
        } else if let Some(ref out_info) = output_info {
            // Non-temp mode: check output file
            let existing_size = out_info.size;

            // --continue: skip if server file is smaller than local
            if args.resume
                && let Some(total) = expected_length
                && existing_size > total
            {
                if !args.quiet {
                    eprintln!(
                        "Local file ({}) is larger than server file ({}), skipping.",
                        HumanBytes(existing_size),
                        HumanBytes(total)
                    );
                }
                return Ok(());
            }

            // Check if file is already complete (when we know expected size)
            if let Some(total) = expected_length
                && existing_size >= total
                && !args.newer
                && !args.overwrite
            {
                if !args.quiet {
                    eprintln!("File already fully downloaded.");
                }
                // --json-verify-hash must still check a pre-existing file
                if let Some(expected) = expected_sha256 {
                    verify_sha256_file(&output_path, expected, args.quiet, dir_cache)?;
                }
                return Ok(());
            }

            // File exists but is incomplete (or unknown size)
            if args.resume {
                // --continue flag: resume from existing position
                start_byte = existing_size;
                if let Some(total) = expected_length {
                    if !args.quiet {
                        eprintln!(
                            "Resuming from byte {} ({:.1}%)",
                            start_byte,
                            (start_byte as f64 / total as f64) * 100.0
                        );
                        eprintln!("Remaining to download: {}", HumanBytes(total - start_byte));
                    }
                } else if !args.quiet {
                    eprintln!("Resuming from byte {}", start_byte);
                }
            } else if args.newer {
                // -N mode: we'll overwrite if server is newer (handled above or via If-Modified-Since)
            } else if !args.overwrite {
                // File exists, no --continue, no --overwrite: clear error
                return Err(PermanentError::FileAlreadyExists(output_path.to_path_buf()).into());
            }
            // If --overwrite is set, we fall through and truncate the file
        }
    }

    let mut force_truncate = false;
    let response;
    let mut content_length;
    let mut get_last_modified;

    // Loop added to safely retry the entire request if we discover a different
    // Content-Disposition dynamically and need to reset an active partial-resume context.
    loop {
        let mut request = client.get(url.clone());
        if start_byte > 0 {
            request = request.header(RANGE, format!("bytes={}-", start_byte));
        }

        // -N mode without --no-if-modified-since: add If-Modified-Since header
        if args.newer
            && !args.no_if_modified_since
            && !is_stdout
            && let Some(ref out_info) = output_info
            && let Some(local_mtime) = out_info.modified
            && let Some(http_date) = format_http_date(local_mtime)
        {
            if args.verbose {
                eprintln!("Sending If-Modified-Since: {}", http_date);
            }
            request = request.header(IF_MODIFIED_SINCE, http_date);
        }

        // Credentials are only sent when the final URL is still on the
        // originally requested host (see resolve_final_url_and_client).
        if send_auth && let Some(ref u) = args.user {
            request = request.basic_auth(u, args.password.as_deref());
        }

        let current_response = request.send().await.context("Failed to send GET request")?;
        let status = current_response.status();

        // Handle 304 Not Modified (from If-Modified-Since in -N mode)
        if status == StatusCode::NOT_MODIFIED {
            if !args.quiet {
                eprintln!(
                    "Server file is not newer than local file '{}', skipping.",
                    output_path.display()
                );
            }
            return Ok(());
        }

        // Check for redirect on GET (HEAD and GET may behave differently)
        if status.is_redirection() {
            if let Some(location) = current_response.headers().get(LOCATION) {
                let location_str = location.to_str().unwrap_or("<invalid>");
                return Err(PermanentError::RedirectOnGet {
                    status: status.as_u16(),
                    location: location_str.to_string(),
                }
                .into());
            }
            return Err(PermanentError::RedirectWithoutLocation(status.as_u16()).into());
        }

        if status == StatusCode::RANGE_NOT_SATISFIABLE {
            if !args.quiet {
                eprintln!("File already fully downloaded.");
            }
            // If we were using a temp file, verify (when requested) and rename it
            if let Some(ref tp) = temp_path
                && temp_info.is_some()
            {
                if let Some(expected) = expected_sha256 {
                    verify_sha256_file(tp, expected, args.quiet, dir_cache)?;
                }
                perform_atomic_move(tp, &output_path, args, dir_cache)?;
            } else if let Some(expected) = expected_sha256 {
                // Non-temp resume: the presumed-complete data already sits at
                // the output path; --json-verify-hash must still check it.
                verify_sha256_file(&output_path, expected, args.quiet, dir_cache)?;
            }
            if args.server_timestamps {
                apply_server_timestamp(&output_path, head_last_modified, args.debug, dir_cache);
            }
            return Ok(());
        }

        // Handle HTTP 4xx and 5xx errors
        if status.is_client_error() || status.is_server_error() {
            if args.content_on_error {
                if !args.quiet {
                    eprintln!(
                        "Warning: HTTP {} returned. Saving error body to file due to --content-on-error.",
                        status
                    );
                }
            } else {
                return Err(PermanentError::HttpClientError(status.as_u16()).into());
            }
        }

        get_last_modified = current_response
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Validate Content-Range when resuming
        if args.resume && start_byte > 0 {
            if status != StatusCode::PARTIAL_CONTENT {
                if !args.quiet {
                    eprintln!("Server doesn't support resume, restarting from scratch.");
                }
                start_byte = 0;
                force_truncate = true;
            } else {
                // Validate Content-Range header matches our request
                if let Some(content_range) = current_response.headers().get(CONTENT_RANGE)
                    && let Ok(range_str) = content_range.to_str()
                    && let Some(server_start) = parse_content_range(range_str)
                    && server_start != start_byte
                {
                    return Err(PermanentError::ContentRangeMismatch {
                        requested: start_byte,
                        received: server_start,
                    }
                    .into());
                }
            }
        }

        content_length = current_response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // Re-check Content-Disposition from GET response (some servers only set it on GET, not HEAD)
        // Only relevant when no explicit --output was given. Skipped when the
        // output path was pinned by a previous attempt: a retry must keep
        // writing to the exact file the first attempt chose.
        if args.output.is_none() && !is_stdout && !output_pinned {
            let get_cd = current_response
                .headers()
                .get(CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_disposition_header);

            if let Some(ref new_name) = get_cd
                && *new_name != head_filename
            {
                if args.debug {
                    eprintln!(
                        "[DEBUG] Content-Disposition changed on GET: '{}' -> '{}'",
                        head_filename, new_name
                    );
                }

                let old_filename = head_filename.clone();
                head_filename = new_name.clone();
                final_filename = new_name.clone();
                output_path = if let Some(ref dir_str) = args.output_dir {
                    Path::new(dir_str).join(&final_filename)
                } else {
                    PathBuf::from(&final_filename)
                };

                // The output path changed, so re-run the same collision/existence
                // checks that were performed for the original name at the top of
                // this function. Without this, --multiple-copies numbering, the
                // FileAlreadyExists guard and the device check would all be
                // bypassed for the new name, and an unrelated existing file could
                // be silently overwritten.
                let (resolved_path, was_renamed) =
                    resolve_unique_output_path(&output_path, args, used_filenames, dir_cache)?;
                if was_renamed && !args.quiet {
                    eprintln!(
                        "Filename collision: '{}' -> '{}'",
                        output_path.display(),
                        resolved_path.display()
                    );
                }
                output_path = resolved_path;
                if let Some(fname) = output_path.file_name().and_then(|s| s.to_str()) {
                    final_filename = fname.to_string();
                }
                *resolved_output = Some(output_path.clone());

                if args.temp {
                    let parent = output_path.parent().unwrap_or(Path::new("."));
                    temp_path = Some(generate_deterministic_temp_filename(
                        url,
                        &final_filename,
                        parent,
                        args.tempnamelen,
                        args.debug,
                    ));
                }

                check_path_before_open(&output_path, dir_cache)?;

                // Re-evaluate the existing-output guard for the new name (mirrors
                // the top-of-function logic). A pre-existing target must not be
                // silently clobbered unless --continue/--overwrite/--newer is set.
                if let Some(out_info) = stat_file_via_cache(&output_path, dir_cache)? {
                    // content_length is only the REMAINING byte count when this
                    // is a 206 response, so compare against the full size
                    // (start_byte + remaining), not the remainder alone.
                    if let Some(remaining) = content_length
                        && out_info.size >= start_byte.saturating_add(remaining)
                        && !args.newer
                        && !args.overwrite
                    {
                        if !args.quiet {
                            eprintln!("File already fully downloaded.");
                        }
                        // --json-verify-hash must still check a pre-existing file
                        if let Some(expected) = expected_sha256 {
                            verify_sha256_file(&output_path, expected, args.quiet, dir_cache)?;
                        }
                        return Ok(());
                    }
                    if !args.resume && !args.overwrite && !args.newer {
                        return Err(PermanentError::FileAlreadyExists(output_path.clone()).into());
                    }
                }

                // If we were resuming with the old temp/output file, we must
                // restart since the resume context (and the temp filename) was
                // derived from the old output filename. Re-issue the GET without a
                // Range header. When start_byte is 0 the current response already
                // holds the full body, so there is no need to re-issue.
                if start_byte > 0 {
                    if !args.quiet {
                        eprintln!(
                            "Filename changed during resume ('{}' -> '{}'), restarting download.",
                            old_filename, new_name
                        );
                    }
                    start_byte = 0;
                    force_truncate = true;
                    continue; // RE-ISSUE GET REQUEST
                }
            }
        }

        response = current_response;
        break; // Successfully got response, break loop
    }

    // Prefer GET's Last-Modified, fallback to HEAD's
    let effective_last_modified = get_last_modified.as_deref().or(head_last_modified);

    // Pre-parse server timestamp for futimens (used inside download functions)
    let server_mtime = if args.server_timestamps {
        effective_last_modified.and_then(parse_http_date)
    } else {
        None
    };

    // Calculate total size for resume logic, but for the progress bar
    // we strictly want to track the *stream* size (remaining bytes)
    // to ensure speed/ETA calculations are correct.
    let remaining_bytes = content_length;

    // If writing to stdout, bypass file/temp logic
    if is_stdout {
        // Safety: Refuse binary/unknown content to terminal unless --force-tty-write
        if std::io::stdout().is_terminal() && !args.force_tty_write {
            let get_content_type =
                response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok());
            if !is_text_content_type(get_content_type) {
                return Err(PermanentError::BinaryToTerminal(
                    get_content_type.map(|s| s.to_string()),
                )
                .into());
            }
        }
        let mut stdout = tokio::io::stdout();
        write_response_to_file(response, &mut stdout, args, remaining_bytes, start_byte, "-")
            .await?;
        return Ok(());
    }

    // In -N mode, force overwrite since we've already determined the file needs updating
    let mut effective_args = args.clone();
    if args.newer && output_info.is_some() {
        effective_args.overwrite = true;
    }

    if effective_args.temp {
        let path_buf = temp_path.clone().expect("Logic error: temp path missing");
        download_to_temp(
            response,
            &output_path,
            &effective_args,
            start_byte,
            remaining_bytes,
            force_truncate,
            path_buf,
            expected_sha256,
            dir_cache,
            server_mtime,
        )
        .await?;
    } else {
        download_direct(
            response,
            &output_path,
            &effective_args,
            start_byte,
            remaining_bytes,
            force_truncate,
            expected_sha256,
            dir_cache,
            server_mtime,
        )
        .await?;
    }

    Ok(())
}

/// Open a temp file for writing (with resume support).
/// Sandboxed across all OSes using cap-std.
fn open_temp_file_safely(
    path: &Path,
    args: &Args,
    start_byte: u64,
    force_truncate: bool,
    cache: &mut DirCache,
) -> Result<std::fs::File> {
    let parent = safe_parent(path);
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Path has no filename")
    })?;

    let dir = get_cached_dir(cache, parent)?;

    let mut opts = OpenOptions::new();
    opts.write(true);

    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        let custom_flags = libc::O_NOCTTY | libc::O_NOFOLLOW;
        opts.custom_flags(custom_flags);

        if let Some(ref mode_str) = args.filemode
            && let Ok(m) = u32::from_str_radix(mode_str, 8)
        {
            opts.mode(m);
        }
    }

    // Execute the correct open strategy via cap-std handles
    let (cap_file, file_existed) = if start_byte > 0 && !force_truncate {
        opts.append(true);
        (dir.open_with(filename, &opts)?, true)
    } else {
        // Attempt O_CREAT | O_EXCL
        let mut excl_opts = opts.clone();
        excl_opts.create_new(true);

        match dir.open_with(filename, &excl_opts) {
            Ok(f) => (f, false),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Something already sits at the temp path. Inspect it without
                // following symlinks to decide how to proceed.
                match dir.symlink_metadata(filename) {
                    // Stale regular temp file: delete and recreate fresh via
                    // O_EXCL. Unlinking depends on directory write access rather
                    // than the file's ownership, matching --overwrite semantics.
                    Ok(meta) if meta.file_type().is_file() => {
                        match dir.remove_file(filename) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                        (dir.open_with(filename, &excl_opts)?, false)
                    }
                    // Symlink/FIFO/other: never unlink or follow it. O_TRUNC plus
                    // O_NOFOLLOW makes a symlink fail with ELOOP; a FIFO opens for
                    // writing into the pipe.
                    Ok(_) => {
                        let mut trunc_opts = opts.clone();
                        trunc_opts.create(true).truncate(true);
                        (dir.open_with(filename, &trunc_opts)?, true)
                    }
                    // Vanished between the O_EXCL attempt and the stat: create fresh.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        (dir.open_with(filename, &excl_opts)?, false)
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    };

    // Convert the cap-std file to a standard file
    let std_file = cap_file.into_std();

    // Post-open TOCTOU check on any pre-existing object we actually opened (an
    // appended temp file, or a non-regular object such as a FIFO): verify on the
    // real fd that it is not a device and (unless --insecure-owner) is owned by
    // us. The delete-and-recreate path produced a brand-new O_EXCL file we own, so
    // it is exempt.
    if file_existed {
        check_file_after_open(&std_file, path, true, args.insecure_owner)?;
    }

    Ok(std_file)
}

async fn download_to_temp(
    response: Response,
    output_path: &Path,
    args: &Args,
    start_byte: u64,
    remaining_bytes: Option<u64>,
    force_truncate: bool,
    temp_path: PathBuf,
    expected_sha256: Option<&str>,
    dir_cache: &mut DirCache,
    server_mtime: Option<SystemTime>,
) -> Result<PathBuf> {
    // Store temp path for potential cleanup on signal
    {
        let mut guard = CURRENT_TEMP_PATH.lock().unwrap();
        *guard = Some(temp_path.clone());
    }

    // Log temporary filename
    if !args.quiet {
        if start_byte > 0 && !force_truncate {
            eprintln!("Resuming with temporary file: {}", temp_path.display());
        } else {
            eprintln!("Using temporary file: {}", temp_path.display());
        }
    }

    // Determine actual start byte from temp file
    let actual_start_byte = if force_truncate {
        0
    } else if start_byte > 0 {
        start_byte
    } else {
        0
    };

    // Open temp file (create or append)
    let std_file =
        open_temp_file_safely(&temp_path, args, actual_start_byte, force_truncate, dir_cache)
            .context("Failed to open temp file")?;

    let mut async_file = tokio::fs::File::from_std(std_file);
    let bytes_written = write_response_to_file(
        response,
        &mut async_file,
        args,
        remaining_bytes,
        actual_start_byte,
        output_path.to_str().unwrap_or(""),
    )
    .await?;

    match async_file.sync_all().await {
        Ok(_) => {}
        Err(e) if is_sync_ignorable(&e) => {}
        Err(e) => return Err(e.into()),
    };

    // Apply server timestamp on the temp file via futimens BEFORE close and rename.
    // The mtime is set on the temp file's fd — rename preserves inode metadata,
    // so the final file inherits the correct mtime.
    if let Some(mtime) = server_mtime {
        let std_file = async_file.into_std().await;
        if let Err(e) = set_mtime_on_fd(&std_file, mtime) {
            if args.debug {
                eprintln!("[DEBUG] futimens on temp file failed: {}", e);
            }
        } else if args.debug {
            eprintln!("[DEBUG] Set temp file mtime via futimens before rename");
        }
        drop(std_file);
    } else {
        drop(async_file);
    }

    // Verify SHA256 on the temp file BEFORE renaming to the final path.
    // This way a corrupt download never overwrites a good file.
    if let Some(expected) = expected_sha256
        && let Err(e) = verify_sha256_file(&temp_path, expected, args.quiet, dir_cache)
    {
        {
            let mut guard = CURRENT_TEMP_PATH.lock().unwrap();
            *guard = None;
        }
        // A temp file that failed verification must not survive by default:
        // with the deterministic temp name a later `--temp --continue` run
        // would see it as size-complete and finalize it. With --keep-temp it
        // is kept for inspection; the finalize paths re-verify before
        // promoting it.
        if !args.keep_temp {
            let _ = std::fs::remove_file(&temp_path);
        }
        return Err(e);
    }

    let move_result = perform_atomic_move(&temp_path, output_path, args, dir_cache);
    {
        let mut guard = CURRENT_TEMP_PATH.lock().unwrap();
        *guard = None;
    }
    match move_result {
        Ok(path) => {
            // SUCCESS: Log the output and return the path
            if !args.quiet {
                eprintln!(
                    "Downloaded {} to {}",
                    HumanBytes(bytes_written + actual_start_byte),
                    path.display()
                );
                if bytes_written == 0 {
                    eprintln!("(No new data written)");
                }
            }
            Ok(path)
        }
        Err(e) => {
            // FAILURE: Clean up the temp file (unless --keep-temp is set)
            if !args.keep_temp && temp_path.exists() {
                let _ = std::fs::remove_file(&temp_path);
            }
            Err(e)
        }
    }
}

async fn download_direct(
    response: Response,
    output_path: &Path,
    args: &Args,
    start_byte: u64,
    remaining_bytes: Option<u64>,
    force_truncate: bool,
    expected_sha256: Option<&str>,
    dir_cache: &mut DirCache,
    server_mtime: Option<SystemTime>,
) -> Result<PathBuf> {
    let (std_file, actual_path) =
        match open_file_securely(output_path, args, start_byte, force_truncate, dir_cache) {
            Ok((f, _existed)) => (f, output_path.to_path_buf()),
            Err(e) => {
                // Check if the root cause is ENAMETOOLONG
                let is_too_long = e
                    .chain()
                    .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .any(is_name_too_long);

                if is_too_long {
                    let truncated = resolve_output_path(output_path)?;
                    if truncated == output_path {
                        return Err(PermanentError::FilenameTooLong.into());
                    }
                    eprintln!("Filename too long, truncating to: {}", truncated.display());

                    // Retry with truncated path
                    match open_file_securely(
                        &truncated,
                        args,
                        start_byte,
                        force_truncate,
                        dir_cache,
                    ) {
                        Ok((f, _)) => (f, truncated),
                        Err(e) => return Err(e),
                    }
                } else {
                    return Err(e);
                }
            }
        };

    let mut file = tokio::fs::File::from_std(std_file);
    let bytes_written = write_response_to_file(
        response,
        &mut file,
        args,
        remaining_bytes,
        start_byte,
        output_path.to_str().unwrap_or(""),
    )
    .await?;
    match file.sync_all().await {
        Ok(_) => {}
        Err(e) if is_sync_ignorable(&e) => {}
        Err(e) => return Err(e.into()),
    };

    // Apply server timestamp via futimens on the still-open fd, after fsync.
    // This avoids reopening the file and is TOCTOU-safe.
    if let Some(mtime) = server_mtime {
        let std_file = file.into_std().await;
        if let Err(e) = set_mtime_on_fd(&std_file, mtime) {
            if args.debug {
                eprintln!("[DEBUG] futimens on output file failed: {}", e);
            }
        } else if args.debug {
            eprintln!("[DEBUG] Set output file mtime via futimens");
        }
        // Must drop the std file handle so the blocking SHA256 read can open it
        drop(std_file);
    } else {
        drop(file);
    }

    // Verify SHA256 after writing and syncing
    if let Some(expected) = expected_sha256 {
        verify_sha256_file(&actual_path, expected, args.quiet, dir_cache)?;
    }

    if !args.quiet {
        eprintln!(
            "Downloaded {} to {}",
            HumanBytes(bytes_written + start_byte),
            actual_path.display()
        );
    }

    Ok(actual_path)
}

async fn write_response_to_file<W: AsyncWrite + Unpin>(
    response: Response,
    writer_dest: &mut W,
    args: &Args,
    remaining_bytes: Option<u64>,
    start_byte: u64,
    output_path_str: &str,
) -> Result<u64> {
    let mut bytes_written: u64 = 0;
    let buf_capacity = if output_path_str == "-" { 64 * 1024 } else { BUFFER_SIZE };
    let mut writer = TokBufWriter::with_capacity(buf_capacity, writer_dest);

    // Progress Bar Setup
    // Hide progress bar when writing to stdout to avoid polluting the output
    let pb = if args.quiet || output_path_str == "-" {
        ProgressBar::hidden()
    } else if let Some(len) = remaining_bytes {
        let pb = ProgressBar::new(len);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-"));
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {bytes} ({bytes_per_sec})")?,
        );
        pb
    };

    // Use the raw stream.
    // Since we are now on 'current_thread' runtime, we don't need fancy
    // buffering to avoid cross-thread wakeups, because there are no other threads.
    let mut stream = response.bytes_stream();

    // Reusable timer
    let sleep_timer = tokio::time::sleep(Duration::from_secs(args.timeout));
    tokio::pin!(sleep_timer);

    let mut accumulated_bytes: u64 = 0;
    let mut last_update = Instant::now();

    loop {
        let chunk_result = tokio::select! {
            res = stream.next() => res,
            _ = &mut sleep_timer => {
                bail!("Timed out waiting for data ({}s)", args.timeout);
            }
        };

        match chunk_result {
            Some(Ok(chunk)) => {
                let chunk_len = chunk.len() as u64;

                if let Some(max_size) = args.max_size
                    && start_byte + bytes_written + chunk_len > max_size
                {
                    return Err(PermanentError::DownloadExceedsLimit { max: max_size }.into());
                }

                if let Err(e) = writer.write_all(&chunk).await {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        // Consumer closed the pipe (e.g. `| head`). Stop cleanly.
                        break;
                    }
                    return Err(e.into());
                }

                bytes_written += chunk_len;
                accumulated_bytes += chunk_len;

                // Throttled UI updates
                if last_update.elapsed().as_millis() > 25 {
                    if !args.quiet {
                        pb.inc(accumulated_bytes);
                    }
                    accumulated_bytes = 0;
                    sleep_timer.as_mut().reset(Instant::now() + Duration::from_secs(args.timeout));
                    last_update = Instant::now();
                }
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }

    if !args.quiet && accumulated_bytes > 0 {
        pb.inc(accumulated_bytes);
    }
    // Flush and ignore BrokenPipe on flush too
    if let Err(e) = writer.flush().await
        && e.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(e.into());
    }
    if !args.quiet {
        pb.finish_with_message("Download complete");
    }

    Ok(bytes_written)
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
#[cfg(not(miri))]
pub fn apply_security_sandbox() -> Result<(), Box<dyn std::error::Error>> {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    // Block specific syscalls entirely
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("execve")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("execveat")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("accept")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("accept4")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("bind")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("listen")?)?;
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), ScmpSyscall::from_name("ptrace")?)?;

    // Block specific socket families.
    // NOTE: glibc's getaddrinfo() opens an AF_NETLINK socket (__check_pf) to
    // enumerate local addresses and may try AF_UNIX to reach nscd or
    // systemd-resolved. Blocking these relies on glibc's fallback paths: on
    // socket() failure it assumes both address families are configured and
    // falls back to plain DNS via resolv.conf. musl is unaffected. If name
    // resolution ever breaks under this filter, these families are the first
    // suspects.
    let blocked_families =
        [libc::AF_UNIX, libc::AF_NETLINK, libc::AF_PACKET, libc::AF_BLUETOOTH, libc::AF_VSOCK];

    for family in blocked_families {
        ctx.add_rule_conditional(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name("socket")?,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, family as u64)],
        )?;
    }

    ctx.load()?;
    Ok(())
}

#[cfg(any(miri, target_os = "android", not(target_os = "linux")))]
pub fn apply_security_sandbox() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

//#[tokio::main]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Install the default crypto provider (aws-lc-rs) globally
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // NOTE: rustls_platform_verifier::android::init_hosted() is NOT called here
    // because this is a CLI binary, not a JNI library loaded by a JVM.
    // If running on Android (e.g., Termux), we fallback to webpki-roots in build_client.

    // Parse args early to set keep_temp flag
    let mut args = Args::parse();

    // --debug implies --verbose
    if args.debug {
        args.verbose = true;
    }

    // Set global flag for signal handler
    KEEP_TEMP_ON_CANCEL.store(args.keep_temp, Ordering::SeqCst);

    // Load HSTS database once at startup (skip if --no-hsts-update)
    let no_hsts_update = args.no_hsts_update;
    let hsts_path =
        if let Some(ref p) = args.hsts_file { PathBuf::from(p) } else { get_default_hsts_path() };
    let mut hsts_db = if no_hsts_update { HashMap::new() } else { load_hsts_db(&hsts_path) };

    let exit_code = tokio::select! {
        result = run_with_args(args, &mut hsts_db) => {
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {:#}", e);
                    ExitCode::FAILURE
                }
            }
        },
        _ = shutdown_signal() => {
            let keep_temp = KEEP_TEMP_ON_CANCEL.load(Ordering::SeqCst);

            if keep_temp {
                // Check if there's a temp file to keep
                let temp_path = CURRENT_TEMP_PATH.lock().unwrap().clone();
                if let Some(tp) = temp_path {
                    eprintln!("\nDownload cancelled. Keeping temporary file: {}", tp.display());
                    eprintln!("Resume with: {} --temp --continue <url>", env!("CARGO_PKG_NAME"));
                } else {
                    eprintln!("\nDownload cancelled.");
                }
            } else {
                // Clean up temp file if exists
                let temp_path = CURRENT_TEMP_PATH.lock().unwrap().take();
                if let Some(tp) = temp_path {
                    if tp.exists() {
                        let _ = fs::remove_file(&tp);
                        eprintln!("\nDownload cancelled. Temporary file removed.");
                    } else {
                        eprintln!("\nDownload cancelled.");
                    }
                } else {
                    eprintln!("\nDownload cancelled.");
                }
            }
            ExitCode::FAILURE
        }
    };

    // Save HSTS database exactly once, regardless of how we exited (skip if --no-hsts-update)
    if !no_hsts_update {
        save_hsts_db(&hsts_path, &hsts_db);
    }

    exit_code
}

/// Helper to listen for Ctrl+C (SIGINT) and SIGTERM (Unix)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        // Handle SIGTERM (standard kill command)
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>(); // Wait forever on Windows/other

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_hsts;
#[cfg(test)]
mod tests_json_alignment;
