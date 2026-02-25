// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 Sami Farin

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
use std::fs::{self, File, OpenOptions};
use std::io::IsTerminal;
use std::io::{BufRead, BufReader, BufWriter, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::content_disposition::{DispositionType, parse_content_disposition};
use anyhow::{Context, Result, bail};
use clap::Parser;
use clap::builder::TypedValueParser;
use data_encoding::BASE32_NOPAD;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use reqwest::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE,
    STRICT_TRANSPORT_SECURITY,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Identity, Response, StatusCode};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use sha3::{
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

#[derive(Debug)]
pub enum PermanentError {
    // Size limits
    FileSizeExceedsLimit { size: u64, max: u64, url: String },
    DownloadExceedsLimit { max: u64 },

    // File conflicts
    FileAlreadyExists(PathBuf),
    TruncatedFilenameExists(PathBuf),
    FilenameTooLong,

    // URL/scheme errors
    InsecureUrl(String),
    UnsupportedScheme(String),

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
    HttpClientError(u16), // 4xx errors

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
                    "File '{}' already exists. Use --continue to resume or --overwrite to replace.",
                    path.display()
                )
            }
            Self::TruncatedFilenameExists(path) => {
                write!(f, "Truncated filename '{}' already exists.", path.display())
            }
            Self::FilenameTooLong => {
                write!(f, "Filename too long and cannot be truncated")
            }
            Self::InsecureUrl(url) => {
                write!(f, "Refusing insecure HTTP URL: {}. Use --insecure to allow.", url)
            }
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
                    "Server returned redirect on GET ({}). This may indicate HEAD/GET inconsistency. Redirect target: {}",
                    status, location
                )
            }
            Self::HttpClientError(status) => {
                write!(f, "Download failed with HTTP status: {}", status)
            }
            Self::FileAppearedDuringDownload(path) => {
                write!(
                    f,
                    "File '{}' appeared during download (TOCTOU race). Use --overwrite to replace.",
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
        }
    }
}

impl std::error::Error for PermanentError {}

/// Maximum number of redirects to follow
const MAX_REDIRECTS: usize = 20;

const BUFFER_SIZE: usize = 1024 * 1024;

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

/// Apply safe open flags (O_NOFOLLOW | O_NOCTTY) on Unix
#[cfg(unix)]
fn apply_safe_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NOCTTY);
}

#[cfg(not(unix))]
fn apply_safe_flags(_opts: &mut OpenOptions) {}

#[cfg(unix)]
fn apply_file_mode(opts: &mut OpenOptions, args: &Args) {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(ref mode_str) = args.filemode
        && let Ok(mode) = u32::from_str_radix(mode_str, 8)
    {
        opts.mode(mode);
    }
}

/// HSTS database filename
const HSTS_DB_FILENAME: &str = "hsts.json";

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

    /// Overwrite existing file without prompting
    #[arg(long = "overwrite", help = "Overwrite existing file")]
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

    /// Timeout in seconds if no data is received (default: 300)
    #[arg(long = "timeout", default_value_t = 300, help = "Timeout in seconds (no data received)")]
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

    /// Read URLs from a local or external file
    #[arg(short = 'i', long = "input-file", help = "Read URLs from a local or external file")]
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
        help = "Path to HSTS cache file (default: ~/.config/rget/hsts.conf)"
    )]
    hsts_file: Option<String>,
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

    match File::create(path) {
        Ok(file) => {
            let writer = BufWriter::new(file);
            if let Err(e) = serde_json::to_writer_pretty(writer, &valid_entries) {
                eprintln!("Failed to serialize HSTS DB to '{}': {}", path.display(), e);
            }
        }
        Err(e) => {
            eprintln!("Failed to write HSTS DB to '{}': {}", path.display(), e);
        }
    }
}

fn check_hsts(map: &HstsMap, host: &str) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // Check exact match
    if let Some(entry) = map.get(host)
        && entry.expiry > now
    {
        return true;
    }

    // Check superdomains if they have includeSubDomains set
    let mut parts: Vec<&str> = host.split('.').collect();
    while parts.len() > 1 {
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
    if let Some(hsts_val) = headers.get(STRICT_TRANSPORT_SECURITY)
        && let Ok(hsts_str) = hsts_val.to_str()
    {
        let mut max_age = None;
        let mut include_subdomains = false;

        for part in hsts_str.split(';') {
            let part = part.trim();
            if part.eq_ignore_ascii_case("includeSubDomains") {
                include_subdomains = true;
            } else if let Some(age_str) = part.to_lowercase().strip_prefix("max-age=")
                && let Ok(age) = age_str.trim().parse::<u64>()
            {
                max_age = Some(age);
            }
        }

        if let Some(age) = max_age {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let expiry = now + age;
            if let Some(host) = url.host_str() {
                map.insert(host.to_string(), HstsEntry { expiry, include_subdomains });

                if debug {
                    eprintln!(
                        "[DEBUG] HSTS: Added/Updated entry for '{}' (max-age={}, includeSubDomains={})",
                        host, age, include_subdomains
                    );
                }
            }
        }
    }
}

fn build_client(args: &Args, resolve_override: Option<(&str, SocketAddr)>) -> Result<Client> {
    let mut builder = Client::builder()
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
        // Secure Path: Use platform verifier and manual mTLS config
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

            tls_builder
                .with_client_auth_cert(certs, key)
                .context("Failed to configure client auth")?
        } else {
            tls_builder.with_no_client_auth()
        };

        builder = builder.use_preconfigured_tls(client_config);
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

    builder.build().context("Failed to build HTTP client")
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
) -> Result<(Client, Url, Option<u64>, Option<String>)> {
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
            && (std::env::var("HTTP_PROXY").is_ok() || std::env::var("HTTPS_PROXY").is_ok())
        {
            build_client(args, None)?
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
                let new_client = build_client(args, Some((host, safe_ip)))?;
                client_cache.insert(cache_key, new_client.clone());
                new_client
            }
        };

        let mut request = client.head(current_url.clone());
        if let Some(ref u) = args.user {
            request = request.basic_auth(u, args.password.as_deref());
        }

        let mut response = request.send().await.context("Failed to send HEAD request")?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            if args.debug {
                eprintln!("[DEBUG] HEAD status: 405 Method Not Allowed. Retrying with GET...");
            }
            let mut get_request = client.get(current_url.clone());
            if let Some(ref u) = args.user {
                get_request = get_request.basic_auth(u, args.password.as_deref());
            }
            response = get_request.send().await.context("Failed to send GET request")?;
        }

        update_hsts(hsts_db, &current_url, response.headers(), args.debug);

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

        if status.is_success() || status.is_client_error() || status.is_server_error() {
            return Ok((client, current_url, content_length, content_disposition));
        }

        bail!("Unexpected status code: {}", status);
    }
}

async fn run_with_args(args: Args) -> Result<()> {
    let mut all_urls = args.urls.clone();

    env_logger::init();
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
            if !trimmed.is_empty() {
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

    if args.output.is_some() && urls.len() > 1 {
        return Err(PermanentError::InvalidArguments(
            "--output cannot be used with multiple URLs".to_string(),
        )
        .into());
    }

    if let Err(e) = apply_security_sandbox() {
        eprintln!("Failed to apply seccomp filter: {}", e);
        std::process::exit(1);
    }

    // Load HSTS Database
    let hsts_path =
        if let Some(p) = &args.hsts_file { PathBuf::from(p) } else { get_default_hsts_path() };
    let mut hsts_db = load_hsts_db(&hsts_path);

    let mut client_cache: HashMap<String, Client> = HashMap::new();
    let mut overall_success = true;
    let max_retries = if args.retries == 0 { u64::MAX } else { args.retries };

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

        let mut attempt = 0;
        loop {
            let mut current_args = args.clone();
            if attempt > 0 {
                current_args.resume = true;
            }

            // Pass the cache to be used/updated
            let result = async {
                match resolve_final_url_and_client(
                    url.clone(),
                    &current_args,
                    &mut client_cache,
                    &mut hsts_db,
                )
                .await
                {
                    Ok((client, final_url, content_length, content_disposition)) => {
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
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            .await;

            match result {
                Ok(()) => break,
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
                        if args.retries == 0 {
                            "\u{221e}".to_string()
                        } else {
                            args.retries.to_string()
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

    save_hsts_db(&hsts_path, &hsts_db);

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
                // Shared Address Space (RFC 6598): 100.64.0.0/10
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
                // IETF Protocol Assignments: 192.0.0.0/24
                || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
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

    // 2. Handle 'filename*' (High Priority)
    if let Some(raw_ext) = data.params.get("filename*") {
        let parts: Vec<&str> = raw_ext.split('\'').collect();
        // The last part contains the encoded text (UTF-8''%E2%9C%93.txt -> %E2%9C%93.txt)
        if let Some(encoded) = parts.last() {
            // CALL THE HELPER HERE
            let decoded = percent_decode_str(encoded);
            return Some(sanitize_filename(&decoded));
        }
    }

    // 3. Handle 'filename' (Low Priority)
    if let Some(name) = data.params.get("filename") {
        return Some(sanitize_filename(name));
    }

    None
}

// This takes a string slice and returns a STRING.
// It handles the hex decoding and the UTF-8 conversion internally.
fn percent_decode_str(input: &str) -> String {
    let mut res = Vec::new();
    let mut bytes = input.bytes();

    while let Some(b) = bytes.next() {
        if b == b'%' {
            // Try to read the next two bytes without inventing zeros
            let h1 = bytes.next();
            let h2 = bytes.next();

            match (h1, h2) {
                (Some(v1), Some(v2)) => {
                    // We have two bytes, try to decode them as hex
                    let hex_str = format!("{}{}", v1 as char, v2 as char);
                    if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                        res.push(byte);
                    } else {
                        // Not valid hex, push raw sequence
                        res.push(b);
                        res.push(v1);
                        res.push(v2);
                    }
                }
                (Some(v1), None) => {
                    // String ended after %X (incomplete sequence)
                    res.push(b);
                    res.push(v1);
                }
                (None, None) => {
                    // String ended after %
                    res.push(b);
                }
                _ => unreachable!(), // Iterator can't go from None back to Some
            }
        } else {
            res.push(b);
        }
    }

    String::from_utf8_lossy(&res).to_string()
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

    // 3. Windows Reserved Name Check (Windows Only)
    #[cfg(windows)]
    {
        use std::path::Path;

        let stem =
            Path::new(&sanitized).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_uppercase();

        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "COM0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
            "LPT9", "LPT0",
        ];

        if reserved_names.contains(&stem.as_str()) {
            // Replace ONLY the reserved word with '_', preserving extension
            let extension =
                Path::new(&sanitized).extension().and_then(|e| e.to_str()).unwrap_or("");

            if !extension.is_empty() {
                sanitized = format!("_.{}", extension);
            } else {
                sanitized = "_".to_string();
            }
        }
    }

    if sanitized.is_empty() { "download".to_string() } else { sanitized }
}

fn filename_from_url(url: &Url) -> String {
    let path = url.path();
    let decoded_path = percent_decode_str(path);
    let filename =
        decoded_path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("index.html");
    let filename = filename.split('?').next().unwrap_or(filename);
    let filename = filename.split('#').next().unwrap_or(filename);
    sanitize_filename(filename)
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

/// Pre-open check: stat() the path to reject block/char devices before opening.
/// Returns Ok(true) if file exists, Ok(false) if it doesn't exist.
/// This performs exactly one stat() call for existing files.
/// Returns error if file is a block or char device.
#[cfg(unix)]
fn check_path_before_open(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    match fs::metadata(path) {
        Ok(metadata) => {
            // File exists - check if it's a device
            if let Some(device_type) = is_block_or_char_device(metadata.mode()) {
                return if device_type == "block" {
                    Err(PermanentError::BlockDeviceNotAllowed(path.to_path_buf()).into())
                } else {
                    Err(PermanentError::CharDeviceNotAllowed(path.to_path_buf()).into())
                };
            }
            Ok(true) // File exists and is not a device
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(false) // File doesn't exist
        }
        Err(_) => {
            // Other error (permission denied, etc.) - let open() handle it
            Ok(false)
        }
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
        let process_uid = nix::unistd::getuid().as_raw();

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

// Windows stub implementations
#[cfg(not(unix))]
fn check_path_before_open(path: &Path) -> Result<bool> {
    Ok(path.exists())
}

#[cfg(not(unix))]
fn check_file_after_open(
    _file: &File,
    _path: &Path,
    _check_owner: bool,
    _insecure_owner: bool,
) -> Result<()> {
    Ok(())
}

fn open_file_safely(
    path: &Path,
    args: &Args,
    start_byte: u64,
    force_truncate: bool,
) -> Result<File> {
    // Pre-open check: stat() to reject block/char devices AND determine if file exists
    let file_existed = check_path_before_open(path)?;
    let is_append = start_byte > 0;
    let mut opts = OpenOptions::new();

    if is_append {
        opts.append(true);
    } else if file_existed || args.overwrite || force_truncate {
        // File exists (even if 0 bytes) OR overwrite/truncate requested: truncate
        opts.create(true).write(true).truncate(true);
    } else {
        // File doesn't exist and no overwrite: create new (O_EXCL)
        opts.write(true).create_new(true);
    }

    apply_safe_flags(&mut opts);
    #[cfg(unix)]
    apply_file_mode(&mut opts, args);

    let file = opts.open(path)?;

    // Post-open check: fstat() for TOCTOU protection and owner verification
    // Owner check applies when operating on EXISTING files
    let check_owner = file_existed;
    check_file_after_open(&file, path, check_owner, args.insecure_owner)?;

    Ok(file)
}

/// Low-level helper: Rename a file atomically without overwriting the destination.
/// Includes fallback for Android/FAT filesystems where renameat2 is not supported.
fn rename_noreplace(from: &Path, to: &Path, debug: bool) -> std::io::Result<()> {
    // Android is a "Unix" but not "Linux" in Rust `cfg` terms (target_os = "android").
    // However, we want it to use the robust Linux logic (renameat2 if available, plus Last Resort fallback)
    // instead of the generic Unix fallback (which relies only on hard links and fails on /sdcard).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // 1. Try atomic renameat2 via nix (Linux Only)
        // renameat2 is not available in nix on Android, so we skip this step there.
        #[cfg(target_os = "linux")]
        {
            use nix::fcntl::{RenameFlags, renameat2};
            use std::os::fd::BorrowedFd;
            let cwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };

            // Passing 'None' for dirfd is equivalent to AT_FDCWD
            match renameat2(cwd, from, cwd, to, RenameFlags::RENAME_NOREPLACE) {
                Ok(_) => {
                    if debug {
                        eprintln!("[DEBUG] renameat2 succeeded");
                    }
                    return Ok(());
                }
                Err(e) => {
                    if debug {
                        eprintln!(
                            "[DEBUG] renameat2 failed: {} (errno: {}). Checking fallback...",
                            e, e as i32
                        );
                    }
                    // If the OS explicitly says "File Exists", respect it immediately.
                    if e == nix::errno::Errno::EEXIST {
                        return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
                    }
                }
            }
        }

        // 2. Fallback: Hard Link + Unlink (POSIX atomic standard)
        // This fails on Android /sdcard (FAT/Emulated)
        if debug {
            eprintln!("[DEBUG] Attempting fallback: hard link + unlink");
        }
        if std::fs::hard_link(from, to).is_ok() {
            let _ = std::fs::remove_file(from);
            return Ok(());
        }

        // 3. Last Resort:  plain rename (not atomic noreplace, but best we can do)
        if debug {
            eprintln!("[DEBUG] Attempting last resort: rename (if dst missing)");
        }
        if to.exists() {
            return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
        }
        std::fs::rename(from, to)
    }

    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "android")))]
    {
        if debug {
            eprintln!("[DEBUG] rename_noreplace: using hard_link fallback (non-linux)");
        }
        match std::fs::hard_link(from, to) {
            Ok(()) => {
                std::fs::remove_file(from)?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(windows)]
    {
        if debug {
            eprintln!("[DEBUG] rename_noreplace: using rename fallback (windows)");
        }
        if to.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Destination exists",
            ));
        }
        std::fs::rename(from, to)
    }
}

/// High-level helper: Handles the decision between overwrite vs noreplace,
/// and handles Filename Too Long truncation logic automatically.
fn perform_atomic_move(temp_path: &Path, target_path: &Path, args: &Args) -> Result<PathBuf> {
    // Helper closure to attempt the actual move operation based on flags
    let try_move = |src: &Path, dst: &Path| -> std::io::Result<()> {
        // If we are resuming (--continue) OR overwriting, we implicitly
        // have permission to replace the destination file.
        if args.overwrite || args.resume {
            if args.debug {
                eprintln!(
                    "[DEBUG] Force rename (overwrite/resume): '{}' -> '{}'",
                    src.display(),
                    dst.display()
                );
            }
            std::fs::rename(src, dst)
        } else {
            rename_noreplace(src, dst, args.debug)
        }
    };

    // Attempt 1: Try the move
    match try_move(temp_path, target_path) {
        Ok(_) => Ok(target_path.to_path_buf()),

        // Handle "File Exists" logic (from rename_noreplace OR fs::rename failure)
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if args.overwrite || args.resume {
                // If we are here and overwrite/resume is TRUE, then this error is
                // a hard error (e.g. destination is a directory, or permission denied),
                // because fs::rename would normally have succeeded in replacing a file.
                Err(e.into())
            } else {
                // If overwrite=false and resume=false, this is the intended protection.
                // We map it to our nice error message.
                Err(PermanentError::FileAlreadyExists(target_path.to_path_buf()).into())
            }
        }

        // Handle "Filename Too Long" logic
        Err(e) if is_name_too_long(&e) => {
            let truncated = resolve_output_path(target_path)?;

            // Safety check: if truncation didn't actually shorten it, stop to avoid infinite loop
            if truncated == target_path {
                return Err(PermanentError::FilenameTooLong.into());
            }

            if !args.quiet {
                eprintln!("Filename too long, retrying with: {}", truncated.display());
            }

            // Attempt 2: Try with truncated name
            match try_move(temp_path, &truncated) {
                Ok(_) => Ok(truncated),
                // If the truncated filename also exists:
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(PermanentError::TruncatedFilenameExists(truncated).into())
                }
                Err(e) => Err(e).context("Failed to rename to truncated path"),
            }
        }

        // Handle TOCTOU race (File appeared during download) special error mapping.
        // This catches cases where the file didn't exist when we started, but does now.
        Err(e)
            if !args.overwrite
                && !args.resume
                && (e.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            Err(PermanentError::FileAppearedDuringDownload(target_path.to_path_buf()).into())
        }

        // Catch-all for other I/O errors
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
    if err.downcast_ref::<PermanentError>().is_some() {
        return true;
    }

    // Check for IO errors using portable ErrorKinds
    if let Some(io_err) = err.root_cause().downcast_ref::<std::io::Error>() {
        return matches!(
            io_err.kind(),
            ErrorKind::InvalidInput
                | ErrorKind::PermissionDenied
                | ErrorKind::AlreadyExists
                // | ErrorKind::FilesystemLoop // https://github.com/rust-lang/rust/issues/86442
                | ErrorKind::ReadOnlyFilesystem
                | ErrorKind::FileTooLarge
                | ErrorKind::NotSeekable
                | ErrorKind::IsADirectory
                | ErrorKind::StorageFull
                | ErrorKind::BrokenPipe
                | ErrorKind::QuotaExceeded // Rust 1.74
        );
    }

    // Check for HTTP client errors (4xx except 429)
    if let Some(reqwest_err) = err.root_cause().downcast_ref::<reqwest::Error>()
        && let Some(status) = reqwest_err.status()
    {
        // 4xx errors are permanent (except 429 Too Many Requests)
        if status.is_client_error() && status.as_u16() != 429 {
            return true;
        }
    }

    false
}

async fn download_file(
    client: &Client,
    url: &Url,
    args: &Args,
    expected_length: Option<u64>,
    content_disposition: Option<&str>,
) -> Result<()> {
    // 1. Determine filenames first
    let mut final_filename = determine_filename(args, url, content_disposition);
    let mut output_path = if let Some(ref output) = args.output {
        PathBuf::from(output)
    } else {
        PathBuf::from(&final_filename)
    };

    let is_stdout = output_path.to_str() == Some("-");
    if !is_stdout {
        check_path_before_open(&output_path)?;
    }

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

    let mut start_byte: u64 = 0;
    // Handle existing file (NOT writing to stdout)
    if !is_stdout {
        // For temp mode, check if temp file exists for resume
        if let Some(ref tp) = temp_path {
            if tp.exists() && args.resume {
                let metadata = fs::metadata(tp)?;
                start_byte = metadata.len();

                if args.debug {
                    eprintln!(
                        "[DEBUG] Found existing temp file. Size: {}. Resume: true. New Start Byte: {}",
                        start_byte, start_byte
                    );
                }
                if let Some(total) = expected_length {
                    if start_byte >= total {
                        if !args.quiet {
                            eprintln!(
                                "Temp file '{}' already fully downloaded, finalizing...",
                                tp.display()
                            );
                        }
                        perform_atomic_move(tp, &output_path, args)?;
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
            } else if tp.exists() && !args.resume && !args.overwrite {
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
                    tp.exists(),
                    args.resume,
                    args.overwrite
                );
            }

            // Also check if output file already exists (for temp mode)
            if output_path.exists() {
                let metadata = fs::metadata(&output_path)?;
                let existing_size = metadata.len();

                // Check if file is already complete
                if let Some(total) = expected_length
                    && existing_size >= total
                {
                    if !args.quiet {
                        eprintln!("File already fully downloaded.");
                    }
                    return Ok(());
                }

                // Output file exists but is incomplete
                if !args.resume && !args.overwrite {
                    return Err(PermanentError::FileAlreadyExists(output_path.to_path_buf()).into());
                }
                // With --resume or --overwrite, we proceed (download to temp, then rename)
                // Note: we don't resume from the output file in temp mode, we use the temp file
            }
        } else if output_path.exists() {
            // Non-temp mode: check output file
            let metadata = fs::metadata(&output_path)?;
            let existing_size = metadata.len();

            // Check if file is already complete (when we know expected size)
            if let Some(total) = expected_length
                && existing_size >= total
            {
                if !args.quiet {
                    eprintln!("File already fully downloaded.");
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
            } else if !args.overwrite {
                // File exists, no --continue, no --overwrite: clear error
                return Err(PermanentError::FileAlreadyExists(output_path.to_path_buf()).into());
            }
            // If --overwrite is set, we fall through and truncate the file
        }
    }

    let mut request = client.get(url.clone());
    if start_byte > 0 {
        request = request.header(RANGE, format!("bytes={}-", start_byte));
    }

    if let Some(ref u) = args.user {
        request = request.basic_auth(u, args.password.as_deref());
    }

    let response = request.send().await.context("Failed to send GET request")?;
    let status = response.status();

    // Check for redirect on GET (HEAD and GET may behave differently)
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

    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        if !args.quiet {
            eprintln!("File already fully downloaded.");
        }
        // If we were using a temp file, rename it
        if let Some(ref tp) = temp_path
            && tp.exists()
        {
            perform_atomic_move(tp, &output_path, args)?;
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

    let mut force_truncate = false;
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
            if let Some(content_range) = response.headers().get(CONTENT_RANGE)
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

    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Calculate total size for resume logic, but for the progress bar
    // we strictly want to track the *stream* size (remaining bytes)
    // to ensure speed/ETA calculations are correct.
    let remaining_bytes = content_length;

    // Re-check Content-Disposition from GET response (some servers only set it on GET, not HEAD)
    // Only relevant when no explicit --output was given
    if args.output.is_none() && !is_stdout {
        let get_cd = response
            .headers()
            .get(CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_content_disposition_header);

        if let Some(ref new_name) = get_cd
            && *new_name != final_filename
        {
            if args.debug {
                eprintln!(
                    "[DEBUG] Content-Disposition changed on GET: '{}' -> '{}'",
                    final_filename, new_name
                );
            }
            // If we were resuming with the old temp file, we must restart since
            // the temp filename is derived from the output filename
            if start_byte > 0 {
                if !args.quiet {
                    eprintln!(
                        "Filename changed during resume ('{}' -> '{}'), restarting download.",
                        final_filename, new_name
                    );
                }
                start_byte = 0;
                force_truncate = true;
            }

            final_filename = new_name.clone();
            output_path = PathBuf::from(&final_filename);

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
        }
    }

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

    if args.temp {
        let path_buf = temp_path.clone().expect("Logic error: temp path missing");
        download_to_temp(
            response,
            &output_path,
            args,
            start_byte,
            remaining_bytes,
            force_truncate,
            path_buf,
        )
        .await?;
    } else {
        download_direct(response, &output_path, args, start_byte, remaining_bytes, force_truncate)
            .await?;
    }

    Ok(())
}

/// Open a temp file for writing (with resume support).
///
/// - Uses O_EXCL (create_new) when starting fresh to prevent race conditions.
/// - Uses mode defined by --filemode or umask (default) for security.
/// - Handles resuming via Append mode.
fn open_temp_file_safely(
    path: &Path,
    _args: &Args,
    start_byte: u64,
    force_truncate: bool,
) -> std::io::Result<File> {
    // Case 1: Resuming an existing download
    if start_byte > 0 && !force_truncate {
        let mut opts = OpenOptions::new();
        opts.append(true);

        apply_safe_flags(&mut opts);
        return opts.open(path);
    }

    // Case 2: Starting fresh (Create new or Truncate)
    // We try 'create_new' (O_EXCL) first for atomic security.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);

    apply_safe_flags(&mut opts);
    #[cfg(unix)]
    apply_file_mode(&mut opts, _args);

    match opts.open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // File exists, but we aren't resuming (force_truncate is true, or start_byte is 0).
            // We must truncate it.
            let mut opts = OpenOptions::new();
            opts.write(true).truncate(true).create(true);

            apply_safe_flags(&mut opts);
            #[cfg(unix)]
            apply_file_mode(&mut opts, _args);
            opts.open(path)
        }
        Err(e) => Err(e),
    }
}

async fn download_to_temp(
    response: Response,
    output_path: &Path,
    args: &Args,
    start_byte: u64,
    remaining_bytes: Option<u64>,
    force_truncate: bool,
    temp_path: PathBuf,
) -> Result<PathBuf> {
    // Store temp path for potential cleanup on signal
    {
        let mut guard = CURRENT_TEMP_PATH.lock().unwrap();
        *guard = Some(temp_path.clone());
    }

    // Log temporary filename
    if !args.quiet {
        if temp_path.exists() && start_byte > 0 {
            eprintln!("Resuming with temporary file: {}", temp_path.display());
        } else {
            eprintln!("Using temporary file: {}", temp_path.display());
        }
    }

    // Determine actual start byte from temp file
    let actual_start_byte = if force_truncate {
        0
    } else if temp_path.exists() && start_byte > 0 {
        start_byte
    } else {
        0
    };

    // Open temp file (create or append)
    let std_file = open_temp_file_safely(&temp_path, args, actual_start_byte, force_truncate)
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
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => {}
        Err(e) => return Err(e.into()),
    };
    drop(async_file); // Close file handle before rename

    let move_result = perform_atomic_move(&temp_path, output_path, args);
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
) -> Result<PathBuf> {
    let (std_file, actual_path) =
        match open_file_safely(output_path, args, start_byte, force_truncate) {
            Ok(f) => (f, output_path.to_path_buf()),
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
                    (open_file_safely(&truncated, args, start_byte, force_truncate)?, truncated)
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
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => {}
        Err(e) => return Err(e.into()),
    };

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

    // Block specific socket families
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

#[cfg(any(target_os = "android", not(target_os = "linux")))]
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

    tokio::select! {
        result = run_with_args(args) => {
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
    }
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
