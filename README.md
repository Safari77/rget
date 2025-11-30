# **rget - Secure File Downloader**

**rget** is a modern, secure-by-default command-line file downloader written in Rust. Designed as a safer alternative to `wget`, it prioritizes security features like DNS rebinding protection, SSRF prevention, and strict TLS enforcement, while maintaining high performance via the Tokio async runtime.

## **Key Features**

### **🔒 Security First**

* **HTTPS Enforcement:** Rejects insecure HTTP connections by default (can be overridden).
* **DNS Rebinding Protection:** Performs manual DNS resolution and overrides the connection address to prevent Time-of-Check to Time-of-Use (TOCTOU) attacks.
* **SSRF Protection:** Optional blocking of private/local IP ranges (localhost, 10.x, 192.168.x, etc.) via `--no-private-ips`.
* **Path Sanitization:** Prevents path traversal attacks and sanitizes filenames (handling Windows reserved names like `CON`, `PRN`).

### **Robust File Handling**

* **Atomic Writes:** Implementation of `--temp` writes data to a temporary file first and atomically renames it upon completion, preventing corrupted partial files.
* **Smart Filenames:** Derives filenames from the URL or `Content-Disposition` headers (with RFC 5987 charset support).
* **Resumable Downloads:** Supports `Range` headers to resume interrupted downloads (`-c`).
* **Filename Truncation:** Automatically truncates filenames that exceed the filesystem's limit.

### **Networking & UX**

* **Modern Stack:** Built on `reqwest` (HTTP), `rustls` (TLS), and `tokio`.
* **IP Enforcement:** Force IPv4 (`-4`) or IPv6 (`-6`) connections.
* **Progress Bar:** Beautiful, informative progress indicators via `indicatif`.

### **Setup**
mkdir -p ~/.config/rget && uuidgen > ~/.config/rget/resumekey.conf

### **Notes**

Tests for content-disposition:
http://test.greenbytes.de/tech/tc2231/

