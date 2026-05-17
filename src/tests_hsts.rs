#![cfg(test)]

use super::*;

#[cfg(test)]
mod hsts_tests {
    //! Tests for the HSTS handling functions in this file (check_hsts,
    //! update_hsts) and the constants/types they rely on (HstsEntry,
    //! HstsMap, MAX_HSTS_ENTRIES). These exercise the RFC 6797 rules that
    //! the implementation enforces.

    use super::*;

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    fn sts(value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(value));
        h
    }

    /// check_hsts: exact match, subdomain match via includeSubDomains,
    /// trailing-dot normalization, and explicit non-matches (sibling /
    /// substring spoof / subdomain of an exact-only entry).
    #[test]
    fn check_hsts_exact_and_subdomain_matching() {
        let mut map = HstsMap::new();
        let later = now() + 3600;

        // Exact-only entry (no includeSubDomains).
        map.insert("exact.example".into(), HstsEntry { expiry: later, include_subdomains: false });
        // Apex with includeSubDomains.
        map.insert("example.com".into(), HstsEntry { expiry: later, include_subdomains: true });

        // Matches.
        assert!(check_hsts(&map, "exact.example"));
        assert!(check_hsts(&map, "example.com"));
        assert!(check_hsts(&map, "foo.example.com"));
        assert!(check_hsts(&map, "a.b.example.com"));
        // Trailing dot is normalized.
        assert!(check_hsts(&map, "foo.example.com."));

        // Non-matches.
        // Exact-only entry does NOT cover its subdomains.
        assert!(!check_hsts(&map, "sub.exact.example"));
        // Substring spoof: label-by-label matching must reject this.
        assert!(!check_hsts(&map, "evil-example.com"));
        // Unrelated host.
        assert!(!check_hsts(&map, "other.org"));
        // IP literals are never Known HSTS Hosts (RFC §8.1.1 / §8.3).
        assert!(!check_hsts(&map, "203.0.113.5"));
        assert!(!check_hsts(&map, "[2001:db8::1]"));
    }

    /// update_hsts: IP-literal authorities MUST NOT be noted as HSTS hosts
    /// (RFC §8.1.1), neither for IPv4 nor for bracketed IPv6.
    #[test]
    fn update_hsts_skips_ip_literal_hosts() {
        let h = sts("max-age=31536000; includeSubDomains");

        let mut map = HstsMap::new();
        update_hsts(&mut map, &Url::parse("https://203.0.113.5/").unwrap(), &h, false);
        update_hsts(&mut map, &Url::parse("https://[2001:db8::1]/").unwrap(), &h, false);

        assert!(map.is_empty(), "IP-literal hosts must not be noted: {:?}", map);
    }

    /// update_hsts: max-age=0 removes a prior entry, including one that had
    /// includeSubDomains asserted (RFC §8.1, §6.1.1 NOTE).
    #[test]
    fn update_hsts_max_age_zero_removes_entry() {
        let mut map = HstsMap::new();
        map.insert(
            "example.com".into(),
            HstsEntry { expiry: now() + 3600, include_subdomains: true },
        );
        // Sanity: subdomain currently matches via includeSubDomains.
        assert!(check_hsts(&map, "sub.example.com"));

        let url = Url::parse("https://example.com/").unwrap();
        update_hsts(&mut map, &url, &sts("max-age=0"), false);

        // Entry is gone; subdomain no longer matches.
        assert!(!map.contains_key("example.com"));
        assert!(!check_hsts(&map, "example.com"));
        assert!(!check_hsts(&map, "sub.example.com"));
    }

    /// update_hsts parses quoted max-age values (RFC §6.1 / §6.2) and ignores
    /// the entire header on duplicate directives, malformed values, or a
    /// missing required max-age (RFC §6.1 rules 2 and 4).
    #[test]
    fn update_hsts_accepts_quoted_rejects_malformed() {
        let url = Url::parse("https://example.com/").unwrap();

        // Quoted max-age is valid.
        let mut map = HstsMap::new();
        update_hsts(&mut map, &url, &sts("max-age=\"600\"; includeSubDomains"), false);
        let e = map.get("example.com").expect("entry should be present");
        assert!(e.include_subdomains);
        assert!(e.expiry > now());

        // Set up a stable prior entry to confirm "ignored" really means no-op.
        let mut map = HstsMap::new();
        let prior = HstsEntry { expiry: now() + 99_999, include_subdomains: false };
        map.insert("example.com".into(), prior.clone());
        let before = prior.expiry;

        // Duplicate max-age -> whole header ignored, prior unchanged.
        update_hsts(&mut map, &url, &sts("max-age=10; max-age=20"), false);
        assert_eq!(map.get("example.com").unwrap().expiry, before);

        // Duplicate includeSubDomains -> whole header ignored.
        update_hsts(
            &mut map,
            &url,
            &sts("max-age=10; includeSubDomains; includeSubDomains"),
            false,
        );
        assert_eq!(map.get("example.com").unwrap().expiry, before);

        // Non-numeric max-age value -> whole header ignored.
        update_hsts(&mut map, &url, &sts("max-age=notanumber"), false);
        assert_eq!(map.get("example.com").unwrap().expiry, before);

        // max-age missing (it is REQUIRED, RFC §6.1.1) -> header ignored.
        update_hsts(&mut map, &url, &sts("includeSubDomains"), false);
        assert_eq!(map.get("example.com").unwrap().expiry, before);
    }

    /// When the cache is over MAX_HSTS_ENTRIES, the entries with the soonest
    /// expiry are evicted -- but the entry just stored survives even when its
    /// own expiry is the smallest of the lot (otherwise a server with a small
    /// max-age would be silently dropped on every visit).
    #[test]
    fn update_hsts_cap_evicts_soonest_but_keeps_fresh_insert() {
        let mut map = HstsMap::new();
        // Fill the cache with entries that all expire far in the future.
        let far = now() + 1_000_000;
        for i in 0..MAX_HSTS_ENTRIES {
            map.insert(
                format!("h{}.example", i),
                HstsEntry { expiry: far, include_subdomains: false },
            );
        }
        assert_eq!(map.len(), MAX_HSTS_ENTRIES);

        // Insert a fresh entry whose expiry will be tiny relative to the rest.
        let url = Url::parse("https://fresh.example/").unwrap();
        update_hsts(&mut map, &url, &sts("max-age=60"), false);

        // Cap is enforced.
        assert_eq!(map.len(), MAX_HSTS_ENTRIES);
        // The freshly-inserted entry survives even though its expiry is the
        // smallest in the map.
        assert!(map.contains_key("fresh.example"));
        // Exactly one of the pre-existing entries was evicted.
        let kept_old =
            (0..MAX_HSTS_ENTRIES).filter(|i| map.contains_key(&format!("h{}.example", i))).count();
        assert_eq!(kept_old, MAX_HSTS_ENTRIES - 1);
    }
}
