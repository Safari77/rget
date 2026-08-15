#!/bin/sh
cargo audit --ignore RUSTSEC-2026-0173 && cargo test --release --no-fail-fast && cargo release patch --no-publish --execute
