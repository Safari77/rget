#!/bin/sh
cargo deny check && cargo test --release --no-fail-fast && cargo release patch --execute
