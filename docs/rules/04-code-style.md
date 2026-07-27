# 04 Code Style

- `rustfmt` is authoritative.
- Clippy runs on all targets with warnings denied.
- Use explicit domain structs for API, configuration, and persistence boundaries.
- Return `anyhow::Result` at command orchestration boundaries and add context to operational failures.
- Avoid `unwrap`, `expect`, and panics in user-controlled command paths.
- Validate paths, IDs, URLs, file sizes, and external command results before use.
- Keep async work non-blocking; isolate unavoidable blocking operations.
- Use platform modules or `cfg` blocks narrowly and keep cross-platform behavior aligned.

Unit tests cover focused logic. `tests/cli_contract.rs` protects commands and user-facing contracts; installer smoke tests protect packaged behavior.
