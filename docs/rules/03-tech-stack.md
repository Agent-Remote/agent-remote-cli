# 03 Tech Stack

- Stable Rust with the 2021 edition is authoritative.
- Cargo owns dependency resolution and `Cargo.lock`.
- Tokio owns asynchronous command execution.
- Reqwest with rustls owns HTTPS calls.
- Clap owns CLI parsing.
- Serde owns API and configuration serialization.
- Rusqlite owns local metadata storage.

Use the standard library before adding a dependency. Keep default features narrow, explain security-sensitive or platform-specific dependencies, and commit lockfile changes with manifest changes. CI must cover supported behavior on Linux and Windows; installer workflows cover the wider release matrix.

`vt100` reconstructs the bounded visible SSH screen for Claude login-link detection, including
cursor movement, ANSI styling and wrapped URLs. `terminal_size` supplies portable terminal geometry.
The observer does not retain scrollback, persist terminal content, or change SSH input handling.

`unicode-normalization` supplies NFC validation for the shared skill manifest contract; Rust's
standard library does not expose Unicode normalization. Matching Python and Go prevents the same
portable path from receiving incompatible content identities across the three components.

`cap-std` and `cap-fs-ext` bind local skill discovery and packaging to opened directories.
They provide cross-platform descriptor-relative access, no-follow opens and file identities; path
canonicalization alone cannot prevent a concurrently replaced parent or link from escaping the
selected source. `yaml-rust2` (encoding features disabled) reads bounded UTF-8 Claude frontmatter
without executing tags; aliases/anchors, excessive nesting and non-mapping metadata are rejected.
The Server independently validates metadata and remains authoritative.

State resolution uploads enable Reqwest's `stream` feature and Tokio filesystem support. The existing
Tokio utility dependency is declared directly with its `io` feature for `ReaderStream`; 64 KiB chunks
provide backpressure over private staged files without loading GiB-scale runtime data into memory.
