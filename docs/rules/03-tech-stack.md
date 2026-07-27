# 03 Tech Stack

- Stable Rust with the 2021 edition is authoritative.
- Cargo owns dependency resolution and `Cargo.lock`.
- Tokio owns asynchronous command execution.
- Reqwest with rustls owns HTTPS calls.
- Clap owns CLI parsing.
- Serde owns API and configuration serialization.
- Rusqlite owns local metadata storage.

Use the standard library before adding a dependency. Keep default features narrow, explain security-sensitive or platform-specific dependencies, and commit lockfile changes with manifest changes. CI must cover supported behavior on Linux and Windows; installer workflows cover the wider release matrix.
