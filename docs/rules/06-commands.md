# 06 Commands

## Quality Gate

```sh
scripts/run-quality-checks.sh
```

Expanded commands:

```sh
bash -n scripts/*.sh tests/*.sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
scripts/run-tests.sh
git diff --check
```

Use `cargo run -- --help` for local execution and `cargo fmt` to format changes. Install hooks with `scripts/install-githooks.sh`.

Release and installer commands are documented in `README.md`. Run packaging only when the task requires release artifacts; never commit generated archives or local state.

The quality, coverage, and release-preparation gates use cargo-nextest 0.9.146 with eight
concurrent test processes across binaries. Doc tests still run through Cargo. Install the
same runner locally with `cargo install cargo-nextest --version 0.9.146 --locked`.
Fresh checkouts without nextest use the complete Cargo suite with four test threads per
binary. Test processes retain isolated temporary state and loopback ports; tests that
mutate process-global state keep their existing mutexes. Use
`cargo test -- --test-threads=1` when diagnosing scheduling issues.
