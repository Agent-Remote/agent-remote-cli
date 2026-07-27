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
cargo test
git diff --check
```

Use `cargo run -- --help` for local execution and `cargo fmt` to format changes. Install hooks with `scripts/install-githooks.sh`.

Release and installer commands are documented in `README.md`. Run packaging only when the task requires release artifacts; never commit generated archives or local state.
