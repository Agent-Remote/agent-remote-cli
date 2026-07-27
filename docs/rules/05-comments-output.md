# 05 Comments And Output

Public modules and non-obvious public APIs should use concise Rust documentation comments. Inline comments explain security decisions, compatibility workarounds, or non-obvious failure handling; they must not restate the code.

Terminal output is a compatibility surface:

- Use `terminal.rs` primitives for color and consistent status presentation.
- Keep errors actionable without exposing tokens, private keys, credential-store values, or server internals.
- Preserve `--color`, `NO_COLOR`, non-interactive behavior, and stable exit status.
- Do not introduce undocumented machine-readable output. Add a deliberate format and contract tests when scripting support is required.

Update both English and Simplified Chinese README files when user workflows change materially.
