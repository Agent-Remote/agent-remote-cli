# Test layout

The test tree is separated from production sources:

- `unit/src/` mirrors the `src/` module tree. These are Rust unit modules loaded by the
  corresponding production module with `#[cfg(test)]` and `#[path]`, so private implementation
  details remain testable without becoming public API.
- The Rust files directly under `tests/` are contract and integration tests. They exercise public
  command behavior, external processes, installers, and cross-component boundaries.
- `support/` and `fixtures/` contain shared test helpers and bounded fixture data.

Keep new focused unit tests in `tests/unit/src/` beside the production module they cover. Keep
behavioral or process-boundary checks as top-level contract tests so their scope is visible in the
repository layout.
