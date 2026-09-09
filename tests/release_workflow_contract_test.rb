# frozen_string_literal: true

require "yaml"

root = File.expand_path("..", __dir__)
workflow = YAML.safe_load(File.read(File.join(root, ".github/workflows/release.yml")), aliases: true)
text = File.read(File.join(root, ".github/workflows/release.yml"))
ci_text = File.read(File.join(root, ".github/workflows/ci.yml"))
install_text = File.read(File.join(root, ".github/workflows/install-smoke.yml"))
static_checks = File.read(File.join(root, "scripts/run-static-checks.sh"))
managed_tools = File.read(File.join(root, "scripts/build-managed-tools.sh"))
windows_packager = File.read(File.join(root, "scripts/package-release.ps1"))
unix_packager = File.read(File.join(root, "scripts/package-release.sh"))

[
  "refs/tags/v${version}",
  "sha256",
  "anchore/sbom-action@",
  "cosign verify-blob",
  "actions/attest-build-provenance@",
  "gh attestation verify",
  "cargo-audit@0.22.2",
  "cargo-audit.json.sha256",
  "cargo-audit.json.sigstore.json",
  "environment: production-community-release",
  "COMMUNITY_SIGNER_CERTIFICATE_SHA1",
  "AGENT_REMOTE_DEVICE_SIGNER_CERTIFICATE_SHA1",
  "AGENT_REMOTE_DEVICE_CREDENTIAL_MODE",
  "community-file",
  "^[A-F0-9]{40}$",
].each do |fragment|
  raise "release workflow is missing #{fragment}" unless text.include?(fragment)
end

raise "Unix release matrix is missing" unless workflow.dig("jobs", "release", "strategy", "matrix")
raise "Windows release matrix is missing" unless workflow.dig("jobs", "release-windows", "strategy", "matrix")
windows_matrix = workflow.dig("jobs", "release-windows", "strategy", "matrix", "include")
windows_arm64 = windows_matrix.find { |entry| entry["target"] == "aarch64-pc-windows-msvc" }
raise "Windows ARM64 release target is missing" unless windows_arm64
raise "Windows ARM64 must use the cosign-compatible runner" unless windows_arm64["os"] == "windows-latest"
raise "release publish does not depend on audit" unless workflow.dig("jobs", "publish", "needs").include?("audit")

[text, ci_text, install_text].each do |workflow_text|
  raise "workflow does not control duplicate runs" unless workflow_text.include?("concurrency:")
  raise "workflow jobs do not have timeouts" unless workflow_text.include?("timeout-minutes:")
end
raise "CI does not classify changed paths" unless ci_text.include?("dorny/paths-filter@v4.0.3")
raise "CI workflow changes can bypass release contract tests" unless ci_text.include?(".github/workflows/**")
raise "CI does not cache Rust builds" unless ci_text.include?("Swatinem/rust-cache@v2.9.2")
raise "CI coverage upload must not depend on Codecov availability" unless ci_text.include?("fail_ci_if_error: false")
raise "Ubuntu CI does not use the non-test quality gate" unless ci_text.include?("scripts/run-static-checks.sh")
raise "static quality checks do not enforce Clippy" unless static_checks.include?("cargo clippy --all-targets -- -D warnings")
raise "install smoke does not cache managed tools" unless install_text.include?("managed-tools-v1-")
raise "managed tool builds do not use runner CPU capacity" if managed_tools.include?("make -j2")
raise "managed tool binary cache is missing" unless managed_tools.include?('cache_root="$MANAGED_TOOLS_CACHE_DIR/$TARGET/$cache_variant"')
raise "managed tool source uses the retired WireGuard snapshot endpoint" if managed_tools.include?("git.zx2c4.com/wireguard-tools/snapshot")
wireguard_tools_url = 'https://github.com/WireGuard/wireguard-tools/archive/refs/tags/v${WIREGUARD_TOOLS_VERSION}.tar.gz'
raise "managed tool source does not use the official WireGuard tag archive" unless managed_tools.include?(wireguard_tools_url)
raise "Windows downloads do not retry" unless windows_packager.include?("function Invoke-Download")
raise "managed tool cache behavior is not tested" unless static_checks.include?("tests/managed_tools_cache_test.sh")
[
  "CARGO_TARGET_DIR",
  "REQUIRE_DEVICE_SIGNING_IDENTITY",
  "AGENT_REMOTE_DEVICE_SIGNER_CERTIFICATE_SHA1",
  "agent-remote $VERSION",
  "strings",
].each do |fragment|
  raise "Unix release packager is missing #{fragment}" unless unix_packager.include?(fragment)
end
raise "release workflow must use an isolated Cargo target directory" unless text.include?("CARGO_TARGET_DIR:")
raise "release workflow must require a pinned macOS identity" unless text.include?("REQUIRE_DEVICE_SIGNING_IDENTITY")
