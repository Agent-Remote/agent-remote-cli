# frozen_string_literal: true

require "yaml"

root = File.expand_path("..", __dir__)
workflow = YAML.safe_load(File.read(File.join(root, ".github/workflows/release.yml")), aliases: true)
text = File.read(File.join(root, ".github/workflows/release.yml"))

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
  "environment: production-device-release",
  "DEVICE_APP_TEAM_IDENTIFIER",
  "AGENT_REMOTE_DEVICE_TEAM_IDENTIFIER",
  "^[A-Z0-9]{10}$",
].each do |fragment|
  raise "release workflow is missing #{fragment}" unless text.include?(fragment)
end

raise "Unix release matrix is missing" unless workflow.dig("jobs", "release", "strategy", "matrix")
raise "Windows release matrix is missing" unless workflow.dig("jobs", "release-windows", "strategy", "matrix")
raise "release publish does not depend on audit" unless workflow.dig("jobs", "publish", "needs").include?("audit")
