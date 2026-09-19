# 09 Local State And Secrets

- SQLite stores local metadata only; schema changes must be backward compatible or include an explicit migration.
- Access tokens and private keys belong in the platform credential store when available.
- The user-token secret may contain a versioned CLI session with access/refresh credentials
  and deadlines. Update this as one secret, serialize login/refresh/logout with a local file
  lock, and never persist either credential in SQLite. Legacy raw tokens migrate only while
  the Server still accepts them; expired/revoked sessions require login. API mutations are
  not retried automatically after authentication failures.
- File fallback is permitted only with owner-only permissions and atomic writes.
- The community-local-trust macOS build stores the active Network Broker credential in the fixed
  `device-broker-credential.json` under `AGENT_REMOTE_HOME`. It must use an atomic owner-only write;
  the Broker independently rejects symlinks, other owners, links, unsafe modes, and oversized data.
- Tool account credentials, browser cookies, and remote login state must never enter local SQLite or configuration.
- `AGENT_REMOTE_HOME` overrides state paths for tests and custom installations; tests must never use a developer's real home.

WireGuard private keys are generated locally and only public keys are enrolled. SSH private keys remain local and agent forwarding requires explicit authorization. Logout and repair flows must distinguish local cleanup from remote revocation and report partial failures clearly.
