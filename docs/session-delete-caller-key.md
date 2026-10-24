# Fixed session collection deletion

`fclaude delete` and the desktop bridge use the version-1 caller-key deletion
contract. The client lists Claude sessions once, keeps only `failed`,
`interrupted` and `stopped` rows, sorts their canonical UUIDs, and sends that
complete set to:

```text
POST /api/v1/sessions/delete-requests
GET  /api/v1/sessions/delete-requests/{request_id}
```

The request contains `schema_version`, a locally generated UUID v4
`request_id`, `tool_type`, sorted unique `session_ids`, and a frozen
`selection` object:

```json
{
  "tool_type": "claude",
  "statuses": ["failed", "interrupted", "stopped"],
  "project_key": null
}
```

`selection_digest` is SHA-256 over canonical JSON of
`schema_version`, `tool_type`, sorted `session_ids` and `selection`.
`intent_fingerprint` hashes the same object with `reason` added. The Server
recomputes both values and compares the exact collection while holding its
lifecycle lock. It never expands an `--all` request with sessions created after
the list operation.

The receipt keeps the immutable IDs, selection and digests. It also returns one
`session_contexts` entry per ID containing account, workspace, project, node and
runtime backend identity, plus deletion task and per-session status fields. The
CLI rejects a receipt with missing, duplicate or out-of-set contexts.

The local SQLite journal stores only the home/server/user scope, caller key,
session IDs, selection summary, digests, phase and public task/status metadata.
It never stores credentials, command arguments, prompts or source contents. A
transport or server failure leaves phase `unknown`; `fclaude delete-status`
and `sessions.delete.request` perform a GET for that original key only. They do
not recompute the collection, guess a latest session, or submit a replacement.

Deletion remains subject to Server lifecycle and Skill-retention checks. A
collection mismatch or unresolved retention requirement is a definite rejection;
an uncertain transport result remains recoverable with the original key.
