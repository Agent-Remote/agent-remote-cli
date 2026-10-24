# Administrator runtime recovery (desktop protocol 1)

The six `accounts.runtime_recovery.*` operations share the human CLI's Rust service.
Human authentication preparation retains its existing migration/refresh behavior, then calls the
same strict service. Machine operations never run that preparation. They use the additive [Server contract](../../agent-remote-server/docs/runtime-recovery-requests.md).
Legacy Server routes and Node execution are unchanged. Inspection is observation, not eligibility
or permission to execute. No shared service or machine operation refreshes, migrates or publishes user credentials.
Reviewed desktop and human recovery require these additive Server endpoints. An older Server's
missing authority/inspection endpoint stops preparation; clients never silently downgrade to a
legacy mutation route without the reviewed original binding.

## Identity and inspection

`UserContext` is `{home,server_url,actor_user_id}`. Home is the explicit absolute CLI home,
Server URL is its configured canonical URL, and actor is a canonical nonzero UUID verified using
the explicit user credential. An active device never supplies administrator authority.
Authority and every remote operation revalidate the current user. A stored session access token
can be used after its refresh schedule if its access and session deadlines have not expired.
Expired credentials require login; reads never create directories, lock files or SQLite rows.

`Original` has exactly `task_id,task_record_id,user_id,tool_account_id,node_id,tool_type,
source_runtime_backend,target_runtime_backend`, matching the Server projection. `user_id` is the
account owner, **not** the administrator. All UUIDs are canonical nonzero lowercase UUIDs;
the migration logical task ID must match its account. Tool is `claude`, backends are
`native|docker_sandbox` and must differ. `Action` is explicitly one of
`verify_target|verify_source|repair_source`.

| Method suffix | Parameters | Result |
| --- | --- | --- |
| `authority` | `expected_home,expected_server_url` | `{context,admin}` |
| `inspect` | `expected_context,account_id,original_task_id,action` | `{context,account_id,original,action,original_status,account_status,digest}` |
| `apply` | `confirmed,expected_context,account_id,original,action,expected_digest,request_id` | Receipt below plus `operation_id` |
| `status` | `expected_context,account_id,request_id,expected_digest,expected_binding` | Receipt below |
| `pending` | `expected_home` | `{home,items:[records below]}` |
| `forget` | Status parameters plus `confirmed` | `{operation_id,context,account_id,request_id,digest,forgotten:true}` |

The digest is `sha256:` plus lowercase hex over compact serialized schema-1 context, account,
complete original projection and action. It excludes request key and observed statuses.
Status strings are bounded exact Server enums; they are neither an eligibility claim nor durable
execution state. Apply recomputes the local digest, reserves the caller key, and sends one POST.
Server compares the full original projection inside the existing writer transaction before new
acceptance. No opaque server fingerprint or second execution protocol is introduced.

## Exact receipts and nullable fields

Receipt is `{context,account_id,request_id,digest,recovery:{binding,status},
target_completion_confirmed,source_restoration_confirmed}`. Both confirmation fields are booleans.
They are true only for succeeded recovery of the matching target/source action; acceptance alone
does not confirm recovery. `binding` preserves the existing v1/v2/v3 API fields and omission of
`binding.action` in v1. Neither raw task output nor arbitrary Node error text is exposed.

Status `expected_digest` and `expected_binding` are **required nullable** fields. For a manually
entered old key with no registry record, digest is null; binding is initially null and may be the
complete prior observation on subsequent queries, which must match exactly. Result digest is null. This query
does not know the original submitting administrator, does not create local metadata, and never
becomes an apply plan. Server history is accessible to the currently authorized administrator.

For a retained record, digest must be non-null and exact. A known retained binding requires an
equal `expected_binding`; an unknown binding permits null or a complete prior observation. Every returned receipt is independently
validated against account/key, action and the complete retained original projection. Status never
updates the registry. A changed context or malformed/mismatched binding is an error, never a new
operation or an invitation to silently choose another key.

## Public caller-key registry

The CLI SQLite store is the only durable owner of desktop/human recovery keys. A record contains
exactly `{context,account_id,request_id,digest,original,action,binding,phase,rejection_code}`.
Binding is null until a validated acceptance receipt is saved. Phase is
`unknown|accepted|rejected`; it describes submission evidence, not remote task progress.
`rejection_code` is null except for a fixed code on a definitively rejected single submission.
The registry contains no credentials, source contents, host paths beyond context.home, or remote
result/error text. It is bounded to 256 records and 16 KiB per record. Database connections close
before HTTP awaits. Existing unresolved same-context/account intent blocks fresh submission;
the original caller-selected key is never silently replaced or automatically replayed.

Pre-submit failures never invent a retained key. Clients rediscover durable records using pending;
an operation ID, locally generated UUID, or generic timeout does not prove one was persisted.
After reservation, ambiguous transport, malformed success, 408/409/429 and 5xx retain unknown.
An exact structured review-changed 409 is a definite single-attempt rejection. Other explicit
4xx except 408/409/429 may be retained as rejected. A later response can never erase an earlier
unknown acceptance. Human legacy error rendering retains its existing stable envelope separately.

Forget requires non-null exact digest. A known binding must match the retained binding. For an
unknown binding, a freshly observed binding may be supplied as terminal evidence, but the local
CAS always compares the original stored record. Rejected records can be explicitly removed offline;
they require expected_binding=null. Otherwise, fresh user-admin authorization and exact-key GET
must prove a matching terminal task before compare-and-delete. Unknown/404/running never permits
deletion. Forget deletes local public metadata only and cannot undo a remote recovery.

## Capabilities and fixed errors

Authority/inspect/status advertise `credential:user,effect:read`; apply advertises
`credential:user,effect:write,confirmation:exact_request`; pending is `none/read`; forget is
`none/write/exact_request` because definitive rejection cleanup is offline. Its other branch still
requires current user-administrator authorization. Pending always returns the queried `home`, even
for an empty list, and every record's context.home must match it.

Fixed recovery codes are `runtime_recovery_response_invalid`, `runtime_recovery_status_unknown`,
`runtime_recovery_outcome_unknown`, `runtime_recovery_rejected`, `runtime_recovery_review_changed`,
`runtime_recovery_registry_unavailable`, `runtime_recovery_pending`, `runtime_recovery_context_changed`,
`runtime_recovery_receipt_changed`, and `runtime_recovery_not_terminal`. Common codes are
`invalid_params`, `confirmation_required`, `configuration_changed`, `configuration_unavailable`,
`credential_unavailable`, `authentication_required`, `permission_denied`, `canceled`, and `timeout`.
Only `runtime_recovery_rejected|runtime_recovery_review_changed` may appear as rejection_code.
No error payload includes raw Server/Node messages or credential material.

The human `recovery-status --forget` flag requires separate interactive confirmation or `--yes`;
`--yes` requires `--forget`. Default status output and v1/v2/v3 error schemas remain compatible.
Human authentication may refresh before the shared service; a rejected local receipt can still be
forgotten offline. An existing key in `recover-runtime` is queried only after exact original/action
comparison; it is never automatically posted again.
