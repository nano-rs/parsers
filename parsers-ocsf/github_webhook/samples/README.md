# GitHub webhook samples

Each delivery appears twice: `<name>.json` is GitHub's JSON body exactly as
signed, and `envelope_<name>.json` is the same body as a forwarder sends it,
`{github_event, github_delivery, github_hook_id,
github_hook_installation_target_type, payload}` with `github_event` from the
X-GitHub-Event header. Shapes follow
https://docs.github.com/en/webhooks/webhook-events-and-payloads; ids, logins and
keys are example values (the deploy key body is truncated).

| File | Branch |
|------|--------|
| `organization_member_added.json` | organization.member_added: Group Management, Add User |
| `organization_member_invited.json` | organization.member_invited: the invitee is the user |
| `team_added_to_repository.json` | team.added_to_repository: Group Management, Assign Privileges |
| `member_added_collaborator.json` | member.added: repository collaborator, permission as privilege |
| `org_block_blocked.json` | org_block.blocked: blocked account is the user |
| `deploy_key_created.json` | deploy_key.created: API Activity, key + repository resources |
| `branch_protection_rule_deleted.json` | branch_protection_rule.deleted: API Activity, Delete, no clock (time received) |
| `repository_ruleset_edited.json` | repository_ruleset.edited: ruleset resource |
| `repository_publicized.json` | repository.publicized: API Activity, Update |
| `push_forced_main.json` | push (no action), forced: time from repository.pushed_at (epoch s) |
| `secret_scanning_alert_created.json` | Detection Finding, active secret (Critical), push protection bypass actor as evidence |
| `code_scanning_alert_created.json` | Detection Finding, CodeQL rule as analytic |
| `dependabot_alert_created.json` | Detection Finding, advisory summary, GHSA, severity |
| `workflow_run_completed_failure.json` | Application Lifecycle, Stop, Failure |
| `workflow_job_completed_success.json` | Application Lifecycle, Stop, Success, completed_at clock |
| `issues_deleted_unidentified.json` | a bare `issues` body: unknown.deleted, Other (never "repository.deleted") |
| `create_branch_unidentified.json` | a bare `create` body: unknown, Other (never "public") |
| `malformed.json` | truncated JSON: Base Event fallback |
| `security_and_analysis_disabled.json` | security_and_analysis (no action, has changes): secret scanning turned off, never "public" |
