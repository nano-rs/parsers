# GitHub webhook samples

One record per file, as the NAN-5898 dogfood edge relay forwards it: the
envelope `{github_event, github_delivery, github_hook_id,
github_hook_installation_target_type, payload}` (GitHub sends the event type
and delivery GUID as headers, so the relay carries them). Payload shapes follow
https://docs.github.com/en/webhooks/webhook-events-and-payloads; ids, logins
and keys are synthetic (the deploy key body is truncated).

| File | Branch |
|------|--------|
| `organization_member_added.json` | organization.member_added: Group Management, Add User |
| `team_added_to_repository.json` | team.added_to_repository: Group Management, Assign Privileges |
| `deploy_key_created.json` | deploy_key.created: API Activity, key + repository resources |
| `branch_protection_rule_deleted.json` | branch_protection_rule.deleted: API Activity, Delete, no clock (time received) |
| `repository_publicized.json` | repository.publicized: API Activity, Update |
| `push_forced_main.json` | push (no action), forced: API Activity, time from repository.pushed_at (epoch s) |
| `secret_scanning_alert_created.json` | secret_scanning_alert.created: Detection Finding, active secret (Critical), push protection bypass actor as evidence |
| `code_scanning_alert_created.json` | code_scanning_alert.created: Detection Finding, CodeQL rule as analytic |
| `workflow_run_completed_failure.json` | workflow_run.completed: Application Lifecycle, Stop, Failure |
| `malformed.json` | truncated JSON: Base Event fallback |
