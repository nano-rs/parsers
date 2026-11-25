# GitHub webhook samples

One delivery per file: GitHub's JSON body exactly as signed (the event name is
not in the body; the parser reads it from the payload's keys).
`envelope_organization_member_added.json` is the same delivery in a relay
envelope `{github_event, github_delivery, ..., payload}`, which is also accepted.
Shapes follow https://docs.github.com/en/webhooks/webhook-events-and-payloads;
ids, logins and keys are example values (the deploy key body is truncated).

| File | Branch |
|------|--------|
| `organization_member_added.json` | organization.member_added: Group Management, Add User |
| `team_added_to_repository.json` | team.added_to_repository: Group Management, Assign Privileges |
| `deploy_key_created.json` | deploy_key.created: API Activity, key + repository resources |
| `branch_protection_rule_deleted.json` | branch_protection_rule.deleted: API Activity, Delete, no clock (time received) |
| `repository_publicized.json` | repository.publicized: API Activity, Update |
| `push_forced_main.json` | push (no action), forced: time from repository.pushed_at (epoch s) |
| `secret_scanning_alert_created.json` | secret_scanning_alert.created: Detection Finding, active secret (Critical), push protection bypass actor as evidence |
| `code_scanning_alert_created.json` | code_scanning_alert.created: Detection Finding, CodeQL rule as analytic |
| `workflow_run_completed_failure.json` | workflow_run.completed: Application Lifecycle, Stop, Failure |
| `envelope_organization_member_added.json` | relay envelope form |
| `malformed.json` | truncated JSON: Base Event fallback |
