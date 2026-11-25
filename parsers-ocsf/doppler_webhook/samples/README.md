# Doppler webhook samples

Doppler project webhook bodies as Doppler posts them (names of changed secrets
only, never values). Shape per https://docs.doppler.com/docs/webhooks; confirm
against the first real delivery.

| File | Branch |
|------|--------|
| `config_secrets_updated.json` | config.secrets.update: added + updated names |
| `config_secrets_updated_branch.json` | branch config, never fetched (null clocks) |
| `config_secrets_removed.json` | a removed secret name in a root, locked config |
| `json_not_doppler.json` | JSON that is not a Doppler webhook: Base Event fallback |
| `malformed.json` | truncated JSON: Base Event fallback |
