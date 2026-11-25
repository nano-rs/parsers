# Stripe Event samples

Stripe Event objects exactly as a webhook endpoint receives them
(https://docs.stripe.com/api/events/object). Ids are redacted placeholders.

| File | Branch |
|------|--------|
| `customer_subscription_created.json` | API Activity, Create, API request (request.id set) |
| `customer_subscription_deleted_api.json` | API Activity, Delete |
| `checkout_session_completed.json` | API Activity, Other, automatic (actor Stripe) |
| `charge_failed.json` | API Activity, Failure with failure_code / failure_message |
| `radar_early_fraud_warning_created.json` | Detection Finding, fraud_type |
| `charge_dispute_created.json` | Detection Finding, dispute reason fraudulent |
| `malformed.json` | not JSON: Base Event fallback |
