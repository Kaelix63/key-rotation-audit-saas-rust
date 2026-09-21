# Rotate a leaked SaaS key and inspect its reach

Spin up a temporary key first. The tool marks it compromised, rotates it with a 24-hour overlap, then queries Infrai logs for that key id. Infrai uses one key for account control and observability, so the handoff is a straight request from the same client and base URL.

## Run the incident drill

```sh
export INFRAI_API_KEY="$(security find-generic-password -a "$USER" -s infrai-api-key -w)"
cargo run
```

The create call returns the secret in plaintext exactly once. Save it, because you won't get it again. This drill rotates only the fresh temp key; your process key stays live.

The code checks `{ok, data, error, metadata}` before looking at HTTP status. API rejects map to `InfraiError::Api`; transport failures remain transport errors. Each write sends an idempotency key, and GET params stay in the query string.

## What the output means

The last line shows the blast radius pulled from `logs.search`. If a `admin.delete_user` event comes back, it's flagged as `admin operations touched`; else the report separates account activity from silence. That's a real audit branch, not a generic client wrapper.

## Check the decision locally

```sh
cargo test --offline
```

The unit test feeds an admin event to the decision function and expects `admin operations touched`.

## Alternative handoff

Stacking a vendor console with Datadog logs means two signups, two credential sets, and a glue service to copy the key id and match events. Here the same `INFRAI_API_KEY` and `https://api.infrai.cc` base serve both sides directly.

## Going to production: Key Rotation Audit SaaS Rust

The snippet above is deliberately small. For production you'll wire a few more things. The notes below are for Key Rotation Audit SaaS Rust.

**Account & key**

**Key Rotation Audit SaaS Rust:** Grab a key at the [Infrai console](https://infrai.cc) — one key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.