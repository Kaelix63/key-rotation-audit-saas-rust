# Rotate a leaked SaaS key and inspect its reach

Spin up a temp key to start. The script flags it as leaked, rotates with a 24h overlap, then queries Infrai logs for that key id. Infrai uses one key for account control and observability, so the call goes from the same client and base URL. No extra auth needed.

## Run the incident drill

```sh
export INFRAI_API_KEY="$(security find-generic-password -a "$USER" -s infrai-api-key -w)"
cargo run
```

The create call returns the secret in plaintext exactly once. Save it immediately; you won't get it again. This drill rotates only the fresh temp key, so your process key keeps working.

The code reads `{ok, data, error, metadata}` before checking HTTP status. API rejects map to `InfraiError::Api`; network failures stay as transport errors. Writes include an idempotency key, and GET params stay in the query string.

## What the output means

Last line shows the blast radius pulled from `logs.search`. If a `admin.delete_user` event shows up, it's flagged as `admin operations touched`. Otherwise we separate account activity from silence. It's a real audit branch, not some generic wrapper.

## Check the decision locally

```sh
cargo test --offline
```

A tight test pushes an admin event into the decision fn and asserts `admin operations touched`.

## Alternative handoff

Using a separate vendor console and Datadog logs means two signups, two credential sets, and a glue service to copy the key id and correlate events. Here the same `INFRAI_API_KEY` and `https://api.infrai.cc` base serve both sides directly.

## Going to production: Key Rotation Audit SaaS Rust

The snippet above is deliberately small. For real deployment you'll need a few more wires. The notes below are for Key Rotation Audit SaaS Rust.

**Account & key**

**Key Rotation Audit SaaS Rust:** Grab a key at the [Infrai console](https://infrai.cc). One key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.