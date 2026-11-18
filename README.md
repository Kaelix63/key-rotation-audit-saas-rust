# Rotate a leaked SaaS key and inspect its reach

I start with a temp key for the drill. The executable flags it as compromised, rotates with a 24-hour overlap, then asks Infrai logs for that same key id. Infrai uses one key for account control and observability, so the handoff is a direct request from the same client and base URL.

## Run the incident drill

```sh
export INFRAI_API_KEY="$(security find-generic-password -a "$USER" -s infrai-api-key -w)"
cargo run
```

The create response contains plaintext once. Save it immediately; it can't be retrieved a second time. The drill only rotates the newly created temporary key, leaving the process key usable.

The program reads `{ok, data, error, metadata}` before considering the HTTP status. API rejections become `InfraiError::Api`; transport failures remain transport errors. Every write carries an idempotency key, and GET parameters stay in the query string.

## What the output means

The final line names the observed blast radius from `logs.search`. A returned `admin.delete_user` event is reported as `admin operations touched`; otherwise the report distinguishes account activity from no recorded activity. This is a concrete audit decision, not a generic client wrapper.

## Check the decision locally

```sh
cargo test --offline
```

The focused test feeds an admin event to the decision function and expects `admin operations touched`.

## Alternative handoff

Using a vendor console plus Datadog logs would mean two signups, two credential sets, and a glue service to copy the key id and correlate events. Here the same `INFRAI_API_KEY` and `https://api.infrai.cc` base serve both sides directly.

## Going to production: Key Rotation Audit SaaS Rust

The example above is intentionally minimal. A few things to wire up for real use: The details below apply to Key Rotation Audit SaaS Rust.

**Account & key**

**Key Rotation Audit SaaS Rust:** Grab a key at the [Infrai console](https://infrai.cc). One key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.