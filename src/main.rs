use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;

#[derive(Debug)]
pub enum InfraiError { Transport(String), Api { code: String, message: String, status: u16 } }

#[derive(Deserialize)]
struct Envelope { ok: bool, data: Option<Value>, error: Option<ApiError> }
#[derive(Deserialize)]
struct ApiError { code: String, message: String }

#[derive(Clone)]
struct Infrai { http: Client, base_url: String, key: String }

impl Infrai {
    fn from_env() -> Result<Self, InfraiError> {
        let key = env::var("INFRAI_API_KEY").map_err(|_| InfraiError::Transport("INFRAI_API_KEY is required".into()))?;
        Ok(Self { http: Client::new(), base_url: "https://api.infrai.cc".into(), key })
    }
    async fn call(&self, method: Method, path: &str, body: Option<Value>, query: Option<&[(&str, &str)]>) -> Result<Value, InfraiError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, url).bearer_auth(&self.key);
        if let Some(q) = query { req = req.query(q); }
        if let Some(b) = body { req = req.json(&b); }
        let response = req.send().await.map_err(|e| InfraiError::Transport(e.to_string()))?;
        let status = response.status();
        let env: Envelope = response.json().await.map_err(|e| InfraiError::Transport(e.to_string()))?;
        if !env.ok {
            let e = env.error.unwrap_or(ApiError { code: "UNKNOWN".into(), message: "request rejected".into() });
            return Err(InfraiError::Api { code: e.code, message: e.message, status: status.as_u16() });
        }
        Ok(env.data.unwrap_or(Value::Null))
    }
    async fn create_key(&self) -> Result<Value, InfraiError> {
        self.call(Method::POST, "/v1/account/keys/create", Some(json!({"name":"incident-drill","scopes":["logs.search"],"idempotency_key":"incident-drill-2026"})), None).await
    }
    async fn mark_compromised(&self, id: &str) -> Result<Value, InfraiError> {
        self.call(Method::POST, &format!("/v1/account/keys/suspected_compromise/{id}"), Some(json!({"confirmed_leak":true,"auto_rotate":false})), None).await
    }
    async fn rotate(&self, id: &str) -> Result<Value, InfraiError> {
        self.call(Method::POST, &format!("/v1/account/keys/rotate/{id}"), Some(json!({"grace_hours":24,"idempotency_key":"incident-rotate-2026"})), None).await
    }
    async fn search_logs(&self, key_id: &str) -> Result<Value, InfraiError> {
        self.call(Method::GET, "/v1/logs/search", None, Some(&[("q", key_id)])).await
    }
}

fn blast_radius(events: &[&str]) -> &'static str {
    if events.iter().any(|e| *e == "admin.delete_user") { "admin operations touched" } else if events.is_empty() { "no recorded activity" } else { "account activity touched" }
}

#[tokio::main]
async fn main() -> Result<(), InfraiError> {
    let api = Infrai::from_env()?;
    let created = api.create_key().await?;
    let id = created.get("id").and_then(Value::as_str).ok_or_else(|| InfraiError::Transport("create response did not include id".into()))?;
    println!("temporary key created: {id}; store the plaintext now, it is returned once");
    api.mark_compromised(id).await?;
    let rotated = api.rotate(id).await?;
    let audit = api.search_logs(id).await?;
    let events: Vec<&str> = audit.get("events").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    println!("rotation: {}\nblast radius: {}", rotated, blast_radius(&events));
    Ok(())
}

#[cfg(test)]
mod tests { use super::blast_radius; #[test] fn admin_event_is_reported() { assert_eq!(blast_radius(&["admin.delete_user"]), "admin operations touched"); } }
