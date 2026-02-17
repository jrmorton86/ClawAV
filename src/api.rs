//! HTTP REST API server for external integrations.
//!
//! Exposes endpoints on a configurable bind address (default port 18791):
//! - `GET /api/status` — system status, uptime, module state
//! - `GET /api/alerts` — last 100 alerts as JSON
//! - `GET /api/health` — health check with last alert age
//! - `GET /api/security` — alert counts by severity and source
//!
//! Uses a [`SharedAlertStore`] (`Arc<Mutex<AlertRingBuffer>>`) shared with the aggregator.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::alerts::{Alert, Severity};

/// Thread-safe ring buffer of alerts for the API.
///
/// Backed by a `VecDeque` with a fixed maximum capacity. When full, the oldest
/// alert is dropped. Provides severity/source counts for the security posture endpoint.
pub struct AlertRingBuffer {
    buf: VecDeque<Alert>,
    max: usize,
}

impl AlertRingBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(max),
            max,
        }
    }

    pub fn push(&mut self, alert: Alert) {
        if self.buf.len() >= self.max {
            self.buf.pop_front();
        }
        self.buf.push_back(alert);
    }

    pub fn last_n(&self, n: usize) -> Vec<&Alert> {
        self.buf.iter().rev().take(n).collect::<Vec<_>>().into_iter().rev().collect()
    }

    pub fn count_by_source(&self) -> std::collections::HashMap<String, usize> {
        let mut m = std::collections::HashMap::new();
        for a in &self.buf {
            *m.entry(a.source.clone()).or_insert(0) += 1;
        }
        m
    }

    pub fn count_by_severity(&self) -> (usize, usize, usize) {
        let (mut info, mut warn, mut crit) = (0, 0, 0);
        for a in &self.buf {
            match a.severity {
                Severity::Info => info += 1,
                Severity::Warning => warn += 1,
                Severity::Critical => crit += 1,
            }
        }
        (info, warn, crit)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

/// Thread-safe shared alert store, used by the aggregator and API server.
pub type SharedAlertStore = Arc<Mutex<AlertRingBuffer>>;

/// Create a new shared alert store with the given maximum capacity.
pub fn new_shared_store(max: usize) -> SharedAlertStore {
    Arc::new(Mutex::new(AlertRingBuffer::new(max)))
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    uptime_seconds: u64,
    version: &'static str,
    modules: Modules,
}

#[derive(Serialize)]
struct Modules {
    auditd: bool,
    network: bool,
    behavior: bool,
    firewall: bool,
}

#[derive(Serialize)]
struct AlertJson {
    ts: String,
    severity: String,
    source: String,
    message: String,
}

#[derive(Serialize)]
struct SecurityResponse {
    uptime_seconds: u64,
    total_alerts: usize,
    alerts_by_severity: SeverityCounts,
    alerts_by_source: std::collections::HashMap<String, usize>,
}

#[derive(Serialize)]
struct SeverityCounts {
    info: usize,
    warning: usize,
    critical: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(body))
        .unwrap()
}

async fn handle(
    req: Request<Body>,
    store: SharedAlertStore,
    start_time: Instant,
    auth_token: Arc<String>,
) -> Result<Response<Body>, Infallible> {
    // Check bearer token auth if configured
    if !auth_token.is_empty() {
        let authorized = req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == auth_token.as_str())
            .unwrap_or(false);

        if !authorized && req.uri().path() != "/api/health" {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"error":"unauthorized"}"#))
                .unwrap());
        }
    }

    let resp = match req.uri().path() {
        "/" => {
            let html = r#"<!DOCTYPE html><html><head><title>ClawTower</title></head><body>
<h1>&#128737; ClawTower is running</h1>
<ul>
<li><a href="/api/status">/api/status</a> — System status</li>
<li><a href="/api/alerts">/api/alerts</a> — Recent alerts</li>
<li><a href="/api/security">/api/security</a> — Security posture</li>
</ul></body></html>"#;
            Response::builder()
                .header("Content-Type", "text/html")
                .body(Body::from(html))
                .unwrap()
        }
        "/api/status" => {
            let resp = StatusResponse {
                status: "running",
                uptime_seconds: start_time.elapsed().as_secs(),
                version: "0.3.0",
                modules: Modules {
                    auditd: true,
                    network: true,
                    behavior: true,
                    firewall: true,
                },
            };
            json_response(StatusCode::OK, serde_json::to_string(&resp).unwrap())
        }
        "/api/alerts" => {
            let store = store.lock().await;
            let alerts: Vec<AlertJson> = store
                .last_n(100)
                .into_iter()
                .map(|a| AlertJson {
                    ts: a.timestamp.to_rfc3339(),
                    severity: a.severity.to_string(),
                    source: a.source.clone(),
                    message: a.message.clone(),
                })
                .collect();
            json_response(StatusCode::OK, serde_json::to_string(&alerts).unwrap())
        }
        "/api/health" => {
            let store = store.lock().await;
            let last_alert_age = store.last_n(1).first().map(|a| {
                chrono::Utc::now().signed_duration_since(a.timestamp).num_seconds() as u64
            });
            let resp = serde_json::json!({
                "healthy": true,
                "uptime_seconds": start_time.elapsed().as_secs(),
                "version": env!("CARGO_PKG_VERSION"),
                "last_alert_age_seconds": last_alert_age,
            });
            json_response(StatusCode::OK, serde_json::to_string(&resp).unwrap())
        }
        "/api/security" => {
            let store = store.lock().await;
            let (info, warn, crit) = store.count_by_severity();
            let resp = SecurityResponse {
                uptime_seconds: start_time.elapsed().as_secs(),
                total_alerts: store.len(),
                alerts_by_severity: SeverityCounts {
                    info,
                    warning: warn,
                    critical: crit,
                },
                alerts_by_source: store.count_by_source(),
            };
            json_response(StatusCode::OK, serde_json::to_string(&resp).unwrap())
        }
        _ => {
            let err = ErrorResponse {
                error: "not found".to_string(),
            };
            json_response(StatusCode::NOT_FOUND, serde_json::to_string(&err).unwrap())
        }
    };
    Ok(resp)
}

/// Start the HTTP API server on the given bind address and port.
///
/// Runs indefinitely, serving requests against the shared alert store.
pub async fn run_api_server(bind: &str, port: u16, store: SharedAlertStore, auth_token: String) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let start_time = Instant::now();
    let auth_token = Arc::new(auth_token);

    let make_svc = make_service_fn(move |_conn| {
        let store = store.clone();
        let auth_token = auth_token.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle(req, store.clone(), start_time, auth_token.clone())
            }))
        }
    });

    eprintln!("API server listening on {}", addr);
    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{Alert, Severity};

    #[test]
    fn test_ring_buffer_capacity() {
        let mut buf = AlertRingBuffer::new(1000);
        for i in 0..1001 {
            buf.push(Alert::new(Severity::Info, "test", &format!("msg {}", i)));
        }
        assert_eq!(buf.len(), 1000);
        // Oldest (msg 0) should be dropped, first should be msg 1
        let alerts = buf.last_n(1000);
        assert_eq!(alerts[0].message, "msg 1");
        assert_eq!(alerts[999].message, "msg 1000");
    }

    #[test]
    fn test_alert_json_serialization() {
        let alert = Alert::new(Severity::Critical, "auditd", "privilege escalation detected");
        let json_alert = AlertJson {
            ts: alert.timestamp.to_rfc3339(),
            severity: alert.severity.to_string(),
            source: alert.source.clone(),
            message: alert.message.clone(),
        };
        let json = serde_json::to_string(&json_alert).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["severity"], "CRIT");
        assert_eq!(parsed["source"], "auditd");
        assert_eq!(parsed["message"], "privilege escalation detected");
        assert!(parsed["ts"].as_str().is_some());
    }

    #[test]
    fn test_api_default_bind_localhost() {
        let config = crate::config::ApiConfig::default();
        assert_eq!(config.bind, "127.0.0.1", "API should default to localhost only");
        assert!(config.auth_token.is_empty(), "Auth token should default to empty");
    }

    #[test]
    fn test_count_by_severity() {
        let mut buf = AlertRingBuffer::new(100);
        buf.push(Alert::new(Severity::Info, "a", "x"));
        buf.push(Alert::new(Severity::Warning, "b", "y"));
        buf.push(Alert::new(Severity::Critical, "c", "z"));
        buf.push(Alert::new(Severity::Info, "d", "w"));
        let (info, warn, crit) = buf.count_by_severity();
        assert_eq!(info, 2);
        assert_eq!(warn, 1);
        assert_eq!(crit, 1);
    }

    // ═══════════════════════════════════════════════════════════════════
    // RED LOBSTER v4 REGRESSION — API Auth Bypass
    // ═══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_redlobster_no_bearer_gets_401() {
        let store = new_shared_store(100);
        let token = Arc::new("secret-token-123".to_string());
        let req = Request::builder()
            .uri("/api/status")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_redlobster_wrong_bearer_gets_401() {
        let store = new_shared_store(100);
        let token = Arc::new("secret-token-123".to_string());
        let req = Request::builder()
            .uri("/api/alerts")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_redlobster_correct_bearer_gets_200() {
        let store = new_shared_store(100);
        let token = Arc::new("secret-token-123".to_string());
        let req = Request::builder()
            .uri("/api/status")
            .header("Authorization", "Bearer secret-token-123")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_redlobster_health_bypasses_auth() {
        let store = new_shared_store(100);
        let token = Arc::new("secret-token-123".to_string());
        let req = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_redlobster_empty_token_no_auth_required() {
        let store = new_shared_store(100);
        let token = Arc::new(String::new());
        let req = Request::builder()
            .uri("/api/status")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Empty auth_token means auth disabled");
    }

    #[tokio::test]
    async fn test_redlobster_security_endpoint_requires_auth() {
        let store = new_shared_store(100);
        let token = Arc::new("mytoken".to_string());
        let req = Request::builder()
            .uri("/api/security")
            .body(Body::empty())
            .unwrap();
        let resp = handle(req, store, Instant::now(), token).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
