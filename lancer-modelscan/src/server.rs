//! Cross-tool local HTTP server (plan §"Cross-tool integration").
//!
//! Binds `127.0.0.1:<auto>`, writes the port to `%TEMP%/lancer-modelscan.port`
//! so the Lancer mothership can discover it, and exposes:
//!   * `GET  /v1/state`            — current jobs / counts
//!   * `GET  /v1/export?format=…`  — the current result set (json/html/sarif/console)
//!   * `POST /v1/import`           — accept a path from another Lancer tool

use ms_core::{ReportFormat, ScanResult};
use std::io::Read;
use std::sync::{Arc, Mutex};

/// State shared between the GUI and the HTTP server.
#[derive(Default)]
pub struct ServerShared {
    /// The most recent completed scan result (for export / state).
    pub last_result: Option<ScanResult>,
    /// Paths pushed in via `/v1/import`, polled by the GUI.
    pub imports: Vec<String>,
    /// Whether a scan is currently running.
    pub scanning: bool,
}

/// Start the server on a background thread. Returns the bound port.
pub fn start(shared: Arc<Mutex<ServerShared>>) -> Option<u16> {
    let server = match tiny_http::Server::http("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cross-tool server failed to bind: {e}");
            return None;
        }
    };
    let port = server.server_addr().to_ip().map(|s| s.port())?;
    let _ = std::fs::write(
        std::env::temp_dir().join("lancer-modelscan.port"),
        port.to_string(),
    );

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            handle(request, &shared);
        }
    });
    Some(port)
}

fn handle(mut request: tiny_http::Request, shared: &Arc<Mutex<ServerShared>>) {
    let url = request.url().to_string();
    let method = request.method().clone();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };

    let (status, body, content_type) = match (method, path.as_str()) {
        (tiny_http::Method::Get, "/v1/state") => {
            let guard = shared.lock().unwrap();
            let (count, max_sev, scanned) = guard
                .last_result
                .as_ref()
                .map(|r| {
                    (
                        r.all_issues().len(),
                        r.max_severity().as_str().to_string(),
                        r.scanned.len(),
                    )
                })
                .unwrap_or((0, "NONE".to_string(), 0));
            let json = serde_json::json!({
                "tool": "lancer-modelscan",
                "scanning": guard.scanning,
                "issues": count,
                "max_severity": max_sev,
                "scanned_files": scanned,
            });
            (200, json.to_string(), "application/json")
        }
        (tiny_http::Method::Get, "/v1/export") => {
            let fmt = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("format="))
                .unwrap_or("json");
            let guard = shared.lock().unwrap();
            match &guard.last_result {
                Some(result) => {
                    let format = ReportFormat::parse(fmt);
                    match result.to_report().render(&format, false) {
                        Ok(text) => {
                            let ct = match format {
                                ReportFormat::Html => "text/html",
                                ReportFormat::Console => "text/plain",
                                _ => "application/json",
                            };
                            (200, text, ct)
                        }
                        Err(e) => (500, format!("render error: {e}"), "text/plain"),
                    }
                }
                None => (404, "no scan result yet".to_string(), "text/plain"),
            }
        }
        (tiny_http::Method::Post, "/v1/import") => {
            let mut payload = String::new();
            let _ = request.as_reader().read_to_string(&mut payload);
            let target = payload.trim().trim_matches('"').to_string();
            if target.is_empty() {
                (400, "empty import payload".to_string(), "text/plain")
            } else {
                shared.lock().unwrap().imports.push(target);
                (
                    200,
                    serde_json::json!({"accepted": true}).to_string(),
                    "application/json",
                )
            }
        }
        _ => (404, "not found".to_string(), "text/plain"),
    };

    let header =
        tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap();
    let response = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}
