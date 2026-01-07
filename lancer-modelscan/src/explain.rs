//! `--explain` — plain-language explanation of findings (plan §"AI augmentation").
//!
//! If `ANTHROPIC_API_KEY` is set, this calls the Claude Messages API to expand
//! the findings into prose plus safe-alternative suggestions. Otherwise it
//! falls back to a deterministic, local rule-based explanation so `--explain`
//! is always useful, even offline.

use ms_core::{ScanResult, Severity};
use std::time::Duration;

/// Produce a markdown explanation block for a scan result.
pub fn explain_result(result: &ScanResult) -> anyhow::Result<String> {
    let local = local_explanation(result);
    match std::env::var("ANTHROPIC_API_KEY") {
        Ok(key) if !key.trim().is_empty() => match llm_explanation(result, &key) {
            Ok(text) => Ok(text),
            Err(e) => {
                // Network/LLM failure shouldn't lose the local explanation.
                Ok(format!(
                    "{local}\n\n_(LLM augmentation unavailable: {e}.)_"
                ))
            }
        },
        _ => Ok(local),
    }
}

/// Deterministic local explanation — no network required.
fn local_explanation(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("## Explanation\n\n");
    if !result.has_issues() {
        out.push_str(
            "No unsafe code-execution risks were found. The scanned artifacts \
             contain no dangerous pickle globals, custom graph ops, or embedded \
             lambda code.\n",
        );
        return out;
    }
    let groups = result.group_by_severity();
    for sev in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
        if let Some(issues) = groups.get(&sev) {
            if issues.is_empty() {
                continue;
            }
            out.push_str(&format!("### {} ({} finding(s))\n\n", sev, issues.len()));
            for issue in issues.iter().take(20) {
                let target = issue.qualified().unwrap_or_else(|| "<dynamic>".to_string());
                out.push_str(&format!(
                    "- `{}` in `{}`: when this file is loaded, it would reference \
                     `{target}`. {}\n",
                    issue.operator.as_deref().unwrap_or("ref"),
                    issue.file_path,
                    remediation(&target),
                ));
            }
            out.push('\n');
        }
    }
    out.push_str(
        "**Recommendation:** prefer `safetensors` for weights, avoid `pickle`/\
         `torch.load` on untrusted files, and load with `weights_only=True` where \
         supported.\n",
    );
    out
}

fn remediation(target: &str) -> &'static str {
    if target.starts_with("os.") || target.starts_with("subprocess.") || target.starts_with("posix.")
    {
        "This binds a shell/process primitive — almost certainly malicious; do not load."
    } else if target.starts_with("builtins.") {
        "This binds a code-eval builtin (eval/exec/compile) — treat as malicious."
    } else if target.starts_with("socket.") || target.contains("request") || target.contains("http")
    {
        "This binds a network primitive — possible exfiltration; review carefully."
    } else {
        "Review whether this reduce target is expected; allowlist it if legitimate."
    }
}

#[cfg(feature = "net")]
fn llm_explanation(result: &ScanResult, key: &str) -> anyhow::Result<String> {
    let model =
        std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string());

    // Compact findings summary for the prompt.
    let mut findings = String::new();
    for issue in result.all_issues().iter().take(60) {
        findings.push_str(&format!(
            "- [{}] {} {} :: {}\n",
            issue.severity,
            issue.file_path,
            issue.qualified().unwrap_or_default(),
            issue.message
        ));
    }
    if findings.is_empty() {
        findings.push_str("(no findings)\n");
    }

    let prompt = format!(
        "You are a security analyst. Given these findings from a ML-model safety \
         scanner, write a concise markdown briefing: (1) what an attacker could do, \
         (2) which findings are most urgent, (3) concrete safe-alternative code \
         (e.g. migrate pickle -> safetensors). Findings:\n\n{findings}"
    );

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()?;

    if !resp.status().is_success() {
        anyhow::bail!("API returned status {}", resp.status());
    }
    let v: serde_json::Value = resp.json()?;
    let text = v["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|blk| blk["text"].as_str())
        .unwrap_or("")
        .to_string();
    if text.trim().is_empty() {
        anyhow::bail!("empty LLM response");
    }
    Ok(format!("## Explanation (AI)\n\n{text}\n"))
}

#[cfg(not(feature = "net"))]
#[allow(dead_code)]
fn llm_explanation(_result: &ScanResult, _key: &str) -> anyhow::Result<String> {
    anyhow::bail!("network feature not enabled")
}
