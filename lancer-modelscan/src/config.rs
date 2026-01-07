//! GUI configuration persisted to the per-OS config dir
//! (`%APPDATA%\lancer-modelscan\`, `~/.config/lancer-modelscan/`, …).

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuiConfig {
    pub dark_mode: bool,
    pub default_format: String,
    pub last_dir: Option<String>,
    pub strict_parity: bool,
}

impl Default for GuiConfig {
    fn default() -> Self {
        GuiConfig {
            dark_mode: true,
            default_format: "console".to_string(),
            last_dir: None,
            strict_parity: false,
        }
    }
}

impl GuiConfig {
    fn config_path() -> Option<PathBuf> {
        ProjectDirs::from("io", "lancer", "lancer-modelscan")
            .map(|d| d.config_dir().join("lancer-modelscan-config.json"))
    }

    /// Load from disk, falling back to defaults on any error.
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return GuiConfig::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => GuiConfig::default(),
        }
    }

    /// Persist to disk (best effort).
    pub fn save(&self) {
        let Some(path) = Self::config_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, text);
        }
    }
}
