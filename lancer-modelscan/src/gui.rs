//! Native GUI (egui/eframe) — the Lancer-standard three-pane layout.
//!
//! Left: scan inputs + options. Center: findings table. Right: selected-finding
//! detail + remediation. Top: menu bar. Bottom: status bar. Scans run on a
//! worker thread; the egui thread only renders. A cross-tool HTTP server
//! ([`crate::server`]) runs alongside so other Lancer tools can import/export.

use crate::config::GuiConfig;
use crate::server::{self, ServerShared};
use ms_core::{ModelScan, ReportFormat, ScanOptions, ScanResult, Settings, Severity};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// Launch the desktop GUI. `initial` pre-fills the scan path.
pub fn launch(initial: Option<PathBuf>) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([820.0, 480.0])
            .with_title("lancer-modelscan"),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-modelscan",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, initial.clone())))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

struct App {
    config: GuiConfig,
    path: String,
    format: String,
    include: String,
    exclude: String,
    max_depth: String,
    strict_parity: bool,

    status: String,
    result: Option<ScanResult>,
    selected: Option<usize>,
    scanning: bool,
    rx: Option<Receiver<Result<ScanResult, String>>>,

    shared: Arc<Mutex<ServerShared>>,
    server_port: Option<u16>,
    show_about: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, initial: Option<PathBuf>) -> Self {
        let config = GuiConfig::load();
        cc.egui_ctx.set_visuals(if config.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
        let shared = Arc::new(Mutex::new(ServerShared::default()));
        let server_port = server::start(shared.clone());
        App {
            path: initial
                .map(|p| p.to_string_lossy().to_string())
                .or_else(|| config.last_dir.clone())
                .unwrap_or_default(),
            format: config.default_format.clone(),
            include: String::new(),
            exclude: String::new(),
            max_depth: String::new(),
            strict_parity: config.strict_parity,
            status: "Ready.".to_string(),
            result: None,
            selected: None,
            scanning: false,
            rx: None,
            shared,
            server_port,
            show_about: false,
            config,
        }
    }

    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        let path = PathBuf::from(self.path.trim());
        if self.path.trim().is_empty() {
            self.status = "Pick a file or folder to scan first.".to_string();
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.scanning = true;
        self.status = format!("Scanning {}…", self.path);
        self.selected = None;
        if let Ok(mut g) = self.shared.lock() {
            g.scanning = true;
        }

        let opts = ScanOptions {
            include: split_csv(&self.include),
            exclude: split_csv(&self.exclude),
            max_depth: self.max_depth.trim().parse::<usize>().ok(),
            follow_symlinks: false,
            strict_parity: self.strict_parity,
            baseline: None,
            show_skipped: true,
        };

        std::thread::spawn(move || {
            let mut scanner = ModelScan::new(Settings::default());
            scanner.set_options(opts);
            let result = match scanner.scan(&path) {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(result);
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        // Imports pushed via the HTTP server.
        if let Ok(mut g) = self.shared.lock() {
            if let Some(p) = g.imports.pop() {
                self.path = p;
                drop(g);
                self.start_scan();
                return;
            }
        }
        // Scan completion.
        if let Some(rx) = &self.rx {
            if let Ok(msg) = rx.try_recv() {
                self.scanning = false;
                self.rx = None;
                match msg {
                    Ok(result) => {
                        self.status = format!(
                            "Done: {} issue(s), {} file(s) scanned in {} ms.",
                            result.all_issues().len(),
                            result.scanned.len(),
                            result.elapsed_ms
                        );
                        if let Ok(mut g) = self.shared.lock() {
                            g.scanning = false;
                            g.last_result = Some(result.clone());
                        }
                        self.result = Some(result);
                    }
                    Err(e) => {
                        self.status = format!("Scan failed: {e}");
                        if let Ok(mut g) = self.shared.lock() {
                            g.scanning = false;
                        }
                    }
                }
            }
        }
        if self.scanning {
            ctx.request_repaint();
        }
    }

    fn export(&self, format: ReportFormat) {
        let Some(result) = &self.result else {
            return;
        };
        let ext = match format {
            ReportFormat::Html => "html",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Console => "txt",
            _ => "json",
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("modelscan-report.{ext}"))
            .save_file()
        {
            if let Ok(text) = result.to_report().render(&format, false) {
                let _ = std::fs::write(path, text);
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.handle_drops(ctx);

        self.top_menu(ctx);
        self.left_panel(ctx);
        self.right_panel(ctx);
        self.bottom_bar(ctx);
        self.central(ctx);

        if self.show_about {
            self.about_window(ctx);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.config.last_dir = Some(self.path.clone());
        self.config.default_format = self.format.clone();
        self.config.strict_parity = self.strict_parity;
        self.config.save();
    }
}

impl App {
    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.into_iter().next() {
            if let Some(path) = file.path {
                self.path = path.to_string_lossy().to_string();
                self.start_scan();
            }
        }
    }

    fn top_menu(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open File…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.path = p.to_string_lossy().to_string();
                            ui.close_menu();
                            self.start_scan();
                        }
                    }
                    if ui.button("Open Folder…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.path = p.to_string_lossy().to_string();
                            ui.close_menu();
                            self.start_scan();
                        }
                    }
                    ui.separator();
                    let has = self.result.is_some();
                    ui.add_enabled_ui(has, |ui| {
                        if ui.button("Export JSON…").clicked() {
                            self.export(ReportFormat::Json);
                            ui.close_menu();
                        }
                        if ui.button("Export HTML…").clicked() {
                            self.export(ReportFormat::Html);
                            ui.close_menu();
                        }
                        if ui.button("Export SARIF…").clicked() {
                            self.export(ReportFormat::Sarif);
                            ui.close_menu();
                        }
                    });
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Settings", |ui| {
                    if ui.checkbox(&mut self.config.dark_mode, "Dark theme").changed() {
                        ctx.set_visuals(if self.config.dark_mode {
                            egui::Visuals::dark()
                        } else {
                            egui::Visuals::light()
                        });
                    }
                    ui.checkbox(&mut self.strict_parity, "Strict parity (drop LOW)");
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                        ui.close_menu();
                    }
                });
            });
        });
    }

    fn left_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("inputs")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading("Scan");
                ui.separator();
                ui.label("Target file or folder:");
                ui.add(egui::TextEdit::singleline(&mut self.path).hint_text("drag & drop or browse"));
                ui.horizontal(|ui| {
                    if ui.button("File…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.path = p.to_string_lossy().to_string();
                        }
                    }
                    if ui.button("Folder…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.path = p.to_string_lossy().to_string();
                        }
                    }
                });
                ui.add_space(8.0);
                ui.collapsing("Options", |ui| {
                    ui.label("Include globs (csv):");
                    ui.text_edit_singleline(&mut self.include);
                    ui.label("Exclude globs (csv):");
                    ui.text_edit_singleline(&mut self.exclude);
                    ui.label("Max depth:");
                    ui.text_edit_singleline(&mut self.max_depth);
                    ui.checkbox(&mut self.strict_parity, "Strict parity");
                    ui.horizontal(|ui| {
                        ui.label("Format:");
                        egui::ComboBox::from_id_salt("fmt")
                            .selected_text(&self.format)
                            .show_ui(ui, |ui| {
                                for f in ["console", "json", "html", "sarif"] {
                                    ui.selectable_value(&mut self.format, f.to_string(), f);
                                }
                            });
                    });
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let scan_label = if self.scanning { "Scanning…" } else { "Scan" };
                    if ui
                        .add_enabled(!self.scanning, egui::Button::new(scan_label))
                        .clicked()
                    {
                        self.start_scan();
                    }
                    if ui
                        .add_enabled(self.scanning, egui::Button::new("Stop"))
                        .clicked()
                    {
                        // Best-effort: detach the worker; discard its result.
                        self.rx = None;
                        self.scanning = false;
                        self.status = "Stopped (result discarded).".to_string();
                        if let Ok(mut g) = self.shared.lock() {
                            g.scanning = false;
                        }
                    }
                });
                ui.add_space(8.0);
                if let Some(result) = &self.result {
                    ui.separator();
                    ui.label(egui::RichText::new("Summary").strong());
                    let counts = result.group_by_severity();
                    for sev in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
                        let n = counts.get(&sev).map(|v| v.len()).unwrap_or(0);
                        ui.colored_label(severity_color(sev), format!("{sev}: {n}"));
                    }
                    ui.label(format!("Scanned: {}", result.scanned.len()));
                    ui.label(format!("Skipped: {}", result.skipped.len()));
                }
            });
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Findings");
            ui.separator();
            let Some(result) = self.result.clone() else {
                ui.add_space(20.0);
                ui.label("No scan yet. Pick a target and press Scan, or drag a model file onto the window.");
                return;
            };
            if result.all_issues().is_empty() {
                ui.add_space(20.0);
                ui.colored_label(
                    egui::Color32::from_rgb(80, 200, 120),
                    "No unsafe code-execution risks found. ✓",
                );
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, issue) in result.all_issues().iter().enumerate() {
                    let selected = self.selected == Some(i);
                    let tag = issue.severity.as_str();
                    let target = issue.qualified().unwrap_or_else(|| "-".to_string());
                    let line = format!(
                        "[{}]  {}  {}  ({})",
                        tag,
                        short_path(&issue.file_path),
                        target,
                        issue.detector
                    );
                    let label = egui::RichText::new(line).color(severity_color(issue.severity));
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected = Some(i);
                    }
                }
            });
        });
    }

    fn right_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading("Detail");
                ui.separator();
                let issue = match (&self.result, self.selected) {
                    (Some(r), Some(i)) => r.all_issues().get(i),
                    _ => None,
                };
                let Some(issue) = issue else {
                    ui.label("Select a finding to see details.");
                    return;
                };
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.colored_label(severity_color(issue.severity), issue.severity.as_str());
                    ui.label(format!("ID: {}", issue.id));
                    ui.label(format!("Detector: {}", issue.detector));
                    ui.separator();
                    ui.label(format!("File: {}", issue.file_path));
                    if let Some(src) = &issue.source {
                        ui.label(format!("Source: {src}"));
                    }
                    ui.label(format!("Offset: {}", issue.offset));
                    if let Some(op) = &issue.operator {
                        ui.label(format!("Operator: {op}"));
                    }
                    if let Some(q) = issue.qualified() {
                        ui.label(format!("Target: {q}"));
                    }
                    ui.separator();
                    ui.label(egui::RichText::new("Message").strong());
                    ui.label(&issue.message);
                    ui.separator();
                    if ui.button("Copy target").clicked() {
                        if let Some(q) = issue.qualified() {
                            // egui 0.29: clipboard text is set via PlatformOutput
                            // (Context::copy_text only exists from 0.31).
                            ui.output_mut(|o| o.copied_text = q);
                        }
                    }
                });
            });
    }

    fn bottom_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(port) = self.server_port {
                        ui.label(format!("api :{port}"));
                    }
                });
            });
        });
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        egui::Window::new("About lancer-modelscan")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("lancer-modelscan v{}", env!("CARGO_PKG_VERSION")));
                ui.label("Rust clone of Protect AI's modelscan, part of the Lancer toolkit.");
                ui.label("Scans serialized ML model files for unsafe code execution — parse-only.");
            });
        self.show_about = open;
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn short_path(p: &str) -> String {
    let parts: Vec<&str> = p.rsplit('/').collect();
    match parts.first() {
        Some(name) if p.len() > 48 => format!("…/{name}"),
        _ => p.to_string(),
    }
}

fn severity_color(sev: Severity) -> egui::Color32 {
    match sev {
        Severity::Critical => egui::Color32::from_rgb(235, 64, 52),
        Severity::High => egui::Color32::from_rgb(235, 130, 52),
        Severity::Medium => egui::Color32::from_rgb(235, 200, 52),
        Severity::Low => egui::Color32::from_rgb(120, 170, 235),
        Severity::None => egui::Color32::GRAY,
    }
}
