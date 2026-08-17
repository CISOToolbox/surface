//! Fast SMB/CIFS file-share content scanner (Rust worker for Surface).
//!
//! Mirrors the Python `smb_scan` add-on: same secret ruleset, masking, finding
//! schema and host roll-up (target = UNC path). Runs as a separate process
//! invoked by the Python shim add-on, so the CPU-heavy document extraction
//! never starves the FastAPI event loop, and benefits from real (GIL-free)
//! parallelism + fast regex.
//!
//! IO contract:
//!   in  (env): SMB_TARGET (\\host\share[\sub] | //... | smb://...),
//!              SMB_USER, SMB_PASS, SMB_DOMAIN (optional),
//!              SMB_CONFIG (optional JSON: extensions[], max_size_mb,
//!              max_files, time_budget_s, custom_regex[])
//!   out (stdout): JSON array of findings
//!                 [{scanner,type,severity,title,description,target,evidence}]

use std::env;
use std::io::{Cursor, Read};
use std::time::Instant;

use pavao::{SmbClient, SmbCredentials, SmbDirentType, SmbOpenOptions, SmbOptions};
use regex::Regex;
use serde::{Deserialize, Serialize};

const SCANNER: &str = "smb_scan";
const MAX_FINDINGS_PER_FILE: usize = 20;
const DEFAULT_MAX_SIZE_MB: u64 = 50;
const DEFAULT_TIME_BUDGET_S: u64 = 1800;

const DEFAULT_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "log",
    "ini", "conf", "cfg", "config", "env", "yml", "yaml", "json", "xml",
    "properties", "sh", "ps1", "bat", "sql", "key", "pem", "kdbx", "rdp",
];

#[derive(Serialize)]
struct Finding {
    scanner: String,
    #[serde(rename = "type")]
    type_: String,
    severity: String,
    title: String,
    description: String,
    target: String,
    evidence: serde_json::Value,
}

fn finding(sev: &str, title: String, desc: String, target: &str, type_: &str,
           evidence: serde_json::Value) -> Finding {
    Finding {
        scanner: SCANNER.into(), type_: type_.into(), severity: sev.into(),
        title, description: desc, target: target.into(), evidence,
    }
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)] extensions: Vec<String>,
    #[serde(default)] max_size_mb: Option<u64>,
    #[serde(default)] max_files: Option<usize>,
    #[serde(default)] time_budget_s: Option<u64>,
    #[serde(default)] custom_regex: Vec<String>,
    // Resume cursor: the share-relative path of the last file covered by the
    // previous scan. The walk is a deterministic sorted pre-order DFS, so we
    // skip every file <= this cursor and scan only the next max_files *new*
    // files. Empty / absent = start from the top.
    #[serde(default)] resume_after: Option<String>,
}

/// Compare two share-relative paths in the canonical walk order: component-wise
/// lexicographic, which exactly matches a sorted pre-order DFS (a file in a
/// sub-directory sorts right after the entries that precede that sub-dir's name
/// in its parent). Used both to skip already-covered files and to prune fully
/// covered sub-trees.
fn path_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.trim_start_matches('/').split('/').filter(|s| !s.is_empty())
        .cmp(b.trim_start_matches('/').split('/').filter(|s| !s.is_empty()))
}

/// True when EVERY path under directory `d` sorts at or before `cursor`, so the
/// whole sub-tree was already covered and we can skip listing it. False when the
/// cursor lands inside `d` (must descend) or the sub-tree is all new.
fn dir_fully_before_cursor(d: &str, cursor: &str) -> bool {
    if cursor.is_empty() { return false; }
    let dc: Vec<&str> = d.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let cc: Vec<&str> = cursor.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    for i in 0..dc.len() {
        if i >= cc.len() { return false; }            // cursor inside d → descend
        match dc[i].cmp(cc[i]) {
            std::cmp::Ordering::Less => return true,   // diverges lower → fully covered
            std::cmp::Ordering::Greater => return false, // diverges higher → all new
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

enum Item { Dir(String), File(String) }

fn mask(s: &str) -> String {
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return if chars.is_empty() { "***".into() } else { format!("{}***", chars[0]) };
    }
    let first4: String = chars[..4].iter().collect();
    let last2: String = chars[chars.len() - 2..].iter().collect();
    format!("{}…{} ({} chars)", first4, last2, chars.len())
}

/// (rule name, severity, pattern) — kept in sync with the Python ruleset.
fn secret_rules() -> Vec<(&'static str, &'static str, Regex)> {
    let r = |p: &str| Regex::new(p).unwrap();
    vec![
        ("private_key", "critical", r(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
        ("aws_access_key", "critical", r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("aws_secret_key", "high", r(r#"(?i)\baws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}\b"#)),
        ("gcp_service_account", "critical", r(r#""type"\s*:\s*"service_account""#)),
        ("google_api_key", "high", r(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("github_token", "critical", r(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
        ("slack_token", "high", r(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("jwt", "medium", r(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
        ("connection_string", "high", r(r"(?i)(?:Data Source|Server)=[^;]+;[^;]*(?:Password|Pwd)=[^;]+")),
        ("password_assignment", "medium", r(r#"(?i)(?:password|passwd|pwd|mot_de_passe|motdepasse)\s*[=:]\s*['"]?[^\s'"]{6,}"#)),
        ("generic_secret", "medium", r(r#"(?i)\b(?:secret|api[_-]?key|token|client[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9/+_\-]{16,}"#)),
    ]
}

fn interesting_name_re() -> Regex {
    Regex::new(r"(?i)(?:^|[\\/])(?:id_rsa|id_dsa|id_ed25519|\.npmrc|\.pgpass|\.htpasswd|web\.config|unattend\.xml|sysprep\.xml|wp-config\.php|\.kdbx|credentials|secrets?|password|motdepasse|backup)").unwrap()
}

fn scan_text(text: &str, rules: &[(&str, &str, Regex)], custom: &[Regex]) -> Vec<(String, String, String)> {
    let mut hits = Vec::new();
    for (name, sev, rx) in rules {
        for m in rx.find_iter(text) {
            hits.push((name.to_string(), sev.to_string(), mask(m.as_str())));
            if hits.len() >= MAX_FINDINGS_PER_FILE { return hits; }
        }
    }
    for rx in custom {
        for m in rx.find_iter(text) {
            hits.push(("custom_regex".into(), "medium".into(), mask(m.as_str())));
            if hits.len() >= MAX_FINDINGS_PER_FILE { return hits; }
        }
    }
    hits
}

// ── Text extraction ──────────────────────────────────────────────
fn xml_text(xml: &[u8]) -> String {
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Text(e)) => {
                if let Ok(t) = e.unescape() { out.push_str(&t); out.push(' '); }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn zip_entry_text(data: &[u8], name: &str) -> String {
    let cursor = Cursor::new(data);
    if let Ok(mut z) = zip::ZipArchive::new(cursor) {
        if let Ok(mut f) = z.by_name(name) {
            let mut v = Vec::new();
            if f.read_to_end(&mut v).is_ok() { return xml_text(&v); }
        }
    }
    String::new()
}

fn pptx_text(data: &[u8]) -> String {
    let cursor = Cursor::new(data);
    let mut out = String::new();
    if let Ok(mut z) = zip::ZipArchive::new(cursor) {
        for i in 0..z.len() {
            if let Ok(mut f) = z.by_index(i) {
                let name = f.name().to_string();
                if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                    let mut v = Vec::new();
                    if f.read_to_end(&mut v).is_ok() { out.push_str(&xml_text(&v)); }
                }
            }
        }
    }
    out
}

fn xlsx_text(data: &[u8]) -> String {
    use calamine::{Reader, Xlsx};
    let cursor = Cursor::new(data.to_vec());
    let mut out = String::new();
    if let Ok(mut wb) = Xlsx::new(cursor) {
        let names = wb.sheet_names().to_owned();
        for name in names {
            if let Ok(range) = wb.worksheet_range(&name) {
                for row in range.rows() {
                    for cell in row {
                        let s = cell.to_string();
                        if !s.is_empty() { out.push_str(&s); out.push(' '); }
                    }
                }
            }
        }
    }
    out
}

fn extract_text(ext: &str, data: &[u8]) -> String {
    match ext {
        // PDF body extraction is intentionally NOT done in the Rust MVP
        // (no mature crate matching pdfminer). Returns empty → no PDF body
        // findings; filename hits still fire.
        "pdf" => String::new(),
        "docx" => zip_entry_text(data, "word/document.xml"),
        "pptx" => pptx_text(data),
        "xlsx" => xlsx_text(data),
        _ => String::from_utf8_lossy(data).into_owned(),
    }
}

// ── Share path parsing ───────────────────────────────────────────
/// "\\host\share\sub" | "//host/share" | "smb://host/share/dir"
/// -> (host, share, start_path_relative_to_share)
fn parse_share(value: &str) -> Option<(String, String, String)> {
    let raw = value.trim();
    let raw = raw.strip_prefix("smb://").unwrap_or(raw);
    let norm: String = raw.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 { return None; }
    let host = parts[0].to_string();
    let share = parts[1].to_string();
    let sub = if parts.len() > 2 { format!("/{}", parts[2..].join("/")) } else { String::new() };
    Some((host, share, sub))
}

fn unc(host: &str, share: &str, rel: &str) -> String {
    // rel uses forward slashes (relative to share root, leading '/')
    let rel_bs = rel.trim_start_matches('/').replace('/', "\\");
    if rel_bs.is_empty() { format!("\\\\{}\\{}", host, share) }
    else { format!("\\\\{}\\{}\\{}", host, share, rel_bs) }
}

fn emit(f: &Finding) {
    // NDJSON: one finding per line, flushed immediately so the Python shim can
    // persist incrementally — a killed/timed-out scan keeps what it found.
    if let Ok(s) = serde_json::to_string(f) {
        use std::io::Write;
        let out = std::io::stdout();
        let mut h = out.lock();
        let _ = writeln!(h, "{s}");
        let _ = h.flush();
    }
}

fn main() {
    let target = env::var("SMB_TARGET").unwrap_or_default();
    let user = env::var("SMB_USER").unwrap_or_default();
    let pass = env::var("SMB_PASS").unwrap_or_default();
    let domain = env::var("SMB_DOMAIN").unwrap_or_default();
    let cfg: Config = env::var("SMB_CONFIG").ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let (host, share, start) = match parse_share(&target) {
        Some(v) => v,
        None => {
            emit(&finding("info", format!("Partage invalide : {target}"),
                "Format attendu \\\\host\\share".into(), &target, "smb_status", serde_json::json!({})));
            return;
        }
    };
    if user.is_empty() || pass.is_empty() {
        emit(&finding("info", "Identifiants SMB manquants".into(),
            "Renseigner les identifiants sur la cible.".into(), &target, "smb_status", serde_json::json!({})));
        return;
    }

    let exts: Vec<String> = if cfg.extensions.is_empty() {
        DEFAULT_EXTS.iter().map(|s| s.to_string()).collect()
    } else {
        cfg.extensions.iter().map(|e| e.trim_start_matches('.').to_lowercase()).collect()
    };
    let max_bytes = cfg.max_size_mb.unwrap_or(DEFAULT_MAX_SIZE_MB) * 1024 * 1024;
    // No default file cap: an unset max_files means "scan the whole share"
    // (bounded only by the time budget). A cap is an opt-in option; when set it
    // limits each scan to that many NEW files and the resume cursor carries the
    // rest to the next run.
    let max_files: Option<usize> = cfg.max_files;
    let time_budget = cfg.time_budget_s.unwrap_or(DEFAULT_TIME_BUDGET_S);
    let custom: Vec<Regex> = cfg.custom_regex.iter().filter_map(|p| Regex::new(p).ok()).collect();
    let rules = secret_rules();
    let iname = interesting_name_re();
    let deadline = Instant::now();

    let client = match SmbClient::new(
        SmbCredentials::default()
            .server(format!("smb://{host}"))
            .share(format!("/{share}"))
            .username(&user)
            .password(&pass)
            .workgroup(if domain.is_empty() { "WORKGROUP" } else { &domain }),
        SmbOptions::default().one_share_per_server(true),
    ) {
        Ok(c) => c,
        Err(e) => {
            emit(&finding("info", format!("Connexion SMB échouée : {host}"),
                format!("{e}"), &target, "smb_status", serde_json::json!({})));
            return;
        }
    };

    // The resume cursor ONLY applies to capped scans (max_files set): a capped
    // run covers a slice and the cursor carries the rest forward. An UNCAPPED
    // scan must cover the whole share, so any leftover cursor from a previous
    // capped run is ignored here (and cleared at the end) — otherwise it would
    // silently skip everything up to the cursor and wrongly report "completed".
    let cursor = if max_files.is_some() { cfg.resume_after.clone().unwrap_or_default() } else { String::new() };

    let mut candidates: Vec<(String, u64)> = Vec::new();  // (relative path, size)
    let mut truncated: Option<&str> = None;
    let mut reached_end = true;  // cleared when we stop early (cap / time)
    let mut inaccessible_dirs: usize = 0;  // dirs we could not list (perms / SMB errors)

    // Deterministic sorted pre-order DFS bounded by max_files NEW files + time
    // budget. A single stack with each directory's children pushed in reverse
    // sorted order yields ascending pre-order on pop; files <= the resume cursor
    // are skipped (already covered) and fully covered sub-trees are pruned, so
    // each scan advances through the share instead of re-scanning the same head.
    let start_dir = if start.is_empty() { "/".into() } else { start.clone() };
    let mut stack: Vec<Item> = vec![Item::Dir(start_dir)];
    'walk: while let Some(item) = stack.pop() {
        if deadline.elapsed().as_secs() > time_budget { truncated = Some("time"); reached_end = false; break; }
        match item {
            Item::Dir(dir) => {
                let mut entries = match client.list_dir(&dir) {
                    Ok(e) => e,
                    Err(_) => { inaccessible_dirs += 1; continue; }
                };
                entries.sort_by(|a, b| a.name().cmp(b.name()));
                for ent in entries.into_iter().rev() {
                    let name = ent.name().to_string();
                    if name == "." || name == ".." { continue; }
                    let child = if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") };
                    match ent.get_type() {
                        SmbDirentType::Dir => {
                            if !dir_fully_before_cursor(&child, &cursor) { stack.push(Item::Dir(child)); }
                        }
                        SmbDirentType::File => stack.push(Item::File(child)),
                        _ => {}
                    }
                }
            }
            Item::File(child) => {
                // Already covered by a previous scan → skip without reading.
                if !cursor.is_empty() && path_cmp(&child, &cursor) != std::cmp::Ordering::Greater { continue; }
                let ext = child.rsplit('.').next().filter(|_| child.contains('.')).unwrap_or("").to_lowercase();
                let is_name = iname.is_match(&child);
                if !exts.contains(&ext) && !is_name { continue; }
                let size = client.stat(&child).map(|s| s.size as u64).unwrap_or(0);
                if size > max_bytes { continue; }
                if is_name {
                    let fname = child.rsplit('/').next().unwrap_or(&child).to_string();
                    emit(&finding("low", format!("Fichier sensible par nom : {fname}"),
                        "Nom/extension évocateur de données sensibles.".into(),
                        &unc(&host, &share, &child), "interesting_name",
                        serde_json::json!({"file": unc(&host,&share,&child), "rule": "interesting_name"})));
                }
                if exts.contains(&ext) {
                    candidates.push((child, size));
                    if let Some(mf) = max_files {
                        if candidates.len() >= mf { truncated = Some("files"); reached_end = false; break 'walk; }
                    }
                }
            }
        }
    }

    // Read + extract + match. Parallelism is left simple here (sequential) for
    // the MVP; libsmbclient sessions are not Send, so true threading needs a
    // session per worker — a follow-up. Even single-threaded, native code with
    // no GIL is markedly faster than the Python extractor chain.
    for (rel, _size) in &candidates {
        if deadline.elapsed().as_secs() > time_budget { truncated = Some(truncated.unwrap_or("time")); break; }
        let ext = rel.rsplit('.').next().filter(|_| rel.contains('.')).unwrap_or("").to_lowercase();
        let mut buf = Vec::new();
        let read_ok = match client.open_with(rel, SmbOpenOptions::default().read(true)) {
            Ok(mut fh) => fh.read_to_end(&mut buf).is_ok(),
            Err(_) => false,
        };
        if !read_ok { continue; }
        let text = extract_text(&ext, &buf);
        if text.is_empty() { continue; }
        let tgt = unc(&host, &share, rel);
        let base = rel.rsplit('/').next().unwrap_or(rel).to_string();
        for (name, sev, masked) in scan_text(&text, &rules, &custom) {
            emit(&finding(&sev, format!("Donnée sensible ({name}) : {base}"),
                format!("Motif « {name} » détecté dans le corps du fichier."),
                &tgt, &name,
                serde_json::json!({"file": tgt, "rule": name, "match": masked})));
        }
    }

    // Final control record (non-finding `scanner_state` the Python caller merges
    // into the asset config) — reports whether the scan is PARTIAL so the caller
    // marks the job "partial" rather than "completed", and carries/clears the
    // resume cursor:
    //  - file cap hit            → partial, advance the cursor to the last file;
    //  - time budget hit         → partial, cursor unchanged (retry next time);
    //  - dirs inaccessible        → partial (coverage incomplete), no cursor move;
    //  - whole share covered, ok → not partial, CLEAR the cursor (so the next
    //    scan loops back / a stale cursor from a past capped run can't linger).
    let last_covered = candidates.last().map(|(p, _)| p.clone());
    let partial = truncated.is_some() || inaccessible_dirs > 0;
    let mut ev = serde_json::json!({
        "partial": partial,
        "scanned": candidates.len(),
        "inaccessible_dirs": inaccessible_dirs,
    });
    if let Some(reason) = truncated { ev["limit"] = serde_json::json!(reason); }
    if truncated == Some("files") {
        // Only a file-cap advances the cursor; everything else clears it.
        if let Some(cur) = &last_covered { ev["config_patch"] = serde_json::json!({"smb_resume_after": cur}); }
    } else {
        ev["config_unset"] = serde_json::json!(["smb_resume_after"]);
    }
    emit(&finding("info", "État du scan SMB".into(),
        if partial { "Scan partiel — couverture incomplète.".into() }
        else { "Partage entièrement couvert.".to_string() },
        &target, "scanner_state", ev));

    if partial {
        let mut reasons: Vec<String> = Vec::new();
        match truncated {
            Some("files") => reasons.push(format!("{} fichiers analysés (plafond max_files atteint) — la suite au prochain scan", candidates.len())),
            Some("time") => reasons.push("budget temps atteint — augmenter la durée max ou affiner le périmètre".to_string()),
            _ => {}
        }
        if inaccessible_dirs > 0 {
            reasons.push(format!("{inaccessible_dirs} dossier(s) non listable(s) (droits insuffisants ou erreur SMB)"));
        }
        emit(&finding("info", format!("Scan du partage partiel : {host}"),
            format!("Couverture incomplète : {}.", reasons.join(" ; ")),
            &target, "smb_status",
            serde_json::json!({"limit": truncated, "inaccessible_dirs": inaccessible_dirs})));
    }

}
