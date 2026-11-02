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
/// UTF-8 text of `bytes`, each invalid sequence replaced by one `?`: unlike
/// `from_utf8_lossy` (three bytes per U+FFFD) the text is never longer than
/// the input, and unlike a space it does not split a token (a Latin-1 `é`
/// inside a password keeps it whole for the rules).
fn lossy_text(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    if let Ok(s) = std::str::from_utf8(bytes) { return s.into(); }
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() { out.push('?'); }
    }
    out.into()
}

/// Append the text an entity or character reference stands for.
fn push_ref(out: &mut String, r: &quick_xml::events::BytesRef) {
    match r.resolve_char_ref() {
        Ok(Some(c)) => out.push(c),
        _ => match quick_xml::escape::resolve_predefined_entity(r) {
            Some(s) => out.push_str(s),
            // Not an entity (a bare `&` followed by a `;` later on): keep the
            // raw text rather than drop it.
            None => { out.push('&'); out.push_str(r); out.push(';'); }
        },
    }
}

fn xml_text(xml: &[u8]) -> String {
    // An invalid byte would stop the reader for good: replace it instead.
    let xml = lossy_text(xml);
    let xml = xml.as_bytes();
    let mut reader = quick_xml::Reader::from_reader(xml);
    // A bare `&` is kept as text, not an error that would drop the node.
    reader.config_mut().allow_dangling_amp = true;
    let mut buf = Vec::new();
    let mut out = String::new();
    // Entity references (`&amp;`, `&#65;`) arrive as their own events, between
    // the text around them: glue them to it, or a secret holding one would be
    // split in two and missed. Only within one text node: any tag in between
    // keeps the separating space.
    let mut adjacent = false;
    let mut last_err = u64::MAX;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Text(e)) => {
                if adjacent && out.ends_with(' ') { out.pop(); }
                out.push_str(&e.xml10_content());
                out.push(' ');
                adjacent = true;
            }
            Ok(quick_xml::events::Event::GeneralRef(r)) => {
                if adjacent && out.ends_with(' ') { out.pop(); }
                push_ref(&mut out, &r);
                out.push(' ');
                adjacent = true;
            }
            Ok(quick_xml::events::Event::Eof) => break,
            // A malformed node must not hide the rest of the part: skip it,
            // unless the reader cannot move past it.
            Err(_) => {
                let pos = reader.buffer_position();
                if pos as usize >= xml.len() || pos == last_err { break; }
                last_err = pos;
                adjacent = false;
            }
            _ => adjacent = false,
        }
        buf.clear();
    }
    out
}

/// Decompression budget for one document. A few MB of zip can inflate to
/// gigabytes (zip bomb), so every part read out of an archive draws from it;
/// once it runs out, what was read is still scanned and the file is reported
/// as truncated. With the parser's buffers and the text extracted from it, a
/// document peaks at about five times the budget (measured: about 535 MB).
struct Budget { left: u64, truncated: Option<Truncation> }

#[derive(Clone, Copy, Debug, PartialEq)]
enum Truncation { Size, Slides }

impl Budget {
    fn new(bytes: u64) -> Self { Budget { left: bytes, truncated: None } }

    /// Read `r` to its end, or until the budget runs out. A read error keeps
    /// (and charges) what was read before it.
    fn read(&mut self, r: impl Read) -> Vec<u8> {
        let mut v = Vec::new();
        let _ = r.take(self.left + 1).read_to_end(&mut v);
        if v.len() as u64 > self.left {
            v.truncate(self.left as usize);
            self.truncated = Some(Truncation::Size);
        }
        self.left -= v.len() as u64;
        v
    }
}

const MAX_DECOMPRESSED_BYTES: u64 = 100 * 1024 * 1024;
const MAX_SLIDES: usize = 5000;

fn zip_entry_text(data: &[u8], name: &str, budget: &mut Budget) -> String {
    let cursor = Cursor::new(data);
    if let Ok(mut z) = zip::ZipArchive::new(cursor) {
        if let Ok(f) = z.by_name(name) {
            return xml_text(&budget.read(f));
        }
    }
    String::new()
}

fn pptx_text(data: &[u8], budget: &mut Budget) -> String {
    let cursor = Cursor::new(data);
    let mut out = String::new();
    let mut slides = 0;
    if let Ok(mut z) = zip::ZipArchive::new(cursor) {
        for i in 0..z.len() {
            if let Ok(f) = z.by_index(i) {
                let Ok(name) = f.name().map(|n| n.into_owned()) else { continue };
                if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                    if budget.left == 0 { budget.truncated = Some(Truncation::Size); break; }
                    if slides == MAX_SLIDES { budget.truncated = Some(Truncation::Slides); break; }
                    slides += 1;
                    out.push_str(&xml_text(&budget.read(f)));
                }
            }
        }
    }
    out
}

/// The workbook's shared strings (`xl/sharedStrings.xml`), where Excel keeps
/// the text of cells, which then only hold an index. Each `<si>` is one
/// string: its formatting runs are joined, only `<t>` text counts (not the
/// indentation between runs), and the phonetic reading (`<rPh>`) is left out.
/// Stored as one pool (never longer than the XML it came from) plus one span
/// of 8 bytes per string.
#[derive(Default)]
struct SharedStrings { pool: String, spans: Vec<(u32, u32)> }

impl SharedStrings {
    fn get(&self, i: usize) -> &str {
        self.spans.get(i).map_or("", |&(a, b)| &self.pool[a as usize..b as usize])
    }
}

/// Walks spreadsheet XML, tracking whether the reader is inside `<t>` text
/// (and not inside a phonetic reading): the state both parts share.
#[derive(Default)]
struct CellText { in_t: usize, in_rph: usize }

impl CellText {
    fn start(&mut self, name: &str) {
        match name { "t" => self.in_t += 1, "rPh" => self.in_rph += 1, _ => {} }
    }
    fn end(&mut self, name: &str) {
        match name {
            "t" => self.in_t = self.in_t.saturating_sub(1),
            "rPh" => self.in_rph = self.in_rph.saturating_sub(1),
            _ => {}
        }
    }
    fn reading(&self) -> bool { self.in_t > 0 && self.in_rph == 0 }
}

/// Reader for spreadsheet parts: a mismatched end tag is taken as written
/// rather than reported as an error, and every string item or cell starts and
/// ends with a clean state, so an element left open (`<si><rPh>…</si>`)
/// cannot hide or shift what follows.
fn xml_reader(xml: &[u8]) -> quick_xml::Reader<&[u8]> {
    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().allow_dangling_amp = true;
    reader.config_mut().check_end_names = false;
    reader
}

fn shared_strings(xml: &[u8]) -> SharedStrings {
    use quick_xml::events::Event;
    let xml = lossy_text(xml);
    let mut reader = xml_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut sst = SharedStrings::default();
    let mut cell = CellText::default();
    let mut item: Option<u32> = None;
    let mut last_err = u64::MAX;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.local_name();
                if name.as_ref() == "si" { item = Some(sst.pool.len() as u32); cell = CellText::default(); }
                else { cell.start(name.as_ref()); }
            }
            Ok(Event::Empty(e)) if e.local_name().as_ref() == "si" => {
                let at = sst.pool.len() as u32;
                sst.spans.push((at, at));
            }
            Ok(Event::End(e)) => {
                let name = e.local_name();
                if name.as_ref() == "si" {
                    if let Some(a) = item.take() { sst.spans.push((a, sst.pool.len() as u32)); }
                    cell = CellText::default();
                } else { cell.end(name.as_ref()); }
            }
            Ok(Event::Text(e)) if item.is_some() && cell.reading() => sst.pool.push_str(&e.xml10_content()),
            Ok(Event::GeneralRef(r)) if item.is_some() && cell.reading() => push_ref(&mut sst.pool, &r),
            Ok(Event::Eof) => break,
            Err(_) => {
                // Same recovery as xml_text; an unclosed element must not
                // leave the rest of the part unread.
                let pos = reader.buffer_position();
                if pos as usize >= xml.len() || pos == last_err { break; }
                last_err = pos;
                cell = CellText::default();
            }
            _ => {}
        }
        buf.clear();
    }
    sst
}

/// Append the text of a sheet, cell after cell in grid order: a shared string
/// cell (`t="s"`) is replaced by its string, so a label and the value next to
/// it stay side by side for the rules. Inline strings are joined like shared
/// ones; values and formulas are kept. Shared strings repeated across cells
/// are copied, so `out` stops at `cap` (true when it did).
fn sheet_text(xml: &[u8], sst: &SharedStrings, out: &mut String, cap: usize) -> bool {
    use quick_xml::events::Event;
    let xml = lossy_text(xml);
    let mut reader = xml_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut cell = CellText::default();
    let mut shared_cell = false;
    let (mut in_v, mut in_f) = (0usize, 0usize);
    let mut index = String::new();
    let mut last_err = u64::MAX;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    "c" => {
                        cell = CellText::default();
                        (in_v, in_f) = (0, 0);
                        shared_cell = e.attributes().flatten()
                            .any(|a| a.key.local_name().as_ref() == "t" && &*a.value == "s");
                    }
                    "v" => { in_v += 1; index.clear(); }
                    "f" => in_f += 1,
                    other => cell.start(other),
                }
            }
            Ok(Event::End(e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    "v" => {
                        in_v = in_v.saturating_sub(1);
                        if shared_cell {
                            if let Some(i) = string_index(&index) { out.push_str(sst.get(i)); }
                        }
                        out.push(' ');
                    }
                    "f" => { in_f = in_f.saturating_sub(1); out.push(' '); }
                    // A cell always ends its text, whatever it held.
                    "is" | "c" => if !out.ends_with(' ') { out.push(' ') },
                    other => cell.end(other),
                }
            }
            Ok(Event::Text(e)) => {
                if in_v > 0 && shared_cell { index.push_str(&e.xml10_content()); }
                else if in_v > 0 || in_f > 0 || cell.reading() { out.push_str(&e.xml10_content()); }
            }
            Ok(Event::GeneralRef(r)) => {
                if (in_v > 0 && !shared_cell) || in_f > 0 || cell.reading() { push_ref(out, &r); }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                let pos = reader.buffer_position();
                if pos as usize >= xml.len() || pos == last_err { break; }
                last_err = pos;
                cell = CellText::default();
                (in_v, in_f) = (0, 0);
            }
            _ => {}
        }
        buf.clear();
        if out.len() > cap {
            let mut at = cap;
            while !out.is_char_boundary(at) { at -= 1; }
            out.truncate(at);
            return true;
        }
    }
    false
}

/// Shared-string index of a cell: an integer, as Excel writes it, or an
/// integral number (`1.0`), as some writers do.
fn string_index(v: &str) -> Option<usize> {
    let v = v.trim();
    v.parse::<usize>().ok().or_else(|| {
        let f = v.parse::<f64>().ok()?;
        (f >= 0.0 && f.fract() == 0.0 && f < usize::MAX as f64).then_some(f as usize)
    })
}

/// Part names compared the way spreadsheet readers do: case-insensitive,
/// `\` as `/`, without a leading `/`.
fn part_key(name: &str) -> String {
    name.replace('\\', "/").trim_start_matches('/').to_lowercase()
}

/// `target` of a relationship, relative to the part at `from`.
fn resolve_part(from: &str, target: &str) -> String {
    let target = target.replace('\\', "/");
    let mut parts: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        let mut p: Vec<&str> = from.split('/').collect();
        p.pop();
        p
    };
    for seg in target.split('/') {
        match seg { "" | "." => {} ".." => { parts.pop(); } s => parts.push(s) }
    }
    parts.join("/")
}

/// `(Id, Type, Target)` of each relationship in a `.rels` part.
fn relationships(xml: &[u8]) -> Vec<(String, String, String)> {
    use quick_xml::events::Event;
    let xml = lossy_text(xml);
    let mut reader = xml_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut out = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) if e.local_name().as_ref() == "Relationship" => {
                let (mut id, mut ty, mut target) = (String::new(), String::new(), String::new());
                for a in e.attributes().flatten() {
                    let v = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map(|v| v.into_owned()).unwrap_or_default();
                    match a.key.local_name().as_ref() { "Id" => id = v, "Type" => ty = v, "Target" => target = v, _ => {} }
                }
                out.push((id, ty, target));
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Relationship ids of the sheets listed in `workbook.xml`, in workbook order.
fn workbook_sheet_ids(xml: &[u8]) -> Vec<String> {
    use quick_xml::events::Event;
    let xml = lossy_text(xml);
    let mut reader = xml_reader(xml.as_bytes());
    let mut buf = Vec::new();
    let mut ids = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) if e.local_name().as_ref() == "sheet" => {
                for a in e.attributes().flatten() {
                    // r:id (the plain sheetId attribute has another local name)
                    if a.key.local_name().as_ref() == "id" && a.key.prefix().is_some() {
                        ids.push(a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map(|v| v.into_owned()).unwrap_or_default());
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    ids
}

/// Key ordering `sheet2` before `sheet10`.
fn natural_key(name: &str) -> (String, u64) {
    let stem = name.trim_end_matches(".xml");
    let digits = stem.len() - stem.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let (head, num) = stem.split_at(stem.len() - digits);
    (head.to_string(), num.parse().unwrap_or(0))
}

/// The shared-strings part and the sheets of a workbook, as archive names:
/// found through the package relationships like a spreadsheet reader does
/// (workbook order, any folder, names compared case-insensitively), or by
/// their usual names when the relationships are missing.
fn workbook_parts(z: &mut zip::ZipArchive<Cursor<&[u8]>>, budget: &mut Budget)
    -> (Option<String>, Vec<String>) {
    use std::collections::{HashMap, HashSet};
    let names: HashMap<String, String> = z.file_names()
        .filter_map(|n| n.ok().map(|n| (part_key(&n), n.into_owned())))
        .collect();
    let mut read = |z: &mut zip::ZipArchive<Cursor<&[u8]>>, key: &str| -> Option<Vec<u8>> {
        let name = names.get(&part_key(key))?;
        z.by_name(name).ok().map(|f| budget.read(f))
    };
    let workbook = read(z, "_rels/.rels")
        .and_then(|x| relationships(&x).into_iter().find(|r| r.1.ends_with("/officeDocument")))
        .map(|r| resolve_part("", &r.2))
        .unwrap_or_else(|| "xl/workbook.xml".into());
    let (dir, file) = workbook.rsplit_once('/').unwrap_or(("", &workbook));
    let rels_path = if dir.is_empty() { format!("_rels/{file}.rels") } else { format!("{dir}/_rels/{file}.rels") };
    let rels = read(z, &rels_path).map(|x| relationships(&x)).unwrap_or_default();
    let order = read(z, &workbook).map(|x| workbook_sheet_ids(&x)).unwrap_or_default();

    // Archive name of a relationship's target, if the archive holds it.
    let actual = |target: &str| names.get(&part_key(&resolve_part(&workbook, target))).cloned();
    let is_sheet = |ty: &str| ty.ends_with("/worksheet") || ty.ends_with("/dialogsheet");
    // Indexed, so a hostile workbook listing many sheets stays linear; a
    // duplicated id keeps its last relationship, as spreadsheet readers do.
    let by_id: HashMap<&str, &(String, String, String)> =
        rels.iter().filter(|r| is_sheet(&r.1)).map(|r| (r.0.as_str(), r)).collect();
    let listed: HashSet<&str> = order.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut sheets: Vec<String> = order.iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .chain(rels.iter().filter(|r| is_sheet(&r.1) && !listed.contains(r.0.as_str())))
        .filter_map(|r| actual(&r.2))
        .filter(|n| seen.insert(n.clone()))
        .collect();
    // The usual name first, as calamine reads it, then the relationship.
    let mut sst = names.get(&part_key(&resolve_part(&workbook, "sharedStrings.xml"))).cloned()
        .or_else(|| rels.iter().filter(|r| r.1.ends_with("/sharedStrings")).find_map(|r| actual(&r.2)));
    // Missing relationships, or targets the archive does not hold: fall back
    // on the usual names.
    if sheets.is_empty() {
        let mut found: Vec<&String> = names.keys()
            .filter(|k| k.ends_with(".xml") && (k.contains("worksheets/") || k.contains("dialogsheets/")))
            .collect();
        found.sort_by_cached_key(|k| natural_key(k));
        sheets = found.into_iter().filter_map(|k| names.get(k).cloned()).collect();
    }
    if sst.is_none() {
        sst = names.iter().find(|(k, _)| k.ends_with("sharedstrings.xml")).map(|(_, n)| n.clone());
    }
    (sst, sheets)
}

/// Whether an archive entry starts like XML, judged on its first bytes only:
/// after any UTF-8 BOMs and blanks comes `<`, or nothing but blanks yet.
fn looks_like_xml(z: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> bool {
    let Ok(f) = z.by_name(name) else { return false };
    let mut head = Vec::with_capacity(512);
    let _ = f.take(512).read_to_end(&mut head);
    let mut head = head.as_slice();
    while let Some(rest) = head.strip_prefix(b"\xef\xbb\xbf") { head = rest; }
    matches!(head.iter().find(|b| !b.is_ascii_whitespace()), None | Some(b'<'))
}

/// Workbook text, read as XML within the budget: the shared strings first,
/// then each sheet with its shared-string cells resolved. No spreadsheet
/// library: building cell ranges amplifies memory far beyond the archive (a
/// cell pair at A1 and XFD1048576 allocates a dense range, a declared string
/// count is reserved up front), which no budget on the decompressed bytes can
/// bound. The sheet text is capped too (twice the budget), since a shared
/// string can be referenced by any number of cells. When the budget or the cap cuts
/// the sheets short, the shared strings already read are scanned as they are,
/// so nothing paid for is left unscanned.
fn xlsx_text(data: &[u8], budget: &mut Budget) -> String {
    let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) else { return String::new() };
    // Resolved cells repeat their shared strings: twice the budget leaves a
    // workbook that cites each string a few times whole.
    let cap = 2 * budget.left as usize;
    let (sst_name, sheets) = workbook_parts(&mut z, budget);
    let sst_name = sst_name.filter(|n| looks_like_xml(&mut z, n));
    let sst = match sst_name.and_then(|n| z.by_name(&n).ok()) {
        Some(f) => shared_strings(&budget.read(f)),
        None => SharedStrings::default(),
    };
    let mut out = String::new();
    for name in sheets {
        if budget.left == 0 { budget.truncated = Some(Truncation::Size); break; }
        // A relationship can point at anything: a part that is not XML is not
        // a sheet and must not drain the budget meant for the real ones.
        if !looks_like_xml(&mut z, &name) { continue; }
        if let Ok(f) = z.by_name(&name) {
            if sheet_text(&budget.read(f), &sst, &mut out, cap) {
                budget.truncated = Some(Truncation::Size);
                break;
            }
        }
    }
    // Cut short: every shared string already read is scanned too, once, on
    // top of the capped sheet text (at most the size of what was read).
    if budget.truncated.is_some() {
        out.reserve(sst.pool.len() + sst.spans.len());
        for i in 0..sst.spans.len() {
            out.push_str(sst.get(i));
            out.push(' ');
        }
    }
    out
}

fn extract_text(ext: &str, data: &[u8], budget: &mut Budget) -> String {
    match ext {
        // PDF body extraction is intentionally NOT done in the Rust MVP
        // (no mature crate matching pdfminer). Returns empty → no PDF body
        // findings; filename hits still fire.
        "pdf" => String::new(),
        "docx" => zip_entry_text(data, "word/document.xml", budget),
        "pptx" => pptx_text(data, budget),
        "xlsx" => xlsx_text(data, budget),
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
    let mut truncated_files: usize = 0;  // documents cut at the decompression budget

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
        // Bounded too: the file may have grown since its size was checked
        // during the walk; past max_size_mb it is skipped, as it would have
        // been then.
        let read_ok = match client.open_with(rel, SmbOpenOptions::default().read(true)) {
            Ok(fh) => fh.take(max_bytes + 1).read_to_end(&mut buf).is_ok(),
            Err(_) => false,
        };
        if !read_ok || buf.len() as u64 > max_bytes { continue; }
        let mut budget = Budget::new(MAX_DECOMPRESSED_BYTES);
        let text = extract_text(&ext, &buf, &mut budget);
        let tgt = unc(&host, &share, rel);
        let base = rel.rsplit('/').next().unwrap_or(rel).to_string();
        if let Some(cut) = budget.truncated {
            truncated_files += 1;
            let limit_mb = MAX_DECOMPRESSED_BYTES / (1024 * 1024);
            let (desc, ev) = match cut {
                Truncation::Size => (
                    format!("Le contenu décompressé dépasse {limit_mb} Mo : seule la première partie a été analysée."),
                    serde_json::json!({"file": tgt, "limit_mb": limit_mb})),
                Truncation::Slides => (
                    format!("La présentation compte plus de {MAX_SLIDES} diapositives : seules les premières ont été analysées."),
                    serde_json::json!({"file": tgt, "variant": "slides", "max_slides": MAX_SLIDES})),
            };
            emit(&finding("info", format!("Document tronqué : {base}"), desc, &tgt, "smb_truncated", ev));
        }
        if text.is_empty() { continue; }
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
        "truncated_files": truncated_files,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(parts: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in parts {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn xml_text_does_not_glue_across_tags() {
        assert_eq!(xml_text(b"<t>foo</t><t>&amp;bar</t>"), "foo &bar ");
        assert_eq!(xml_text(b"<t>a&amp;</t><t>b</t>"), "a& b ");
        assert_eq!(xml_text(b"<t>tok=</t><t>&#97;bc</t>"), "tok= abc ");
    }

    #[test]
    fn xml_text_reads_past_a_malformed_node() {
        let t = xml_text(b"<t>R&D password=hunter22</t><t>after</t>");
        assert!(t.contains("password=hunter22"), "{t:?}");
        assert!(t.contains("after"), "{t:?}");
        let t = xml_text(b"<t>R&D password=hunter22; x</t>");
        assert!(t.contains("R&D password=hunter22; x"), "{t:?}");
        let t = xml_text(b"<t>a\xffb</t><t>zz</t>");
        assert!(t.contains("zz"), "{t:?}");
    }

    #[test]
    fn xml_text_keeps_entities_inside_the_word() {
        let t = xml_text(b"<p><t>pass&amp;word=s&#51;cret</t><t>next</t></p>");
        assert!(t.contains("pass&word=s3cret"), "{t:?}");
        assert!(t.contains("next"), "{t:?}");
    }

    #[test]
    fn docx_body_is_read() {
        let doc = zip_of(&[("word/document.xml",
            "<w:document><w:body><w:p><w:r><w:t>AKIAIOSFODNN7EXAMPLE</w:t></w:r></w:p></w:body></w:document>")]);
        assert!(extract_text("docx", &doc, &mut Budget::new(MAX_DECOMPRESSED_BYTES)).contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn pptx_slides_are_read() {
        let deck = zip_of(&[
            ("ppt/slides/slide1.xml", "<p:sld><a:t>first slide</a:t></p:sld>"),
            ("ppt/notesSlides/notesSlide1.xml", "<p:notes><a:t>not a slide</a:t></p:notes>"),
        ]);
        let t = extract_text("pptx", &deck, &mut Budget::new(MAX_DECOMPRESSED_BYTES));
        assert!(t.contains("first slide"), "{t:?}");
        assert!(!t.contains("not a slide"), "{t:?}");
    }

    fn workbook(sheet_xml: &str) -> Vec<u8> {
        zip_of(&[
            ("[Content_Types].xml", r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#),
            ("_rels/.rels", r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#),
            ("xl/workbook.xml", r#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#),
            ("xl/worksheets/sheet1.xml", sheet_xml),
        ])
    }

    #[test]
    fn xlsx_cells_are_read() {
        let book = workbook(r#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>password=hunter2</t></is></c><c r="B1"><v>42</v></c></row></sheetData></worksheet>"#);
        let t = extract_text("xlsx", &book, &mut Budget::new(MAX_DECOMPRESSED_BYTES));
        assert!(t.contains("password=hunter2"), "{t:?}");
        assert!(t.contains("42"), "{t:?}");
    }

    const SMALL: u64 = 1024 * 1024;

    fn bomb_text() -> String {
        // ~8 MB once inflated, a few KB compressed.
        format!("password=hunter2 {}", "A ".repeat(4 * 1024 * 1024))
    }

    #[test]
    fn docx_bomb_is_cut_at_the_budget() {
        let body = format!("<w:document><w:body><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:body></w:document>", bomb_text());
        let doc = zip_of(&[("word/document.xml", &body)]);
        assert!(doc.len() < SMALL as usize / 10, "fixture not compressed: {}", doc.len());
        let mut budget = Budget::new(SMALL);
        let t = extract_text("docx", &doc, &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.len() as u64 <= SMALL, "{}", t.len());
        assert!(t.contains("password=hunter2"));
    }

    #[test]
    fn pptx_bomb_is_cut_at_the_budget() {
        let slide = format!("<p:sld><a:t>{}</a:t></p:sld>", bomb_text());
        let deck = zip_of(&[("ppt/slides/slide1.xml", &slide), ("ppt/slides/slide2.xml", &slide)]);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("pptx", &deck, &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.len() as u64 <= SMALL, "{}", t.len());
        assert!(t.contains("password=hunter2"));
    }

    #[test]
    fn xlsx_bomb_is_cut_at_the_budget() {
        let sheet = format!(r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{}</t></is></c></row></sheetData></worksheet>"#, bomb_text());
        let book = workbook(&sheet);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.len() as u64 <= SMALL, "{}", t.len());
        assert!(t.contains("password=hunter2"));
    }

    #[test]
    fn xlsx_shared_strings_are_read() {
        // Cell text lives in the shared strings, the sheet only holds indexes.
        let mut book = workbook(r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>"#);
        book = {
            let mut z = zip::ZipArchive::new(Cursor::new(book)).unwrap();
            let mut parts: Vec<(String, String)> = Vec::new();
            for i in 0..z.len() {
                let mut f = z.by_index(i).unwrap();
                let mut body = String::new();
                f.read_to_string(&mut body).unwrap();
                parts.push((f.name().unwrap().into_owned(), body));
            }
            parts.push(("xl/sharedStrings.xml".into(),
                r#"<sst uniqueCount="1"><si><t>token=ghp_0123456789</t></si></sst>"#.into()));
            let refs: Vec<(&str, &str)> = parts.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            zip_of(&refs)
        };
        let t = extract_text("xlsx", &book, &mut Budget::new(MAX_DECOMPRESSED_BYTES));
        assert!(t.contains("token=ghp_0123456789"), "{t:?}");
    }

    #[test]
    fn xlsx_amplifiers_stay_small() {
        // A dense-range pair of cells and a lying shared-string count made
        // calamine allocate gigabytes from a 2 KB file.
        let book = workbook(r#"<worksheet><dimension ref="A1:XFD1048576"/><sheetData><row r="1"><c r="A1"><v>1</v></c></row><row r="1048576"><c r="XFD1048576"><v>2</v></c></row></sheetData></worksheet>"#);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert!(t.len() < 1024, "{}", t.len());
        assert_eq!(budget.truncated, None);
    }

    #[test]
    fn invalid_utf8_does_not_grow_the_text() {
        let mut body = b"<w:t>password=hunter2 ".to_vec();
        body.extend(std::iter::repeat(0xFFu8).take(100_000));
        body.extend(b"</w:t>");
        let t = xml_text(&body);
        assert!(t.len() <= body.len(), "{} > {}", t.len(), body.len());
        assert!(t.contains("password=hunter2"));
    }

    #[test]
    fn many_small_nodes_do_not_grow_the_text() {
        let body = "<p>".to_string() + &"a<b/>".repeat(100_000) + "</p>";
        let t = xml_text(body.as_bytes());
        assert!(t.len() <= body.len(), "{} > {}", t.len(), body.len());
    }

    #[test]
    fn pptx_slide_cap_is_reported_as_such() {
        let names: Vec<String> = (0..=MAX_SLIDES).map(|i| format!("ppt/slides/slide{i}.xml")).collect();
        let parts: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "<p:sld/>")).collect();
        let mut budget = Budget::new(SMALL);
        extract_text("pptx", &zip_of(&parts), &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Slides));
    }

    #[test]
    fn latin1_password_stays_whole() {
        let rules = secret_rules();
        for text in [&b"password=Soci\xe9t\xe92024\n"[..], &b"mot_de_passe: \xc9t\xe92024!\n"[..]] {
            let plain = extract_text("txt", text, &mut Budget::new(SMALL));
            assert!(scan_text(&plain, &rules, &[]).iter().any(|h| h.0 == "password_assignment"), "{plain:?}");
            let mut xml = b"<w:t>".to_vec();
            xml.extend_from_slice(text);
            xml.extend_from_slice(b"</w:t>");
            let t = xml_text(&xml);
            assert!(scan_text(&t, &rules, &[]).iter().any(|h| h.0 == "password_assignment"), "{t:?}");
        }
    }

    /// A workbook as Excel writes it: cell text in the shared strings, cells
    /// holding indexes.
    fn shared_workbook(sst: &str, sheet: &str) -> Vec<u8> {
        zip_of(&[("xl/sharedStrings.xml", sst), ("xl/worksheets/sheet1.xml", sheet)])
    }

    fn xlsx(book: &[u8]) -> String {
        extract_text("xlsx", book, &mut Budget::new(MAX_DECOMPRESSED_BYTES))
    }

    #[test]
    fn xlsx_rich_text_runs_are_one_string() {
        let book = shared_workbook(
            r#"<sst><si><r><t>AKIAIOSFOD</t></r><r><rPr><b/></rPr><t>NN7EXAMPLE</t></r><rPh><t>ignored</t></rPh></si></sst>"#,
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><r><t>pass</t></r><r><rPr><i/></rPr><t>word=Secret2024</t></r></is></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        assert!(t.contains("AKIAIOSFODNN7EXAMPLE"), "{t:?}");
        assert!(t.contains("password=Secret2024"), "{t:?}");
        assert!(!t.contains("ignored"), "{t:?}");
    }

    #[test]
    fn xlsx_indented_rich_text_is_one_string() {
        let book = shared_workbook(
            "<sst>\n  <si>\n    <r><t>AKIAIOSFOD</t></r>\n    <r><t>NN7EXAMPLE</t></r>\n  </si>\n</sst>",
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        assert!(t.contains("AKIAIOSFODNN7EXAMPLE"), "{t:?}");
    }

    #[test]
    fn xlsx_label_and_value_stay_side_by_side() {
        // The label is one shared string used on two rows; the values follow
        // it in the grid (one shared, one a number).
        let book = shared_workbook(
            r#"<sst><si><t>password:</t></si><si><t>Pass2024!a</t></si></sst>"#,
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row><row r="2"><c r="A2" t="s"><v>0</v></c><c r="B2"><v>12345678</v></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        let hits = scan_text(&t, &secret_rules(), &[]);
        assert_eq!(hits.iter().filter(|h| h.0 == "password_assignment").count(), 2, "{t:?}");
    }

    #[test]
    fn xlsx_unclosed_phonetic_reading_does_not_hide_the_rest() {
        let book = shared_workbook(
            r#"<sst><si><rPh><t>x</t></si><si><t>password=AfterRph24</t></si></sst>"#,
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>1</v></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        assert!(t.contains("password=AfterRph24"), "{t:?}");
    }

    #[test]
    fn xlsx_repeated_shared_string_is_capped() {
        // One long string referenced by many cells must not amplify memory.
        let sst = format!("<sst><si><t>{}</t></si></sst>", "A".repeat(64 * 1024));
        let cells: String = (0..1000).map(|i| format!(r#"<c r="A{i}" t="s"><v>0</v></c>"#)).collect();
        let sheet = format!("<worksheet><sheetData><row>{cells}</row></sheetData></worksheet>");
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &shared_workbook(&sst, &sheet), &mut budget);
        // The capped sheet text, then the shared strings once.
        assert!(t.len() as u64 <= 2 * SMALL + 64 * 1024 + 1, "{}", t.len());
        assert_eq!(budget.truncated, Some(Truncation::Size));
    }

    #[test]
    fn xlsx_shared_strings_come_first_when_the_budget_runs_out() {
        let sheet = format!(r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData>{}"#,
                            "x".repeat(SMALL as usize));
        let book = zip_of(&[
            ("xl/worksheets/sheet1.xml", &sheet),
            ("xl/sharedStrings.xml", "<sst><si><t>password=hunter2</t></si></sst>"),
        ]);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert!(t.contains("password=hunter2"), "{t:?}");
        assert_eq!(budget.truncated, Some(Truncation::Size));
    }

    #[test]
    fn xlsx_strings_already_read_are_scanned_when_the_budget_runs_out() {
        // The shared strings fit, the sheet does not: the string referenced
        // past the part of the sheet that was read is still scanned.
        let rows: String = (0..60_000).map(|i| format!(r#"<row r="{i}"><c r="A{i}"><v>{i}</v></c></row>"#)).collect();
        let sheet = format!(r#"<worksheet><sheetData>{rows}<row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#);
        let book = shared_workbook("<sst><si><t>AKIAIOSFODNN7EXAMPLE</t></si></sst>", &sheet);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.contains("AKIAIOSFODNN7EXAMPLE"), "{}", t.len());
    }

    #[test]
    fn xlsx_shared_strings_over_budget_are_scanned() {
        let sst = format!("<sst><si><t>password=hunter2</t></si><si><t>{}</t></si></sst>", "x".repeat(2 * SMALL as usize));
        let book = shared_workbook(&sst, r#"<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert!(t.contains("password=hunter2"), "{}", t.len());
    }

    #[test]
    fn xlsx_parts_are_found_through_the_relationships() {
        // Workbook in another folder, odd case and a backslash in the names,
        // a dialog sheet: found the way a spreadsheet reader finds them.
        let book = zip_of(&[
            ("_rels/.rels", r#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="excel/workbook.xml"/></Relationships>"#),
            ("excel/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet name="B" sheetId="2" r:id="rId2"/><sheet name="A" sheetId="1" r:id="rId1"/></sheets></workbook>"#),
            ("excel/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="Data/one.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/dialogsheet" Target="/excel/Dlg/two.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="SharedStrings.xml"/></Relationships>"#),
            ("excel\\sharedstrings.XML", "<sst><si><t>password:</t></si></sst>"),
            ("EXCEL/data/ONE.xml", r#"<worksheet><sheetData><row><c><v>12345678</v></c></row></sheetData></worksheet>"#),
            ("excel/Dlg/two.xml", r#"<dialogsheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></dialogsheet>"#),
        ]);
        let t = xlsx(&book);
        // Workbook order: the dialog sheet (label) comes before the data.
        assert!(scan_text(&t, &secret_rules(), &[]).iter().any(|h| h.0 == "password_assignment"), "{t:?}");
    }

    #[test]
    fn xlsx_sheets_without_relationships_are_in_natural_order() {
        let mut parts: Vec<(String, String)> = (1..=10)
            .map(|i| (format!("xl/worksheets/sheet{i}.xml"),
                      format!(r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>filler{i}</t></is></c></row></sheetData></worksheet>"#)))
            .collect();
        parts[8].1 = r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password:</t></is></c></row></sheetData></worksheet>"#.into();
        parts[9].1 = r#"<worksheet><sheetData><row><c><v>12345678</v></c></row></sheetData></worksheet>"#.into();
        let refs: Vec<(&str, &str)> = parts.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let t = xlsx(&zip_of(&refs));
        assert!(scan_text(&t, &secret_rules(), &[]).iter().any(|h| h.0 == "password_assignment"), "{t:?}");
    }

    #[test]
    fn xlsx_cells_never_glue() {
        // Inline string then a value, a formula then its value, text directly
        // in a cell (malformed): each cell ends its text.
        let book = shared_workbook("<sst/>", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>AKIAIOSFOD</t></is></c><c><v>NN7EXAMPLE</v></c><c><f>AKIAIOSFOD</f><v>NN7EXAMPLE</v></c><c><t>AKIAIOSFOD</t></c><c><t>NN7EXAMPLE</t></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        assert!(!t.contains("AKIAIOSFODNN7EXAMPLE"), "{t:?}");
    }

    #[test]
    fn xlsx_empty_shared_strings_keep_their_index() {
        let book = shared_workbook(r#"<sst><si/><si></si><si><t>password=hunter2</t></si></sst>"#,
            r#"<worksheet><sheetData><row><c t="s"><v> 2 </v></c><c t="s"><v>2.0</v></c></row></sheetData></worksheet>"#);
        let t = xlsx(&book);
        assert_eq!(t.matches("password=hunter2").count(), 2, "{t:?}");
    }

    #[test]
    fn xlsx_cap_cuts_on_a_character_boundary() {
        let sst = format!("<sst><si><t>{}</t></si></sst>", "é".repeat(40_000));
        let cells: String = (0..100).map(|_| r#"<c t="s"><v>0</v></c>"#).collect();
        let sheet = format!("<worksheet><sheetData><row>{cells}</row></sheetData></worksheet>");
        let mut budget = Budget::new(SMALL + 1);
        let t = extract_text("xlsx", &shared_workbook(&sst, &sheet), &mut budget);
        assert!(t.len() as u64 <= 2 * (SMALL + 1) + 80_000 + 1, "{}", t.len());
        assert_eq!(budget.truncated, Some(Truncation::Size));
    }

    #[test]
    fn xlsx_with_large_shared_strings_within_the_budget_is_not_truncated() {
        // Shared strings over half the budget, all referenced: everything fits.
        let big = "x".repeat(SMALL as usize * 3 / 5);
        let sst = format!("<sst><si><t>{big}</t></si><si><t>password:</t></si></sst>");
        let sheet = r#"<worksheet><sheetData><row><c t="s"><v>0</v></c><c t="s"><v>1</v></c><c><v>12345678</v></c></row></sheetData></worksheet>"#;
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &shared_workbook(&sst, sheet), &mut budget);
        assert_eq!(budget.truncated, None);
        assert!(scan_text(&t, &secret_rules(), &[]).iter().any(|h| h.0 == "password_assignment"));
    }

    #[test]
    fn xlsx_capped_sheets_still_scan_every_shared_string() {
        let long = "x".repeat(64 * 1024);
        let cells: String = (0..40).map(|_| r#"<c t="s"><v>0</v></c>"#).collect();
        let sst = format!("<sst><si><t>{long}</t></si><si><t>AKIAIOSFODNN7EXAMPLE</t></si></sst>");
        let sheet = format!(r#"<worksheet><sheetData><row>{cells}</row><row><c t="s"><v>1</v></c></row></sheetData></worksheet>"#);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &shared_workbook(&sst, &sheet), &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn xlsx_many_listed_sheets_stay_linear() {
        let n = 20_000;
        let sheets: String = (0..n).map(|i| format!(r#"<sheet name="s{i}" sheetId="{i}" r:id="r{i}"/>"#)).collect();
        let rels: String = (0..n).map(|i| format!(r#"<Relationship Id="r{i}" Type="x/worksheet" Target="worksheets/s{i}.xml"/>"#)).collect();
        let wb = format!(r#"<workbook xmlns:r="r"><sheets>{sheets}</sheets></workbook>"#);
        let rels = format!("<Relationships>{rels}</Relationships>");
        let book = zip_of(&[("xl/workbook.xml", &wb), ("xl/_rels/workbook.xml.rels", &rels)]);
        let t0 = std::time::Instant::now();
        xlsx(&book);
        assert!(t0.elapsed().as_secs() < 5, "{:?}", t0.elapsed());
    }

    #[test]
    fn xlsx_missing_targets_fall_back_on_usual_names() {
        // The relationships point at parts that are not there; the usual
        // names are: read them, as a spreadsheet reader would.
        let book = zip_of(&[
            ("xl/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet r:id="rId1"/><sheet r:id="rId2"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="gone.xml"/><Relationship Id="rId2" Type="x/worksheet" Target="../xl/./worksheets/../worksheets/sheet1.xml"/><Relationship Id="rId2" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId3" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId9" Type="x/sharedStrings" Target="strings.xml"/></Relationships>"#),
            ("xl/sharedStrings.xml", "<sst><si><t>password=hunter2</t></si></sst>"),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#),
        ]);
        let t = xlsx(&book);
        // Listed once although three relationships lead to it.
        assert_eq!(t.matches("password=hunter2").count(), 1, "{t:?}");
        let gone = zip_of(&[
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="gone.xml"/></Relationships>"#),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password=hunter2</t></is></c></row></sheetData></worksheet>"#),
        ]);
        assert!(xlsx(&gone).contains("password=hunter2"));
    }

    #[test]
    fn xlsx_sheets_missing_from_the_workbook_are_read_after_it() {
        let book = zip_of(&[
            ("xl/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet r:id="rId1"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/a.xml"/><Relationship Id="rId2" Type="x/worksheet" Target="worksheets/b.xml"/></Relationships>"#),
            ("xl/worksheets/a.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password:</t></is></c></row></sheetData></worksheet>"#),
            ("xl/worksheets/b.xml", r#"<worksheet><sheetData><row><c><v>12345678</v></c></row></sheetData></worksheet>"#),
        ]);
        let t = xlsx(&book);
        assert!(scan_text(&t, &secret_rules(), &[]).iter().any(|h| h.0 == "password_assignment"), "{t:?}");
    }

    #[test]
    fn xlsx_relationship_to_a_large_non_sheet_does_not_drain_the_budget() {
        let blob = "\u{1}".repeat(SMALL as usize * 2);
        let book = zip_of(&[
            ("xl/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet r:id="rId1"/><sheet r:id="rId2"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="media/blob.bin"/><Relationship Id="rId2" Type="x/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#),
            ("xl/media/blob.bin", &blob),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password=hunter2</t></is></c></row></sheetData></worksheet>"#),
        ]);
        let mut budget = Budget::new(SMALL);
        assert!(extract_text("xlsx", &book, &mut budget).contains("password=hunter2"));
        assert_eq!(budget.truncated, None);
    }

    #[test]
    fn xlsx_usual_shared_strings_part_wins_over_a_wrong_relationship() {
        let book = zip_of(&[
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="x/sharedStrings" Target="worksheets/sheet1.xml"/></Relationships>"#),
            ("xl/sharedStrings.xml", "<sst><si><t>password=hunter2</t></si></sst>"),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#),
        ]);
        assert!(xlsx(&book).contains("password=hunter2"));
    }

    #[test]
    fn xlsx_odd_but_valid_xml_starts_are_read() {
        for head in [" ".repeat(600), "\n".repeat(600), "\u{feff}\u{feff}".to_string(), "<!-- c -->".to_string()] {
            let sheet = format!(r#"{head}<worksheet><sheetData><row><c t="inlineStr"><is><t>password=hunter2</t></is></c></row></sheetData></worksheet>"#);
            let book = zip_of(&[("xl/worksheets/sheet1.xml", &sheet)]);
            assert!(xlsx(&book).contains("password=hunter2"), "{:?}", &head[..head.len().min(12)]);
        }
    }

    #[test]
    fn xlsx_shared_strings_relationship_to_a_non_xml_part_is_ignored() {
        let blob = "\u{1}".repeat(SMALL as usize * 2);
        let book = zip_of(&[
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="x/sharedStrings" Target="media/blob.bin"/></Relationships>"#),
            ("xl/media/blob.bin", &blob),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password=hunter2</t></is></c></row></sheetData></worksheet>"#),
        ]);
        let mut budget = Budget::new(SMALL);
        assert!(extract_text("xlsx", &book, &mut budget).contains("password=hunter2"));
    }

    #[test]
    fn xlsx_duplicated_id_keeps_its_last_relationship() {
        let book = zip_of(&[
            ("xl/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet r:id="rId1"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/a.xml"/><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/b.xml"/></Relationships>"#),
            ("xl/worksheets/a.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>first</t></is></c></row></sheetData></worksheet>"#),
            ("xl/worksheets/b.xml", r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>password=hunter2</t></is></c></row></sheetData></worksheet>"#),
        ]);
        let t = xlsx(&book);
        // The sheet is the last relationship with its id, as calamine reads it.
        assert!(t.contains("password=hunter2") && !t.contains("first"), "{t:?}");
    }

    #[test]
    fn xlsx_second_shared_strings_relationship_is_tried() {
        let book = zip_of(&[
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="x/sharedStrings" Target="gone.xml"/><Relationship Id="rId3" Type="x/sharedStrings" Target="strings.xml"/></Relationships>"#),
            ("xl/strings.xml", "<sst><si><t>password=hunter2</t></si></sst>"),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#),
        ]);
        assert!(xlsx(&book).contains("password=hunter2"));
    }

    #[test]
    fn xlsx_shared_strings_added_on_truncation_stay_apart() {
        let filler: String = (0..60_000).map(|i| format!(r#"<row><c><v>{i}</v></c></row>"#)).collect();
        let sheet = format!("<worksheet><sheetData>{filler}</sheetData></worksheet>");
        let book = shared_workbook("<sst><si><t>AKIAIOSFOD</t></si><si><t>NN7EXAMPLE</t></si></sst>", &sheet);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &book, &mut budget);
        assert_eq!(budget.truncated, Some(Truncation::Size));
        assert!(t.contains("AKIAIOSFOD NN7EXAMPLE"), "{}", &t[t.len().saturating_sub(40)..]);
    }

    #[test]
    fn xlsx_resolved_text_may_reach_twice_the_budget() {
        // Under the budget once inflated, but each shared string cited five
        // times: the resolved text is 1.5 times the budget and stays whole.
        let long = "x".repeat(SMALL as usize * 3 / 10);
        let sst = format!("<sst><si><t>{long}</t></si><si><t>password:</t></si></sst>");
        let cells: String = (0..5).map(|_| r#"<c t="s"><v>0</v></c>"#).collect();
        let sheet = format!(r#"<worksheet><sheetData><row>{cells}</row><row><c t="s"><v>1</v></c><c><v>12345678</v></c></row></sheetData></worksheet>"#);
        let mut budget = Budget::new(SMALL);
        let t = extract_text("xlsx", &shared_workbook(&sst, &sheet), &mut budget);
        assert_eq!(budget.truncated, None);
        assert!(t.contains("password: 12345678"), "{}", &t[t.len().saturating_sub(40)..]);
    }

    #[test]
    fn documents_within_the_budget_are_not_truncated() {
        let mut budget = Budget::new(SMALL);
        let doc = zip_of(&[("word/document.xml", "<w:t>AKIAIOSFODNN7EXAMPLE</w:t>")]);
        extract_text("docx", &doc, &mut budget);
        assert_eq!(budget.truncated, None);
    }
}
