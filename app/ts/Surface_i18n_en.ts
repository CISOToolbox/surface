if (typeof _registerTranslations === "function") {
    _registerTranslations("en", {
        "ai.error": "Error: {msg}",
        "menu_file":              "File",
        "menu.import_hosts":      "Import hosts",
        "menu.export_report":     "Export report",
        "feature.coming_soon":    "Feature coming soon",
        // ── Toolbar / nav ──────────────────────────────────
        "nav.monitored":   "Monitoring",
        "nav.hosts":       "Hosts",
        "nav.jobs":        "Scans",
        "nav.findings":    "Findings",
        "nav.measures":    "Action Plan",
        "nav.audit":"Audit Log",
        "audit.title":"Audit Log",
        "audit.search":"Search...",
        "audit.empty":"No audit entries",
        "audit.entries":"entries",
        "audit.col_date":"Date",
        "audit.col_user":"User",
        "audit.col_action":"Action",
        "audit.col_target":"Target",
        "audit.col_details":"Details",
        "nav.help_section":"HELP",
        "nav.help_methodo":"Methodology",
        "nav.help_usage":  "Usage",
        "help.tab_methodo":"ASM Methodology",
        "help.tab_usage":  "Usage guide",

        // ── Help panel content (rendered via data-i18n-html) ─────
        "help.methodo_html":
            '<h1 class="heading-blue">Surface — Attack Surface Management</h1>' +
            '<p class="text-muted">Continuous discovery, mapping and monitoring of your external attack surface.</p>' +
            '<h2>What is ASM?</h2>' +
            '<p><strong>Attack Surface Management</strong> is the discipline of identifying, inventorying and continuously monitoring all exposed assets of an organization — domains, subdomains, hosts, IPs, services, TLS certificates, HTTP endpoints — from an external attacker\'s viewpoint. The goal is to detect, before attackers do, the <strong>forgotten, misconfigured or vulnerable assets</strong> that become entry points.</p>' +
            '<div class="help-tip"><strong>Why it is critical:</strong> 70% of incidents documented by ANSSI and Mandiant in 2024-2025 had as entry point an asset the organization did not know it owned, or thought was decommissioned (shadow IT, an old marketing site, a forgotten dev zone, an abandoned S3 bucket, a subdomain delegated to a dead SaaS).</div>' +
            '<h2>The 5 pillars of ASM in Surface</h2>' +
            '<h3>1. Passive discovery (without touching the target)</h3>' +
            '<p>Surface leverages several public sources to inventory assets without generating any traffic to the target:</p>' +
            '<ul>' +
                '<li><strong>Certificate Transparency (crt.sh)</strong> — every publicly issued TLS certificate since 2018 is logged in CT. The <code>ct_logs</code> scanner queries crt.sh to extract all hostnames that ever had a cert.</li>' +
                '<li><strong>SAN pivoting</strong> — during a host\'s TLS scan, Subject Alternative Names in the certificate reveal siblings sharing the same cert.</li>' +
                '<li><strong>Email records</strong> — MX/SPF/DMARC/DKIM analysis exposes mail providers in use and the domain\'s email posture.</li>' +
            '</ul>' +
            '<h3>2. Active discovery</h3>' +
            '<ul>' +
                '<li><strong>DNS brute-force</strong> — 1460+ common keywords (generated via compound permutations) resolved in parallel with wildcard detection to filter false positives.</li>' +
                '<li><strong>IP range discovery</strong> — nmap ping sweep on CIDR ranges to find truly active hosts.</li>' +
                '<li><strong>Reverse DNS</strong> — PTR record extraction on discovered IPs.</li>' +
                '<li><strong>Typosquatting</strong> — generation of lookalike variants (omission, transposition, QWERTY neighbors, alternate TLDs — cap tunable per domain, 80 by default) with optional CT-log correlation, to detect domains registered by third parties.</li>' +
            '</ul>' +
            '<h3>3. Posture assessment</h3>' +
            '<ul>' +
                '<li><strong>Port scans</strong> via nmap (quick/standard/deep profiles)</li>' +
                '<li><strong>TLS analysis</strong>: validity, chain, expiry, self-signed, hostname mismatch</li>' +
                '<li><strong>TLS grade (A-F)</strong> — probes TLS 1.0/1.1/1.2/1.3 and SSL 3.0, inspects the negotiated cipher, flags weak suites (RC4, 3DES, NULL, EXPORT, MD5). A single letter grade captures the distance to Mozilla\'s recommended baseline.</li>' +
                '<li><strong>Security headers grade (A-F)</strong> — grades HSTS, Content-Security-Policy (penalized if it allows <code>unsafe-inline/eval</code>), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. A Mozilla Observatory-lite check with zero external dependency.</li>' +
                '<li><strong>CVE matching NVD + EPSS + KEV</strong> — the <code>cve_lookup</code> scanner consumes nuclei\'s wappalyzer tech-detect output, queries the NVD 2.0 API, enriches each CVE with its EPSS probability and a CISA KEV flag. Unversioned detections are dropped to avoid noise.</li>' +
                '<li><strong>Nuclei DAST</strong>: 12 000+ community templates from ProjectDiscovery, rate-limitable to avoid blacklisting</li>' +
            '</ul>' +
            '<h3>4. Specific risk detection</h3>' +
            '<ul>' +
                '<li><strong>Subdomain takeover</strong> — 25 vulnerable SaaS services (S3, GitHub Pages, Heroku, Azure, Vercel, Shopify, Fastly, ...) with CNAME matching + HTTP fingerprint + NXDOMAIN detection</li>' +
                '<li><strong>Dangling DNS records</strong> — CNAMEs pointing to abandoned resources</li>' +
                '<li><strong>Sensitive exposed ports</strong> — databases, RDP, SSH without strong authentication, etc.</li>' +
            '</ul>' +
            '<h3>5. Secrets, misconfigurations and leaks</h3>' +
            '<p>A fourth, post-discovery phase inspects known assets for directly exploitable leaks:</p>' +
            '<ul>' +
                '<li><strong>Sensitive file exposure (<code>sensitive_files</code>)</strong> — probes 28 critical paths (<code>/.git/config</code>, <code>/.env</code>, <code>/backup.sql</code>, <code>/wp-config.php</code>, <code>/.aws/credentials</code>, <code>/phpinfo.php</code>, <code>/docker-compose.yml</code>, <code>/swagger.json</code>…) and only flags HTTP 200 responses whose body matches the expected signature (low false-positive rate).</li>' +
                '<li><strong>JS bundle analysis (<code>js_analysis</code>)</strong> — downloads every <code>&lt;script src&gt;</code> (capped at 512 KB × 20 files) on the target domain and greps 12 secret patterns: AWS Access/Secret Key, Google API, Slack webhook, Stripe live, Sentry DSN, JWT, private IP, S3/Azure/GCS buckets, Firebase. Critical/high secrets are stored masked (<code>abcd…wxyz</code>) so that we never re-leak them in the database.</li>' +
                '<li><strong>Cloud bucket enumeration (<code>cloud_buckets</code>)</strong> — generates 80 candidate names (<em>static-/cdn-/backup-</em> prefixes, <em>-prod/-staging/-dev/-backup</em> suffixes) and probes S3, Azure Blob, GCS, DigitalOcean Spaces. A 200 with <code>&lt;ListBucketResult&gt;</code> is flagged high (listable content), a 403 medium (bucket exists but ACLs are OK).</li>' +
            '</ul>' +
            '<div class="help-tip"><strong>Anti-SSRF:</strong> all of these scanners go through <code>_resolve_safe_target</code> (blocklist: loopback, sensitive RFC1918, cloud metadata, docker siblings) and re-validate each secondary URL (JS scripts, redirects) before fetching. A hostile HTML page cannot pivot <code>js_analysis</code> onto an internal resource.</div>' +
            '<h2>Severity model</h2>' +
            '<p>Every finding carries one of 5 severity levels, using the suite-wide harmonized color scale (identical tint / fill / solid shades across all modules):</p>' +
            '<table><thead><tr><th>Level</th><th>Meaning</th><th>Handling expectation</th></tr></thead><tbody>' +
            '<tr><td><strong>Critical</strong></td><td>Directly exploitable (takeover, exposed secret, KEV CVE)</td><td>Immediate action</td></tr>' +
            '<tr><td><strong>High</strong></td><td>High risk of exploitation or data exposure</td><td>Within days</td></tr>' +
            '<tr><td><strong>Medium</strong></td><td>Notable posture weakening (weak config, sensitive service)</td><td>Planned</td></tr>' +
            '<tr><td><strong>Low</strong></td><td>Minor deviation from best practices</td><td>Opportunistic</td></tr>' +
            '<tr><td><strong>Info</strong></td><td>Audit trail (clean scan, discovery, valid TLS)</td><td>No action — never counted as "to triage"</td></tr>' +
            '</tbody></table>' +
            '<p><em>Info</em> findings are excluded from alert counters and from the risk score: they document, they do not alert. The <strong>per-host risk score (0-100)</strong> weights active findings by severity (critical ×10, high ×5, medium ×2, low ×0.5) then multiplies by the <strong>business criticality</strong> declared on the asset (factor 1 to 4): a critical asset surfaces before a secondary asset with the same findings.</p>' +
            '<h2>Finding lifecycle</h2>' +
            '<p>Four statuses: <strong>New</strong> (untriaged), <strong>To fix</strong> (real issue, measure created), <strong>False positive</strong> (justified, silenced), <strong>Fixed</strong>. Deduplication relies on the <code>scanner|type|target</code> key — the same logical issue is never duplicated across rescans:</p>' +
            '<ul>' +
                '<li><strong>New</strong> re-detected → content and severity refreshed, no duplicate.</li>' +
                '<li><strong>False positive</strong> re-detected → silenced: never re-raised, the justification stays available for audit.</li>' +
                '<li><strong>To fix</strong> with an unfinished measure → silenced (the work is already planned). Measure done but issue re-detected → <strong>reopened</strong> as New: the remediation did not hold.</li>' +
                '<li><strong>Fixed</strong> re-detected → reopened as New.</li>' +
            '</ul>' +
            '<h2>Triage doctrine</h2>' +
            '<p>Every actionable finding must receive an explicit decision — that discipline is what separates a useful ASM from an ignored alert list:</p>' +
            '<ul>' +
                '<li><strong>Prioritize by severity then business criticality</strong> — handle critical/high findings on critical assets first.</li>' +
                '<li><strong>To fix</strong> is a commitment: the decision creates a <strong>corrective measure</strong> (title, owner, deadline) that feeds the action plan. No "to fix" triage without a measure.</li>' +
                '<li><strong>False positive</strong> requires a <strong>mandatory justification</strong>, timestamped and kept for audit — an unjustified FP is a traceability debt.</li>' +
                '<li><strong>Fixed</strong> is a verifiable assertion: the next scan contradicts it by reopening the finding if the issue persists.</li>' +
                '<li><strong>AI-assisted triage</strong>: the AI analysis provides a structured opinion (false-positive probability, confidence, recommended severity, remediation, references) enriched with NVD data. It is decision support — AI proposes, the human decides and remains accountable for the final status.</li>' +
            '</ul>' +
            '<h2>"Continuous discovery" philosophy</h2>' +
            '<p>ASM is not a point-in-time scan but <strong>continuous monitoring</strong>. Surface runs scanners via a scheduler that re-executes checks at a configurable frequency per asset (24h by default). Auto-discovered hosts are enrolled as <code>MonitoredAsset</code> and scanned in turn — a snowball effect controlled by the scope.</p>' +
            '<div class="help-tip"><strong>Scope:</strong> All scanners that discover hostnames filter results to the parent monitored domain. A DNS brute-force on <code>example.com</code> only keeps <code>*.example.com</code>, not external domains that might appear in a CT log.</div>' +
            '<h2>Known limitations</h2>' +
            '<ul>' +
                '<li><strong>CT logs are public</strong> — an asset certified by a private cert (internal PKI) will not appear there</li>' +
                '<li><strong>crt.sh is sometimes slow</strong> (30-90s timeouts possible) — the scanner retries automatically</li>' +
                '<li><strong>DNS brute-force</strong> depends on the wordlist quality — a larger wordlist (Assetnote, 100k entries) via <code>SURFACE_DNS_BRUTE_WORDLIST</code> will yield more results at the cost of longer scans</li>' +
                '<li><strong>Takeover detection</strong> requires a known fingerprint — a vulnerable SaaS service not listed in the DB is missed</li>' +
            '</ul>',

        "help.usage_html":
            '<h1 class="heading-blue">Using Surface</h1>' +
            '<p class="text-muted">Guide to the module pages — Dashboard, Monitoring, Hosts, Scans, Findings, Action Plan, plus the Audit log (administrators). The FR/EN and light/dark toggles live in the top bar.</p>' +
            '<h2>Dashboard</h2>' +
            '<p>Card-based overview:</p>' +
            '<ul>' +
                '<li><strong>Alert banner</strong> — untriaged Critical / High counters and "New (24h)". Each tile is clickable and opens Findings pre-filtered.</li>' +
                '<li><strong>Most exposed hosts</strong> and <strong>Top hosts at risk</strong> — clicking a host filters Findings on its target.</li>' +
                '<li><strong>30-day trend</strong> — one curve per severity (cumulative existing findings) plus the dashed cumulative-triage curve.</li>' +
                '<li><strong>Recurring finding types</strong> and <strong>Noisiest scanners</strong>.</li>' +
                '<li><strong>Monitoring inventory</strong> — breakdown by asset type and auto vs manual hosts.</li>' +
                '<li><strong>Action plan</strong> — To do / In progress / Done progress bar, 7-day delta, overdue measures.</li>' +
                '<li><strong>Scanner health</strong> — 24h jobs, success rate, failures, running scans, next scheduled scan.</li>' +
            '</ul>' +
            '<p>Header buttons: <strong>Scan all</strong>, <strong>Add a target</strong>, <strong>Import JSON</strong>.</p>' +
            '<div class="help-tip"><strong>Use it for:</strong> weekly status meetings, reporting, or a 5-second check to see if the situation is getting better or worse.</div>' +
            '<h2>Monitoring</h2>' +
            '<p>The <strong>monitored perimeter</strong> — the list of targets Surface scans automatically. Three base types:</p>' +
            '<ul>' +
                '<li><strong>Domain</strong> — a root domain name (<code>example.com</code>). Discovery scanners (CT logs, DNS brute, email security, TLS, takeover, typosquatting) apply.</li>' +
                '<li><strong>Host</strong> — a single host (<code>api.example.com</code> or <code>1.2.3.4</code>). Assessment scanners (nmap, TLS, nuclei, takeover) apply.</li>' +
                '<li><strong>CIDR range</strong> — an IP range (<code>192.168.1.0/24</code>). A ping sweep identifies active IPs then enrolls each discovered host.</li>' +
            '</ul>' +
            '<p>Add-ons can contribute additional types (e.g. SMB file share) — their documentation appears in this help when they are installed. The <strong>Add / Edit target</strong> modal lets you configure:</p>' +
            '<ul>' +
                '<li>The <strong>automatic scan frequency</strong> (1h, 6h, 24h, 7d, 30d, or 0 = manual only)</li>' +
                '<li>The <strong>active scanners</strong> — the list offered depends on the target type; tick all or a subset</li>' +
                '<li>The <strong>business criticality</strong> (Low / Medium / High / Critical) — it weights the risk score</li>' +
                '<li><strong>Tags</strong>, a <strong>label</strong> and internal <strong>notes</strong></li>' +
                '<li><strong>Auto-enroll discovered subdomains</strong> — discoveries themselves become monitored targets</li>' +
                '<li><strong>Stealth mode (anti-WAF)</strong> — less aggressive scans</li>' +
                '<li>An <strong>enabled / disabled toggle</strong> to pause without deleting</li>' +
            '</ul>' +
            '<p>The page offers a <strong>free-text search</strong>, <strong>scanner-type filter pills</strong>, and checkboxes for bulk actions: <strong>Force a scan</strong>, <strong>Apply scans</strong> (same scanner set on N targets; for a single domain the dialog also exposes the typosquatting tuning), <strong>Delete</strong>. Each row has its own scan / edit / delete buttons and shows the last and next scheduled scan.</p>' +
            '<h2>Hosts</h2>' +
            '<p>The "cards" view of monitored hosts (manual or auto-discovered). Hostnames resolving to the same IP are <strong>grouped on a single card</strong> (clickable aliases). Each card shows:</p>' +
            '<ul>' +
                '<li>The hostname / IP, resolved IP and any aliases</li>' +
                '<li>The <strong>risk score (0-100)</strong> colored by tier</li>' +
                '<li><strong>auto</strong> / <strong>manual</strong> / <strong>disabled</strong> / <strong>share</strong> badges, business criticality and tags</li>' +
                '<li>A <strong>screenshot thumbnail</strong> of the web service when available</li>' +
                '<li>The last-scan date, the <strong>severity counters</strong> of active findings and the "N to triage" indicator</li>' +
                '<li>A card footer with the active-scanner count and a <strong>Configure</strong> button (quick scanner selection)</li>' +
            '</ul>' +
            '<p>The search field filters by hostname, label or notes. Clicking a card opens the <strong>host detail view</strong>: full record, <strong>Scan now</strong> / <strong>Edit</strong> / <strong>Delete</strong> buttons, the <strong>scan history</strong> (last 8 jobs with the +N new / ↻N reopened diff), per-severity summary tiles, a "Hide the N false positives" checkbox, and the associated findings table — triageable one by one or in bulk exactly like the Findings page. For a file server, the record lists every share with its own actions.</p>' +
            '<h2>Scans</h2>' +
            '<p>Job history — every scheduler tick and every manual scan creates a job. The table shows the target, scanner type, source (AUTO vs MANUAL), status (<strong>Pending / Running / Completed / Partial / Failed</strong>), the findings count with its diff (+N new, ↻N reopened), start time and duration. Filter by scanner type and by status. Any finished job can be <strong>rerun</strong> (↻ button) or deleted. The page <strong>auto-refreshes</strong> while a job is running.</p>' +
            '<div class="help-tip"><strong>Useful for:</strong> diagnosing why a scan found nothing (silent failure? timeout?), checking that the scheduler is running, or rerunning a failed scan.</div>' +
            '<h2>Findings</h2>' +
            '<p>The triage hub. All findings raised by scanners land here with filters:</p>' +
            '<ul>' +
                '<li><strong>Text search</strong> (title, target, description, scanner, type)</li>' +
                '<li><strong>Status</strong>: Open (= New + To fix, the default filter) / New / To fix / False positive / Fixed / All</li>' +
                '<li><strong>Severity</strong>: Critical, High, Medium, Low, Info (multi-select)</li>' +
                '<li><strong>Scanner type</strong>: by scanner that raised the finding (multi-select)</li>' +
            '</ul>' +
            '<h3>Single triage</h3>' +
            '<p>Each row offers two quick buttons: <strong>To fix</strong> and <strong>False positive</strong>. Clicking the row opens the <strong>detail view</strong> (description, evidence, optional screenshot, linked measure) with the <strong>To fix</strong>, <strong>False positive</strong>, <strong>Fixed</strong>, <strong>Reset</strong> (back to New), <strong>AI analysis</strong> and <strong>Delete</strong> buttons. The triage modal asks for:</p>' +
            '<ul>' +
                '<li><strong>To fix</strong>: a measure name, a remediation description, an owner (directory picker, optional), a deadline (optional). The measure is created and appears in the Action Plan.</li>' +
                '<li><strong>False positive</strong>: a <strong>mandatory</strong> justification kept for audit. The finding is silenced and will not be re-raised by subsequent scans.</li>' +
                '<li><strong>Fixed</strong>: a simple confirmation — the finding will reappear if re-detected on the next scan.</li>' +
            '</ul>' +
            '<h3>Bulk triage</h3>' +
            '<p>Ticking one or more rows via the left checkbox pops up a <strong>sticky action bar at the bottom of the page</strong>. You can:</p>' +
            '<ul>' +
                '<li><strong>Create a corrective measure</strong> — ONE single measure, linked to the N selected findings (useful for "upgrade nginx on 30 hosts")</li>' +
                '<li>Mark <strong>N findings Fixed</strong> after confirmation</li>' +
                '<li>Declare <strong>N findings False positive</strong> with the same justification</li>' +
                '<li><strong>Permanently delete</strong> N findings (irreversible)</li>' +
            '</ul>' +
            '<h3>Run a scan / JSON import</h3>' +
            '<p>The <strong>Run a scan</strong> button triggers a quick ports + TLS scan on any host typed on the fly, even outside the monitored perimeter. The <strong>Import JSON</strong> button opens a full modal: inline format specification, downloadable / copyable template, file upload or paste, and validation before submit. Expected format: an array of objects <code>{scanner, type, severity, title, description, target, evidence}</code> (only <code>title</code> is required). Standard deduplication applies.</p>' +
            '<h2>Action Plan</h2>' +
            '<p>Corrective measures created from findings marked "to fix". Each measure has a short ID (<code>SRF-XXXXXXXX</code>), a title, the number of covered findings, a status (To do / In progress / Done), an owner, a deadline (highlighted when overdue). Clicking a row opens the edit modal, including a <strong>progress log</strong> to timestamp updates. Checkboxes enable bulk <strong>Done</strong> and bulk <strong>Delete</strong>.</p>' +
            '<h2>Weekly email digest</h2>' +
            '<p>Once SMTP is configured (see Settings), Surface <strong>automatically</strong> sends a weekly HTML digest: aggregated counters, top 10 findings to triage, top 10 exposed hosts, scan and measure stats. The scheduler checks hourly whether 7 days have elapsed since the last send (<code>digest.last_sent_at</code> in DB). A <strong>Send now</strong> button in the SMTP section lets you push an ad-hoc digest manually without waiting for the weekly tick.</p>' +
            '<div class="help-tip"><strong>Security:</strong> the SMTP host is validated against the same anti-SSRF blocklist as scanners (no <code>localhost</code>, no <code>surface-db</code>). Sender / recipient addresses are filtered against header injection (CRLF). The SMTP password is stored server-side and never returned in GET responses.</div>' +
            '<h2>AI analysis</h2>' +
            '<p>In a finding\'s detail view, the <strong>AI analysis</strong> button (lightning icon) sends the finding to the backend, which builds the methodology prompt, enriches it with NVD data and queries the configured LLM provider. The result is displayed below the finding:</p>' +
            '<ul>' +
                '<li><strong>Verdict</strong> — probable false positive or genuine finding, with the confidence level</li>' +
                '<li><strong>Recommended severity</strong> if it differs from the scanner\'s</li>' +
                '<li><strong>Summary</strong> — 2-3 line executive summary</li>' +
                '<li><strong>Remediation</strong> — remediation steps</li>' +
                '<li><strong>References</strong> — URLs (CVE, CWE, vendor docs)</li>' +
            '</ul>' +
            '<p>The button only appears when the AI assistant is enabled under <em>Settings → AI assistant</em>. The final decision remains manual: the AI does not click "False positive" or "To fix" for you.</p>' +
            '<h2>Audit log (administrators)</h2>' +
            '<p>Restricted to administrators, this panel traces who did what (date, user, action, target, details, IP) with a free-text search — useful for compliance and post-mortems.</p>' +
            '<h2>Settings (gear icon at the top) — 6 accordion sections</h2>' +
            '<p>The <strong>Settings</strong> page uses a native HTML accordion: opening one section automatically collapses the previous one. Every section is collapsed by default.</p>' +
            '<ol>' +
                '<li><strong>Language</strong> — instant FR/EN toggle for the whole UI</li>' +
                '<li><strong>AI assistant</strong> — enables the AI analysis; depending on the deployment, access is managed by the suite (backend proxy) or configured with your own provider / key</li>' +
                '<li><strong>Timezone</strong> — picker of 30 IANA zones. The default follows the browser-detected timezone. Every date (findings, scans, measures) renders in the chosen zone.</li>' +
                '<li><strong>Nuclei</strong> — version, template count, last update date, <strong>editable tuning</strong> (rate-limit, concurrency, bulk-size, timeout, retries). "Update templates" button.</li>' +
                '<li><strong>Shodan API</strong> — API key stored server-side (masked on display). Enables <code>shodan_domain</code> and <code>shodan_host</code>.</li>' +
                '<li><strong>Email digest (SMTP)</strong> — full SMTP configuration: host, port, username/password, sender, recipients, STARTTLS toggle, "Send now" button.</li>' +
            '</ol>' +
            '<div class="help-tip"><strong>Nuclei tuning tip:</strong> on client targets or WAF-protected environments, lower the rate-limit to 5-10 req/s to avoid blacklisting. For your own assets, 20-50 req/s is comfortable.</div>' +
            '<h2>Typical workflow</h2>' +
            '<ol style="font-size:0.9em;line-height:1.8">' +
                '<li>Add the root domain in <strong>Monitoring</strong> with all scanners ticked</li>' +
                '<li>Wait for the first scheduler tick or run a manual scan → subdomains are discovered and enrolled as hosts</li>' +
                '<li>Auto-discovered hosts are scanned on subsequent ticks (nmap, TLS, nuclei, takeover)</li>' +
                '<li>Open <strong>Findings</strong> filtered on "Open" → triage critical/high findings first</li>' +
                '<li>False positives are documented and silenced, real issues become measures</li>' +
                '<li>Measures are tracked with their owner and deadline in the <strong>Action Plan</strong> tab</li>' +
                '<li>Scans keep running in the background → new findings appear automatically</li>' +
            '</ol>',

        // ── Dashboard ──────────────────────────────────────
        "dash.title":          "Dashboard",
        "dash.findings_total": "Total findings",
        "dash.false_positive": "False positives",
        "dash.measures_done":  "Measures done",
        "dash.headline_critical":    "{n} critical finding(s) to triage — immediate attention required",
        "dash.headline_high":        "{n} high-severity finding(s) to triage",
        "dash.headline_ok":          "Situation under control — no critical or high findings pending triage",
        "dash.new_24h":              "New (24 h)",
        "dash.top_exposed_hosts":    "Most exposed hosts",
        "dash.no_hosts_at_risk":     "No host with active findings",
        "dash.timeline_title":       "30-day trend",
        "dash.timeline_triaged":     "Triaged (cumulative)",
        "dash.top_hosts":            "Top hosts at risk",
        "dash.top_types":            "Recurring finding types",
        "dash.top_scanners":         "Noisiest scanners",
        "dash.no_active_findings":   "No active findings",
        "dash.no_findings":          "No findings",
        "dash.surface_title":        "Monitored inventory",
        "dash.hosts_source":         "Hosts by source",
        "dash.measures_title":       "Action plan",
        "dash.measures_created_7d":  "created 7d",
        "dash.measures_done_7d":     "done 7d",
        "dash.measures_delta":       "net delta",
        "dash.measures_overdue":     "{n} measure(s) overdue",
        "dash.health_title":         "Scanner health",
        "dash.health_jobs_24h":      "Jobs 24 h",
        "dash.health_success_rate":  "Success rate",
        "dash.health_failed_24h":    "Failed 24 h",
        "dash.health_running":       "Running",
        "dash.health_last_job":      "Last job:",
        "dash.health_next":          "Next scan:",
        "dash.gaps_title":           "Coverage & gaps",
        "dash.gaps_stale_hosts":     "Stale hosts (> 7d)",
        "dash.gaps_sparse_hosts":    "Sparse hosts",
        "dash.gaps_disabled_long":   "Disabled > 30d",
        "dash.gaps_stale_list":      "Stale hosts detail",

        // ── Severity labels ────────────────────────────────
        "sev.critical": "Critical",
        "sev.high":     "High",
        "sev.medium":   "Medium",
        "sev.low":      "Low",
        "sev.info":     "Info",

        // ── Status labels ──────────────────────────────────
        "status.open":           "Open",
        "status.new":            "New",
        "status.to_fix":         "To fix",
        "status.false_positive": "False positive",
        "status.fixed":          "Fixed",
        "status.failed":         "Failed",
        "status.all":            "All",
        "status.to_triage":      "To triage",

        // ── Kind labels ────────────────────────────────────
        "kind.domain":   "Domain",
        "kind.host":     "Host",
        "kind.ip_range": "CIDR range",
        "kind.file_share": "File share",

        // ── Monitored / Surveillance ───────────────────────
        "monitored.title":            "Monitored perimeter",
        "monitored.help":             "Domains, IPs and CIDR ranges to monitor. The Scan button triggers a quick port + TLS scan on each target. CIDR ranges are handed to external scanners via bulk-import.",
        "monitored.scan_all":         "Scan all",
        "monitored.add":              "Add target",
        "monitored.empty":            "No perimeter defined. Click + Add to start (domain, IP or CIDR).",
        "monitored.search.placeholder": "Search by value, label, type, scanner...",
        "monitored.filter.scanner": "Scan type:",
        "monitored.no_match":         "No target matches the search.",
        "monitored.count":            "target(s)",
        "monitored.col.type":         "Type",
        "monitored.col.value":        "Value",
        "monitored.col.label":        "Label",
        "monitored.col.scanners":     "Scanners",
        "monitored.col.frequency":    "Frequency",
        "monitored.col.enabled":      "Enabled",
        "monitored.col.last_scan":    "Last scan",
        "monitored.col.next_scan":    "Next",
        "monitored.frequency_hours":  "every {n} h",
        "monitored.next.imminent":    "imminent",
        "monitored.next.disabled":    "disabled",
        "monitored.last.never":       "never",
        "monitored.delete_confirm":   "Delete this target?",
        "monitored.bulk_delete":      "Delete",
        "monitored.bulk_delete_confirm": "Delete {count} monitored target(s)? This action cannot be undone.",
        "monitored.bulk_delete_done": "{count} target(s) deleted",
        "monitored.bulk_delete_partial": "{done} deleted, {errors} error(s)",
        "monitored.bulk_scan":        "Force scan",
        "monitored.bulk_scan_started": "Launching {n} scan(s)...",
        "monitored.bulk_scan_done":   "{n} scan(s) started",
        "monitored.bulk_scan_partial": "{done} started, {errors} error(s)",

        // ── Hosts panel ────────────────────────────────────
        "hosts.title":            "Hosts",
        "hosts.count":            "monitored host(s)",
        "hosts.help":             "List of all monitored hosts, added manually or auto-discovered by scanners (CT logs, SAN, ping sweep). Click a card to see details and associated findings.",
        "hosts.search.placeholder": "Search by hostname, IP, label, source...",
        "hosts.no_match":         "No host matches the search.",
        "hosts.empty":            "No host monitored. Add some via Monitoring or run a CT logs scan on a domain to auto-discover subdomains.",
        "hosts.source.auto":      "auto",
        "hosts.source.manual":    "manual",
        "hosts.badge.disabled":   "disabled",
        "hosts.badge.share":      "share",
        "hosts.share_count":      "{n} shares",
        "hosts.last_scan":        "Last scan",
        "hosts.findings.none":    "No findings",
        "hosts.findings.to_triage": "to triage",

        // ── Host detail ────────────────────────────────────
        "host.back":               "Hosts",
        "host.back_to_host":       "Back to host",
        "host.col.value":          "Value",
        "host.col.label":          "Label",
        "host.col.enabled":        "Enabled",
        "host.col.frequency":      "Frequency",
        "host.col.last_scan":      "Last scan",
        "host.col.scanners":       "Active scanners",
        "host.col.notes":          "Notes",
        "host.frequency_hours":    "{n} hours",
        "host.scan_now":           "Scan now",
        "host.scan_all_shares":    "Scan all shares",
        "host.shares":             "Shares",
        "host.edit":               "Edit",
        "host.delete":             "Delete",
        "host.findings_title":     "Associated findings",
        "host.findings_empty":     "No finding associated with this host. Run a scan to generate some.",
        "host.hide_fp":            "Hide {n} false positive(s)",
        "host.delete_confirm":     "Delete this host? Associated findings will stay in the DB but won't be linked to a monitored asset anymore.",

        // ── Findings panel ─────────────────────────────────
        "findings.title":             "Findings",
        "findings.quick_scan":        "Run a scan",
        "findings.bulk_import":       "Import JSON",
        "findings.search.placeholder": "Search title, target, description, scanner...",
        "findings.filter.status":     "Status:",
        "findings.filter.severity":   "Severity:",
        "findings.filter.scanner":    "Scanner type:",
        "findings.filter.hint":       "(no filter = all)",
        "findings.filter.hint_m":     "(no filter = all)",
        "findings.filter.reset":      "x reset",
        "findings.col.severity":      "Sev.",
        "findings.col.type":          "Type",
        "findings.col.title":         "Title",
        "findings.col.target":        "Target",
        "findings.col.status":        "Status",
        "findings.col.datetime":      "Date & time",
        "findings.count":             "findings",
        "findings.empty":             "No finding matches the filters.",

        // ── Bulk action bar ────────────────────────────────
        "bulk.selected":           "finding(s) selected",
        "bulk.false_positive":     "False positive",
        "bulk.to_fix":             "Create corrective measure",
        "bulk.fixed":              "Fixed",
        "bulk.fixed_confirm":      "{n} finding(s) will be marked as fixed. They will reappear if detected on the next scan.",
        "bulk.delete":             "Delete",
        "bulk.clear":              "Unselect",
        "bulk.fp_title":           "Mark {n} finding(s) as false positives",
        "bulk.fp_help":            "The same justification will be recorded on all {n} selected findings. It is mandatory and kept for audit.",
        "bulk.fp_confirm":         "Confirm false positive ({n})",
        "bulk.fp_justification":   "Justification *",
        "bulk.fp_placeholder":     "Explain why these findings are false positives (context, documented exception, intentional configuration...)",
        "bulk.measure_title":      "Create a corrective measure for {n} finding(s)",
        "bulk.measure_help":       "One corrective measure will be created for each selected finding, all sharing the same title/description/owner/deadline. They'll appear grouped in the Measures tab.",
        "bulk.measure_confirm":    "Create {n} measure(s)",
        "bulk.delete_confirm":     "Permanently delete {n} finding(s)? Linked measures will also be deleted (cascade).",

        // ── Common actions ─────────────────────────────────
        "action.cancel":  "Cancel",
        "action.confirm": "Confirm",
        "action.save":    "Save",
        "action.edit":    "Edit",
        "action.delete":  "Delete",

        // ── Kind help texts ────────────────────────────────
        "kind.help.domain":   "Root domain — e.g. example.com, medsecure.fr",
        "kind.help.host":     "Single host — IP (1.2.3.4, ::1) or DNS name (api.example.com)",
        "kind.help.ip_range": "CIDR range for external scanners — e.g. 192.168.1.0/24",
        "kind.help.file_share": "Windows SMB/CIFS share — e.g. \\\\server\\share or //server/share",

        // ── Scanner labels (displayed in job listings) ─────
        "scanner.nmap":                 "Nmap (ports)",
        "scanner.scheduled_host":       "Scheduled host scan",
        "scanner.scheduled_domain":     "Scheduled domain scan",
        "scanner.manual_host":          "Manual host scan",
        "scanner.manual_domain":        "Manual domain scan",
        "scanner.manual_discovery":     "Manual discovery",
        // NB: clé dupliquée dans la source ("Scheduled discovery" masquée) —
        // seule la dernière valeur gagnait au runtime, conservée ici.
        "scanner.scheduled_discovery":  "Auto discovery (CIDR)",

        // ── Jobs panel ─────────────────────────────────────
        "jobs.title":           "Scans",
        "jobs.help":            "List of all scans (manual and automatic). Jobs run in the background; this page auto-refreshes while a job is running.",
        "jobs.filter.scanner":  "Type:",
        "jobs.filter.status":   "Status:",
        "jobs.filter.all":      "All",
        "jobs.col.target":      "Target",
        "jobs.col.scanner":     "Type",
        "jobs.col.source":      "Source",
        "jobs.col.status":      "Status",
        "jobs.col.findings":    "Findings",
        "jobs.col.started":     "Started",
        "jobs.col.duration":    "Duration",
        "jobs.status.pending":  "Pending",
        "jobs.status.running":  "Running",
        "jobs.status.completed":"Completed",
        "jobs.status.partial":  "Partial",
        "jobs.status.failed":   "Failed",
        "jobs.partial.stopped": "Stopped after {n} files —",
        "jobs.partial.files":   "max cap reached, resumes next scan",
        "jobs.partial.time":    "time budget reached, resumes next scan",
        "jobs.partial.inaccessible": "{n} inaccessible folder(s)",
        "jobs.scanned_files":   "{n} files scanned",
        "jobs.empty":           "No scan has been run. Scans are started by asset monitoring.",
        "jobs.no_match":        "No scan matches the filters.",
        "jobs.rerun":           "Rerun",
        "jobs.rerun_in_progress":"Scan in progress on {target}…",
        "jobs.rerun_done":      "Scan finished on {target} — {n} finding(s)",
        "jobs.source.manual":   "manual",
        "jobs.source.auto":     "auto",

        // ── Monitored asset modal (add/edit) ──────────────
        "mon_modal.title_add":      "Add a target",
        "mon_modal.title_edit":     "Edit target",
        "mon_modal.type":           "Type",
        "mon_modal.value":          "Value",
        "mon_modal.label":          "Label",
        "mon_modal.label_ph":       "Short description (optional)",
        "mon_modal.notes":          "Notes",
        "mon_modal.notes_ph":       "Internal notes (optional)",
        "mon_modal.frequency":      "Automatic scan frequency",
        "mon_modal.frequency_help": "0 = disables automatic scanning",
        "mon_modal.scanners":       "Active scanners",
        "mon_modal.scanners_help":  "Tick the scanners to run. If none is ticked, defaults apply.",
        "mon_modal.fs_regex":       "Custom regex",
        "mon_modal.fs_regex_ph":    "One regular expression per line",
        "mon_modal.fs_regex_help":  "Patterns to search in file bodies, in addition to the built-in secret set.",
        "mon_modal.fs_ext":         "Extensions to scan",
        "mon_modal.fs_ext_ph":      "pdf, docx, xlsx, pptx, txt, conf… (empty = defaults)",
        "mon_modal.fs_ext_help":    "Restrict analysis to these extensions. Empty = the add-on's default list.",
        "mon_modal.fs_maxsize":     "Max size per file (MB)",
        "mon_modal.fs_maxfiles":    "Max files per scan",
        "mon_modal.fs_maxfiles_help": "Optional. Empty = no limit (whole share, within the time budget). When set, each scan processes this many NEW files then resumes from there next time; the scan is marked \"Partial\" until the whole share has been covered.",
        "mon_modal.fs_timebudget":  "Max scan duration (minutes)",
        "mon_modal.fs_timebudget_help": "Maximum time per scan (default 30 min). Beyond it the scan stops and is marked \"Partial\" (it resumes next run if a file cap is also set). Raise it to cover a very large share in one pass.",
        "mon_modal.fs_user":        "SMB username",
        "mon_modal.fs_domain":      "Domain",
        "mon_modal.fs_domain_ph":   "e.g. CORP (empty for a local account)",
        "mon_modal.fs_pwd":         "SMB password",
        "mon_modal.fs_pwd_ph":      "Service-account password",
        "mon_modal.fs_pwd_keep":    "•••••• (leave empty to keep current)",
        "mon_modal.fs_creds_help":  "Per-target credentials (encrypted). If empty, the global service account (SURFACE_SMB_*) is used.",
        "mon_modal.criticality":     "Business criticality",
        "mon_modal.criticality_help":"Business value of this asset. Used by the risk score formula.",
        "mon_modal.crit_low":        "Low",
        "mon_modal.crit_medium":     "Medium",
        "mon_modal.crit_high":       "High",
        "mon_modal.crit_critical":   "Critical",
        "mon_modal.tags":            "Tags",
        "mon_modal.tags_ph":         "production, dmz, pci-scope",
        "mon_modal.tags_help":       "Free-form tags, comma-separated. Shown on host cards.",
        "crit.low":                  "Low criticality",
        "crit.medium":               "Medium criticality",
        "crit.high":                 "High criticality",
        "crit.critical":             "Maximum criticality",
        "risk.score_tooltip":        "Risk score (0-100) = active severities × business criticality",
        "risk.tier_critical":        "Critical",
        "risk.tier_high":            "High",
        "risk.tier_medium":          "Moderate",
        "risk.tier_low":             "Low",
        "risk.tier_clean":           "Clean",
        "host.scan_history":         "Scan history",
        "host.scan_done":            "Scan finished on {target} — {n} finding(s)",
        "host.scan_failed":          "Scan failed on {target}",
        "host.scan_timeout":         "Scan still running on {target} after 6 min — check the Scans page",
        "hosts.scanners":            "scans",
        "hosts.configure":           "Configure",
        "hosts.configure_scans":     "Configure scans",
        "hosts.scanners_updated":    "Scans updated on {n} asset(s)",
        "hosts.bulk_configure_scans":"Apply scans",
        "hosts.bulk_scanners_subtitle":"{n} selected assets",
        "mon_modal.no_scanners_for_kind":"No scanner available for this asset type.",
        "mon_typo.title":            "Typosquatting — settings",
        "mon_typo.max_variants":     "Permutations generated per scan",
        "mon_typo.use_ct":           "Check Certificate Transparency (high-risk lookalikes)",
        "mon_typo.max_ct":           "Max CT requests per scan",
        "hosts.groups":              "IP group(s)",
        "hosts.aliases":              "{n} alias:",
        "hosts.resolved_ip_tooltip":  "Resolved IP at last scan — hostnames sharing the same IP are grouped",
        "host.col.resolved_ip":       "Resolved IP",
        "host.col.aliases":           "Other hostnames",
        "fd.ai_triage":               "AI analysis",
        "fd.ai_not_configured":       "AI assistant not configured",
        "fd.ai_open_settings":        "Open Settings → AI assistant to set your API key.",
        "fd.ai_analyzing":            "Analyzing",
        "fd.ai_verdict":              "Verdict",
        "fd.ai_fp_probable":          "Likely false positive",
        "fd.ai_genuine":              "Credible finding",
        "fd.ai_sev_rec":              "Recommended severity",
        "fd.ai_summary":              "Summary",
        "fd.ai_remediation":          "Remediation",
        "fd.ai_refs":                 "References",
        "smtp.section":               "Email sending (weekly digest)",
        "smtp.help":                  "Configure the SMTP server used to send the weekly email digest.",
        "smtp.host":                  "Host",
        "smtp.port":                  "Port",
        "smtp.user":                  "Username",
        "smtp.password":              "Password",
        "smtp.password_ph":           "••••",
        "smtp.already_set":           "already set",
        "smtp.sender":                "Sender",
        "smtp.recipients":            "Recipients",
        "smtp.use_tls":               "STARTTLS (recommended)",
        "smtp.save":                  "Save",
        "smtp.saved":                 "SMTP config saved",
        "smtp.send_now":              "Send now",
        "smtp.sending":               "Sending digest…",
        "smtp.sent":                  "Digest sent to {n} recipient(s)",
        "smtp.load_error":            "Could not load SMTP config",
        "tz.section":                 "Time zone",
        "tz.hint":                    "All dates shown in the UI are rendered in this zone.",
        "tz.browser":                 "Auto (browser)",
        "tz.saved":                   "Time zone updated",
        "mon_modal.enabled":        "Enabled",
        "mon_modal.auto_enroll":    "Auto-enrol discovered sub-domains",
        "mon_modal.auto_enroll_help": "When enabled, hostnames found via CT logs, DNS brute, SAN or Shodan are automatically added as new monitored assets. Disabled by default: only the asset you add is scanned; discovery still appears in the findings.",
        "mon_modal.stealth":        "Stealth mode (anti-WAF)",
        "mon_modal.stealth_help":   "When enabled, nuclei and nmap switch to a slow, browser-impersonating profile (rate-limit 3 req/s, 1-second delay, nmap timing T2). Bypasses most WAF / anti-bot protections (Cloudflare, RocketCDN…) but makes scans 5–10x slower. Recommended for hosts that emit the 'scanner_blocked' finding.",
        "mon_modal.value_required": "Value is required",
        "mon_modal.added":          "Target added",
        "mon_modal.updated":        "Target updated",
        "mon_modal.deleted":        "Target deleted",
        "mon_modal.scan_in_progress":"Scan in progress...",
        "mon_modal.scan_all_confirm":"Run a scan on all enabled targets?",
        "mon_modal.scan_launched":   "Scan started on {target}",
        "mon_modal.scan_all_in_progress":"Global scan in progress...",
        "mon_modal.scan_all_done":   "{scanned} target(s) scanned, {n} finding(s) created",
        "mon_modal.scan_all_errors": "{n} error(s)",

        // ── Finding detail ────────────────────────────────
        "fd.back":                   "Findings",
        "fd.scanner":                "Scanner",
        "fd.type":                   "Type",
        "fd.target":                 "Target",
        "fd.created":                "Created",
        "fd.triaged":                "Triaged",
        "fd.triaged_by":             "by",
        "fd.description":            "Description",
        "fd.evidence":               "Evidence",
        "fd.screenshot":             "Screenshot",
        "fd.notes":                  "Notes",
        "fd.triage":                 "Triage",
        "fd.triage_notes_ph":        "Notes (optional)...",
        "fd.triage_to_fix":          "To fix (creates a measure)",
        "fd.triage_fp":              "False positive",
        "fd.triage_fixed":           "Fixed",
        "fd.triage_reset":           "Reset (untriaged)",
        "fd.delete":                 "Delete",
        "fd.delete_confirm":         "Delete this finding?",
        "fd.deleted":                "Finding deleted",
        "fd.measure_linked":         "Linked measure",
        "fd.measure_status":         "Status",
        "fd.measure_owner":          "Owner",
        "fd.measure_due":            "Deadline",
        "fd.triage_ok":              "Triage saved",

        // ── Triage modal (single) ─────────────────────────
        "tm.title_to_fix":           "Create a corrective measure",
        "tm.title_fp":               "Mark as false positive",
        "tm.title_reset":            "Reset triage",
        "tm.confirm_to_fix":         "Create measure",
        "tm.confirm_fp":             "Confirm false positive",
        "tm.finding":                "Finding:",
        "tm.fp_justif":              "Justification *",
        "tm.fp_justif_ph":           "Explain why this finding is a false positive (context, documented exception, intentional configuration...)",
        "tm.reset_help":             "Reset this finding to 'New'? The linked measure (if any) will be deleted.",
        "tm.justif_required":        "Justification is required",

        // ── Measures panel ────────────────────────────────
        "measures.title":            "Action Plan",
        "measures.help":             "Action plan from triaged findings. Each measure is linked to the finding that created it.",
        "measures.empty":            "No measure created. Measures appear automatically when you triage a finding to 'To fix'.",
        "measures.col.id":           "ID",
        "measures.col.title":        "Title",
        "measures.col.status":       "Status",
        "measures.col.owner":        "Owner",
        "measures.col.due":          "Deadline",
        "measures.status.a_faire":   "To do",
        "measures.status.en_cours":  "In progress",
        "measures.status.termine":   "Done",
        "measures.col.severity":     "Severity",
        "measures.updated":          "Measure updated",

        // ── Quick prompts (utility actions) ───────────────
        "prompt.quick_scan_host":    "Target host (e.g. example.com):",
        "prompt.findings_imported":  "findings imported",
        "prompt.findings_skipped":   "skipped",
        "prompt.findings_on":        "finding(s) created on",
        "prompt.job_delete_confirm": "Delete this job? (findings already created will not be affected)",

        // ── Generic & host/nuclei inline strings ──────────
        "common.error":              "Error",
        "error.bad_request":         "Invalid request",
        "error.forbidden":           "Access denied",
        "error.not_found":           "Not found",
        "error.server":              "Server error, please try again",
        "error.generic":             "An error occurred",
        "triage.status_prefix":      "Finding",
        "host.deleted":               "Host deleted",
        "nuclei.form.rate_limit":     "Rate limit (req/s)",
        "nuclei.form.concurrency":    "Concurrency",
        "nuclei.form.bulk_size":      "Bulk size",
        "nuclei.form.timeout":        "Per-request timeout (s)",
        "nuclei.form.retries":        "Retries",
        "nuclei.form.rate_limit_h":   "Maximum nuclei requests per second against a target",
        "nuclei.form.concurrency_h":  "Number of templates executed in parallel",
        "nuclei.form.bulk_size_h":    "Batch size of hosts processed in parallel",
        "nuclei.form.timeout_h":      "Timeout for an individual HTTP request",
        "nuclei.form.retries_h":      "Number of retries on network failure",
        "nuclei.form.def":            "def",
        "nuclei.form.min":            "min",
        "nuclei.form.max":            "max",
        "nuclei.saved":               "Nuclei tuning saved",
        "nuclei.save_error":          "Save error",
        "nuclei.save_btn":            "Save tuning",
        "nuclei.update_btn":          "Update templates",
        "nuclei.updating":            "Updating (1-2 min)...",
        "nuclei.templates_after":     "templates after update",
        "nuclei.not_installed":       "Nuclei is not installed in this container.",
        "nuclei.config_error":        "Error: nuclei config unavailable",
        "nuclei.version":             "Version:",
        "nuclei.templates":           "Templates:",
        "nuclei.last_update":         "last update:",
        "nuclei.unknown":             "unknown",
        "nuclei.help":                "Values saved here override the SURFACE_NUCLEI_* environment variables and apply immediately to the next scan.",
        "nuclei.section":             "Nuclei (DAST scanner)",
        "common.loading":             "Loading...",

        // ── Shodan settings section ───────────────────────
        "shodan.section":             "Shodan API",
        "shodan.help":                "Shodan provides a passive inventory of Internet-exposed services. An API key enables the shodan_domain scanner (free, subdomain enumeration) and shodan_host (1 Shodan credit per lookup, ports/services/CVE enrichment).",
        "shodan.warning_title":       "No key configured.",
        "shodan.warning_body":        "Without a key, Shodan scanners are inactive. The key is stored server-side (AppSettings), never returned to the browser, and can be removed at any time.",
        "shodan.key_label":           "Shodan API key",
        "shodan.key_help":            "32 hex characters. Get it at shodan.io → Account → API. The key is tested against /account/profile before being saved.",
        "shodan.key_required":        "API key is required.",
        "shodan.save":                "Save & test",
        "shodan.saved":               "Shodan key saved",
        "shodan.testing":             "Testing key...",
        "shodan.configured":          "API key configured",
        "shodan.last_check":          "Last verified",
        "shodan.replace":              "Replace",
        "shodan.delete":              "Delete key",
        "shodan.delete_confirm":      "Delete the Shodan API key? The shodan_* scanners will no longer run until a new key is configured.",
        "shodan.deleted":             "Shodan key deleted",

        // ── Bulk import modal ──────────────────────────────
        "bulk_import.title":            "Import findings from JSON",
        "bulk_import.intro":            "Inject findings produced by an external tool (nmap, Shodan, Trivy, Burp, manual pentest...) to centralize them in Surface. The same dedup logic as internal scanners applies.",
        "bulk_import.spec_title":       "Show field specification",
        "bulk_import.col_field":        "Field",
        "bulk_import.col_required":     "Required",
        "bulk_import.col_description":  "Description",
        "bulk_import.f_title":          "Short finding title. The only mandatory string.",
        "bulk_import.f_severity":       "One of: info, low, medium, high, critical. Default: medium.",
        "bulk_import.f_scanner":        "Tool identifier (e.g. nmap, shodan, trivy, burp, manual). Default: manual. Used for filtering and deduplication.",
        "bulk_import.f_type":           "Scanner sub-category (e.g. open_port, tls_expiring, xss). Default: other. The combination scanner+type+target is deduplicated.",
        "bulk_import.f_target":         "Hostname, IP, or host:port this finding relates to. Used for scoping and linking to monitored assets.",
        "bulk_import.f_description":    "Long explanation + remediation guidance. Shown in the finding detail view.",
        "bulk_import.f_evidence":       "Free-form JSON object holding raw data (ports, banners, log excerpts, CVEs, URLs...).",
        "bulk_import.wrapper_note":     "JSON can be either a direct array [...] or an object {\"findings\": [...]}. Maximum 500 findings per call.",
        "bulk_import.sample_label":     "Sample format",
        "bulk_import.download_template":"Download template",
        "bulk_import.copy_sample":      "Copy sample",
        "bulk_import.use_sample":       "Pre-fill with this sample",
        "bulk_import.copied":           "Sample copied to clipboard",
        "bulk_import.upload_label":     ".json file",
        "bulk_import.paste_label":      "Or paste JSON directly",
        "bulk_import.submit":           "Import",
        "bulk_import.json_error":       "Invalid JSON",
        "bulk_import.structure_error":  "Invalid structure: expected an array of findings or {findings: [...]}",
        "bulk_import.item_not_object":  "Entry must be a JSON object.",
        "bulk_import.title_required":   "Field 'title' is required and non-empty.",
        "bulk_import.invalid_severity": "Invalid severity, expected info|low|medium|high|critical",
        "bulk_import.validation_failed":"Validation failed:",
        "bulk_import.validation_ok":    "valid finding(s), ready to import",
        "bulk_import.warnings":         "warning(s)",
        "bulk.findings_selected": "{n} finding(s) selected",
        "bulk.delete_confirm_title": "Delete {n} finding(s)?",
        "bulk.delete_confirm_msg": "This action cannot be undone.",
        "bulk.fixed_confirm_title": "Mark {n} finding(s) as fixed?",
        "bulk.fixed_confirm_msg": "Findings will be marked as fixed. They will reappear if detected on the next scan.",
        "bulk.measure_default_title": "Corrective measure",
        "bulk.deleted": "deleted",
        "settings.ai_privacy_warning": "By enabling the AI assistant:\n\n1. DATA SHARING — Your analysis data (context, requirements, controls) will be sent to the selected AI provider. Make sure your privacy policy and contractual obligations allow this.\n\n2. API KEY EXPOSURE — The API key is transmitted directly from your browser. It is visible in browser DevTools and can be captured by browser extensions. Use a browser without extensions or a dedicated profile.\n\n3. NETWORK — Communications are encrypted (HTTPS) but may be logged by corporate proxies.\n\nDo you want to continue?",
        "settings.ai_enable": "Enable AI assistant",
        "matrix.high": "High",
        "matrix.significant": "Significant",
        "settings.save": "Save",
        "settings.language": "Language",
        "settings.saved": "Settings saved",
        "settings.ai_section": "AI Assistant",
        "matrix.low": "Low",
        "matrix.moderate": "Moderate",
        "measures.marked_done": "Measure marked as fixed",
        "matrix.y": "Likelihood",
        "measures.deleted": "Measure deleted",
        "matrix.extreme": "Extreme",
        "measures.col.findings": "Findings",
        "settings.title": "Settings",
        "matrix.x": "Impact",
        "matrix.critical": "Critical",
    });
}
