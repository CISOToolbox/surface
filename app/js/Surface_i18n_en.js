if (typeof _registerTranslations === "function") {
    _registerTranslations("en", {
        // ── Toolbar / nav ──────────────────────────────────
        "nav.dashboard":   "Dashboard",
        "nav.monitored":   "Monitoring",
        "nav.hosts":       "Hosts",
        "nav.jobs":        "Scans",
        "nav.findings":    "Findings",
        "nav.measures":    "Measures",
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
                '<li><strong>Typosquatting</strong> — generation of 60 variants (omission, transposition, QWERTY neighbors, alternate TLDs) to detect lookalike domains registered by third parties.</li>' +
            '</ul>' +
            '<h3>3. Posture assessment</h3>' +
            '<ul>' +
                '<li><strong>Port scans</strong> via nmap (quick/standard/deep profiles)</li>' +
                '<li><strong>TLS analysis</strong>: validity, chain, expiry, self-signed, hostname mismatch</li>' +
                '<li><strong>Nuclei DAST</strong>: 12 000+ community templates from ProjectDiscovery, rate-limitable to avoid blacklisting</li>' +
            '</ul>' +
            '<h3>4. Specific risk detection</h3>' +
            '<ul>' +
                '<li><strong>Subdomain takeover</strong> — 25 vulnerable SaaS services (S3, GitHub Pages, Heroku, Azure, Vercel, Shopify, Fastly, ...) with CNAME matching + HTTP fingerprint + NXDOMAIN detection</li>' +
                '<li><strong>Dangling DNS records</strong> — CNAMEs pointing to abandoned resources</li>' +
                '<li><strong>Sensitive exposed ports</strong> — databases, RDP, SSH without strong authentication, etc.</li>' +
            '</ul>' +
            '<h3>5. Triage and action plan</h3>' +
            '<p>Every finding must be classified as a <strong>false positive</strong> (with a mandatory justification kept for audit) or <strong>to fix</strong>. A <em>to fix</em> finding automatically generates a <strong>corrective measure</strong> that feeds the action plan tracked in the <strong>Measures</strong> tab.</p>' +
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
            '<p class="text-muted">Guide to the 6 main panels — from inventory to corrective measure tracking.</p>' +
            '<h2>Dashboard</h2>' +
            '<p>Aggregated overview: total number of findings, untriaged findings (to triage), findings being fixed, false positives, measures created and measures completed. Below the global counter, a severity breakdown (critical → info) shows at a glance where the problems are.</p>' +
            '<div class="help-tip"><strong>Use it for:</strong> weekly status meetings with management, monthly reporting, or a 5-second check to see if the situation is getting better or worse.</div>' +
            '<h2>Monitoring</h2>' +
            '<p>The <strong>monitored perimeter</strong> — the list of assets Surface must scan automatically. Three types:</p>' +
            '<ul>' +
                '<li><strong>Domain</strong> — a root domain name (<code>example.com</code>). Discovery scanners (CT logs, DNS brute, email security, TLS, takeover, typosquat) apply.</li>' +
                '<li><strong>Host</strong> — a single host (<code>api.example.com</code> or <code>1.2.3.4</code>). Assessment scanners (nmap, TLS, nuclei, takeover) apply.</li>' +
                '<li><strong>CIDR range</strong> — an IP range (<code>192.168.1.0/24</code>). A ping sweep identifies active IPs then enrolls each discovered host.</li>' +
            '</ul>' +
            '<p>For each asset, you can configure:</p>' +
            '<ul>' +
                '<li>The <strong>automatic scan frequency</strong> (1h, 6h, 24h, 7d, 30d, or manual)</li>' +
                '<li>The <strong>active scanners</strong> — tick all of them or only a subset to customize</li>' +
                '<li>A <strong>label</strong> and internal <strong>notes</strong></li>' +
                '<li>An <strong>enabled / disabled toggle</strong> to temporarily disable without deleting</li>' +
            '</ul>' +
            '<h2>Hosts</h2>' +
            '<p>The "cards" view of monitored hosts (manual or auto-discovered). Each card shows:</p>' +
            '<ul>' +
                '<li>The hostname / IP in monospace</li>' +
                '<li>An <strong>auto</strong> badge (discovered) or <strong>manual</strong> badge (added by hand)</li>' +
                '<li>The date of the last scan</li>' +
                '<li>The <strong>severity counters</strong> of active findings (new + to_fix)</li>' +
                '<li>A red "N to triage" indicator</li>' +
            '</ul>' +
            '<p>The search field filters by hostname, label, notes or source. Clicking a card opens the <strong>host detail view</strong> with all info, action buttons (Scan now, Edit, Delete) and the associated findings table — where you can triage single or bulk findings from this screen.</p>' +
            '<h2>Scans (Jobs)</h2>' +
            '<p>History of job executions — every scheduler tick and every manual scan creates a job. The table shows the target, scanner type, source (AUTO vs MANUAL), status (pending / running / completed / failed), number of findings created and duration. Type and status filters let you isolate recent scans or failures.</p>' +
            '<div class="help-tip"><strong>Useful for:</strong> diagnosing why a scan found nothing (silent failure? timeout?), checking that the scheduler is running, or launching a one-off scan on an unmonitored target.</div>' +
            '<h2>Findings</h2>' +
            '<p>The triage hub. All findings raised by scanners land here with filters:</p>' +
            '<ul>' +
                '<li><strong>Text search</strong> (title, target, description, scanner)</li>' +
                '<li><strong>Status</strong>: To triage / To fix / False positives / Fixed / All</li>' +
                '<li><strong>Severity</strong>: critical, high, medium, low, info (multi-select)</li>' +
                '<li><strong>Scanner type</strong>: by scanner that raised the finding (multi-select)</li>' +
            '</ul>' +
            '<h3>Single triage</h3>' +
            '<p>Each row has two quick buttons: <strong>To fix</strong> and <strong>False positive</strong>. Clicking opens a modal asking:</p>' +
            '<ul>' +
                '<li><strong>For "to fix"</strong>: a measure name, a remediation description, an owner (optional), a deadline (optional). The measure is created and appears in the Measures tab.</li>' +
                '<li><strong>For "false positive"</strong>: a <strong>mandatory</strong> justification kept for audit. The finding will not be re-raised in subsequent scans (same ID = silenced instead of refreshed).</li>' +
            '</ul>' +
            '<h3>Bulk triage</h3>' +
            '<p>Ticking one or more rows via the left checkbox pops up a <strong>sticky action bar at the bottom of the page</strong>. You can:</p>' +
            '<ul>' +
                '<li>Mark <strong>N findings as false positive</strong> with the same justification</li>' +
                '<li>Create a <strong>grouped corrective measure</strong> — one measure per finding, all sharing the same title/description/owner/deadline (useful for "upgrade nginx on 30 hosts")</li>' +
                '<li><strong>Permanently delete</strong> N findings (cascade delete of linked measures)</li>' +
            '</ul>' +
            '<h3>JSON import</h3>' +
            '<p>The "Import JSON" button lets you push findings produced by external scanners (manual nmap, Shodan, Burp, Trivy, SBOM, pentest...). Expected format: an array of objects <code>{scanner, type, severity, title, description, target, evidence}</code>. Standard dedup logic applies.</p>' +
            '<h2>Measures</h2>' +
            '<p>Corrective measures created from findings marked "to fix". Each measure has a short ID (<code>SRF-XXXXXXXX</code>), a title, a status (To do / In progress / Done), an owner, a deadline. Editable in place. Measures form the local action plan — their status and fields are persisted inside Surface.</p>' +
            '<h2>Settings (gear icon at the top)</h2>' +
            '<p>Three sections:</p>' +
            '<ul>' +
                '<li><strong>Language</strong>: instant FR/EN toggle for the whole UI</li>' +
                '<li><strong>AI assistant</strong>: configure provider (Anthropic / OpenAI), model and API key (stored locally in the browser, never sent to the backend)</li>' +
                '<li><strong>Nuclei</strong>: version, template count, last update date, <strong>editable tuning</strong> (rate-limit, concurrency, bulk-size, timeout, retries) which applies immediately on the next scan. "Update templates" button to refresh the templates database from upstream.</li>' +
            '</ul>' +
            '<div class="help-tip"><strong>Nuclei tuning tip:</strong> on client targets or WAF-protected environments, lower the rate-limit to 5-10 req/s to avoid blacklisting. For your own assets, 20-50 req/s is comfortable.</div>' +
            '<h2>Typical workflow</h2>' +
            '<ol style="font-size:0.9em;line-height:1.8">' +
                '<li>Add the root domain in <strong>Monitoring</strong> with all scanners ticked</li>' +
                '<li>Wait for the first scheduler tick or run a manual scan → subdomains are discovered and enrolled as hosts</li>' +
                '<li>Auto-discovered hosts are scanned on subsequent ticks (nmap, TLS, nuclei, takeover)</li>' +
                '<li>Open <strong>Findings</strong> filtered on "To triage" → triage critical/high findings first</li>' +
                '<li>False positives are documented and silenced, real issues become measures</li>' +
                '<li>Measures are added to the action plan, followed up with the assigned owner in the <strong>Measures</strong> tab</li>' +
                '<li>Scans keep running in the background → new findings appear automatically</li>' +
            '</ol>',

        // ── Dashboard ──────────────────────────────────────
        "dash.title":          "Dashboard",
        "dash.findings_total": "Total findings",
        "dash.not_triaged":    "Not triaged",
        "dash.to_fix":         "To fix",
        "dash.false_positive": "False positives",
        "dash.measures_done":  "Measures done",
        "dash.empty":          "No findings yet. Import surface results or add some manually from the Findings tab.",
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
        "status.to_fix":         "To fix",
        "status.false_positive": "False positive",
        "status.fixed":          "Fixed",
        "status.all":            "All",
        "status.to_triage":      "To triage",

        // ── Kind labels ────────────────────────────────────
        "kind.domain":   "Domain",
        "kind.host":     "Host",
        "kind.ip_range": "CIDR range",

        // ── Monitored / Surveillance ───────────────────────
        "monitored.title":            "Monitored perimeter",
        "monitored.help":             "Domains, IPs and CIDR ranges to monitor. The Scan button triggers a quick port + TLS scan on each target. CIDR ranges are handed to external scanners via bulk-import.",
        "monitored.scan_all":         "Scan all",
        "monitored.add":              "Add target",
        "monitored.empty":            "No perimeter defined. Click + Add to start (domain, IP or CIDR).",
        "monitored.search.placeholder": "Search by value, label, type, scanner...",
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
        "hosts.last_scan":        "Last scan",
        "hosts.findings.none":    "No findings",
        "hosts.findings.to_triage": "to triage",

        // ── Host detail ────────────────────────────────────
        "host.back":               "Hosts",
        "host.col.value":          "Value",
        "host.col.label":          "Label",
        "host.col.enabled":        "Enabled",
        "host.col.frequency":      "Frequency",
        "host.col.last_scan":      "Last scan",
        "host.col.scanners":       "Active scanners",
        "host.col.notes":          "Notes",
        "host.frequency_hours":    "{n} hours",
        "host.scan_now":           "Scan now",
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
        "bulk.measure_name":       "Measure name *",
        "bulk.measure_name_ph":    "Ex: Upgrade nginx on all exposed hosts",
        "bulk.measure_desc":       "Description / remediation plan",
        "bulk.measure_desc_ph":    "Remediation plan shared by the selected findings...",
        "bulk.measure_resp":       "Owner (optional)",
        "bulk.measure_resp_ph":    "Email or name",
        "bulk.measure_due":        "Deadline (optional)",
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

        // ── Scanner labels (displayed in job listings) ─────
        "scanner.nmap":                 "Nmap (ports)",
        "scanner.scheduled_host":       "Auto host (ports + TLS)",
        "scanner.scheduled_domain":     "Auto domain (email + typosquat + TLS)",
        "scanner.scheduled_discovery":  "Auto discovery (CIDR)",

        // ── Jobs panel ─────────────────────────────────────
        "jobs.title":           "Scans",
        "jobs.new":             "New scan",
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
        "jobs.status.failed":   "Failed",
        "jobs.empty":           "No scan has been run. Click + New scan to start.",
        "jobs.no_match":        "No scan matches the filters.",
        "jobs.rerun":           "Rerun",
        "jobs.rerun_started":   "New scan started on {target}",
        "jobs.source.manual":   "manual",
        "jobs.source.auto":     "auto",
        "jobs.new_title":       "New manual scan (nmap)",
        "jobs.target":          "Target",
        "jobs.target_help":     "Hostname, IP or CIDR range. For a /24, plan 1-2 minutes; for a /16, several hours (use the deep profile patiently).",
        "jobs.target_placeholder": "example.com, 1.2.3.4 or 192.168.1.0/24",
        "jobs.profile":         "Profile",
        "jobs.profile.quick":   "Quick",
        "jobs.profile.quick_help": "top 100 ports",
        "jobs.profile.standard":"Standard",
        "jobs.profile.standard_help": "top 1000 + version",
        "jobs.profile.deep":    "Deep",
        "jobs.profile.deep_help":"all ports + scripts",
        "jobs.pick_monitored":  "Or pick a monitored target",
        "jobs.target_required": "Target required",
        "jobs.launch":          "Launch",
        "jobs.launched":        "Scan launched",

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
        "mon_modal.enabled":        "Enabled",
        "mon_modal.value_required": "Value is required",
        "mon_modal.added":          "Target added",
        "mon_modal.updated":        "Target updated",
        "mon_modal.deleted":        "Target deleted",
        "mon_modal.scan_in_progress":"Scan in progress...",
        "mon_modal.scan_all_confirm":"Run a scan on all enabled targets?",
        "mon_modal.scan_done":       "{n} finding(s) created on {target}",
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
        "fd.description_none":       "(none)",
        "fd.evidence":               "Evidence",
        "fd.notes":                  "Notes",
        "fd.triage":                 "Triage",
        "fd.triage_notes_ph":        "Notes (optional)...",
        "fd.triage_to_fix":          "To fix (creates a measure)",
        "fd.triage_fp":              "False positive",
        "fd.triage_reset":           "Reset (untriaged)",
        "fd.delete":                 "Delete",
        "fd.delete_confirm":         "Delete this finding?",
        "fd.deleted":                "Finding deleted",
        "fd.measure_linked":         "Linked measure",
        "fd.measure_status":         "Status",
        "fd.measure_owner":          "Owner",
        "fd.measure_due":            "Deadline",

        // ── Triage modal (single) ─────────────────────────
        "tm.title_to_fix":           "Create a corrective measure",
        "tm.title_fp":               "Mark as false positive",
        "tm.title_reset":            "Reset triage",
        "tm.confirm_to_fix":         "Create measure",
        "tm.confirm_fp":             "Confirm false positive",
        "tm.confirm_reset":          "Reset",
        "tm.finding":                "Finding:",
        "tm.measure_name":           "Measure name *",
        "tm.measure_name_help":      "This name will appear in the action plan (Measures tab).",
        "tm.measure_desc":           "Description / remediation plan",
        "tm.measure_owner":          "Owner (optional)",
        "tm.measure_owner_ph":       "Email or name",
        "tm.measure_due":            "Deadline (optional)",
        "tm.fp_justif":              "Justification *",
        "tm.fp_justif_ph":           "Explain why this finding is a false positive (context, documented exception, intentional configuration...)",
        "tm.fp_justif_help":         "This justification is mandatory and kept attached to the finding for audit. The finding will not be re-raised in later scans.",
        "tm.reset_help":             "Reset this finding to 'New'? The linked measure (if any) will be deleted.",
        "tm.name_required":          "Measure name is required",
        "tm.justif_required":        "Justification is required",

        // ── Measures panel ────────────────────────────────
        "measures.title":            "Corrective measures",
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
        "measures.updated":          "Measure updated",

        // ── Quick prompts (utility actions) ───────────────
        "prompt.quick_scan_host":    "Target host (e.g. example.com):",
        "prompt.findings_imported":  "findings imported",
        "prompt.findings_skipped":   "skipped",
        "prompt.findings_on":        "finding(s) created on",
        "prompt.job_delete_confirm": "Delete this job? (findings already created will not be affected)",

        // ── Generic & host/nuclei inline strings ──────────
        "common.error":              "Error",
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
    });
}
