if (typeof _registerTranslations === "function") {
    _registerTranslations("fr", {
        // ── Toolbar / nav ──────────────────────────────────
        "nav.dashboard":   "Tableau de bord",
        "nav.monitored":   "Surveillance",
        "nav.hosts":       "Hosts",
        "nav.jobs":        "Scans",
        "nav.findings":    "Findings",
        "nav.measures":    "Mesures",
        "nav.help_section":"AIDE",
        "nav.help_methodo":"Méthodologie",
        "nav.help_usage":  "Utilisation",
        "help.tab_methodo":"Méthodologie ASM",
        "help.tab_usage":  "Utilisation",

        // ── Help panel content (rendered via data-i18n-html) ─────
        "help.methodo_html":
            '<h1 class="heading-blue">Surface — Attack Surface Management</h1>' +
            '<p class="text-muted">Découverte, cartographie et surveillance continue de votre surface d\'attaque externe.</p>' +
            '<h2>Qu\'est-ce que l\'ASM ?</h2>' +
            '<p>L\'<strong>Attack Surface Management</strong> est la discipline qui consiste à identifier, inventorier et surveiller en continu tous les actifs exposés d\'une organisation — domaines, sous-domaines, hosts, IPs, services, certificats TLS, endpoints HTTP — du point de vue d\'un attaquant externe. L\'objectif est de détecter avant les attaquants les <strong>assets oubliés, mal configurés ou vulnérables</strong> qui constituent des points d\'entrée.</p>' +
            '<div class="help-tip"><strong>Pourquoi c\'est critique :</strong> 70 % des incidents documentés par l\'ANSSI et Mandiant en 2024-2025 ont comme point d\'entrée un asset que l\'organisation ignorait posséder, ou qu\'elle croyait désactivé (shadow IT, ancien site marketing, zone dev oubliée, bucket S3 abandonné, sous-domaine délégué à un SaaS disparu).</div>' +
            '<h2>Les 5 piliers de l\'ASM dans Surface</h2>' +
            '<h3>1. Découverte passive (sans toucher la cible)</h3>' +
            '<p>Surface exploite plusieurs sources publiques pour recenser les actifs sans générer le moindre trafic vers la cible :</p>' +
            '<ul>' +
                '<li><strong>Certificate Transparency (crt.sh)</strong> — chaque certificat TLS émis publiquement depuis 2018 est enregistré dans CT. Le scanner <code>ct_logs</code> interroge crt.sh pour extraire tous les hostnames ayant eu un certificat.</li>' +
                '<li><strong>SAN pivoting</strong> — lors du scan TLS d\'un host, les Subject Alternative Names du certificat révèlent des siblings partageant le même certificat.</li>' +
                '<li><strong>Email records</strong> — l\'analyse MX/SPF/DMARC/DKIM révèle les providers mail utilisés et la posture email du domaine.</li>' +
            '</ul>' +
            '<h3>2. Découverte active</h3>' +
            '<ul>' +
                '<li><strong>DNS brute-force</strong> — 1460+ mots-clés courants (générés via compound permutations) sont résolus en parallèle avec détection wildcard pour filtrer les faux positifs.</li>' +
                '<li><strong>IP range discovery</strong> — nmap ping sweep sur les plages CIDR pour trouver les hôtes réellement actifs.</li>' +
                '<li><strong>Reverse DNS</strong> — extraction des enregistrements PTR sur les IPs découvertes.</li>' +
                '<li><strong>Typosquatting</strong> — génération de 60 variantes (omission, transposition, voisins QWERTY, TLD alternatifs) pour détecter les domaines lookalike enregistrés par des tiers.</li>' +
            '</ul>' +
            '<h3>3. Évaluation de la posture</h3>' +
            '<ul>' +
                '<li><strong>Scans de ports</strong> via nmap (profils quick / standard / deep)</li>' +
                '<li><strong>Analyse TLS</strong> : validité, chaîne, expiration, self-signed, hostname mismatch</li>' +
                '<li><strong>Nuclei DAST</strong> : 12 000+ templates de la communauté ProjectDiscovery, rate-limitable pour ne pas être blacklisté</li>' +
            '</ul>' +
            '<h3>4. Détection des risques spécifiques</h3>' +
            '<ul>' +
                '<li><strong>Subdomain takeover</strong> — 25 services SaaS vulnérables (S3, GitHub Pages, Heroku, Azure, Vercel, Shopify, Fastly, ...) avec matching CNAME + empreinte HTTP + détection NXDOMAIN</li>' +
                '<li><strong>Dangling records DNS</strong> — CNAME pointant vers des ressources abandonnées</li>' +
                '<li><strong>Ports sensibles exposés</strong> — bases de données, RDP, SSH sans authentification forte, etc.</li>' +
            '</ul>' +
            '<h3>5. Triage et plan d\'action</h3>' +
            '<p>Chaque finding doit être classé en <strong>faux positif</strong> (avec justification obligatoire, conservée pour audit) ou <strong>à corriger</strong>. Un finding <em>à corriger</em> génère automatiquement une <strong>mesure corrective</strong> qui alimente le plan d\'action suivi dans l\'onglet <strong>Mesures</strong>.</p>' +
            '<h2>Philosophie « continuous discovery »</h2>' +
            '<p>L\'ASM n\'est pas un scan ponctuel mais une <strong>surveillance continue</strong>. Surface exécute les scanners via un scheduler qui relance les checks selon une fréquence configurable par asset (par défaut 24 h). Les hosts découverts automatiquement sont enrôlés comme <code>MonitoredAsset</code> et scannés à leur tour — c\'est un effet boule de neige contrôlé par le scope.</p>' +
            '<div class="help-tip"><strong>Scope :</strong> tous les scanners qui découvrent des hostnames filtrent les résultats selon le domaine parent surveillé. Une brute-force DNS sur <code>example.com</code> ne retiendra que <code>*.example.com</code>, pas les domaines externes qui pourraient apparaître dans un CT log.</div>' +
            '<h2>Limites à connaître</h2>' +
            '<ul>' +
                '<li><strong>CT logs publics</strong> — un asset certifié par un cert privé (PKI interne) n\'y apparaîtra pas</li>' +
                '<li><strong>crt.sh est parfois lent</strong> (30-90 s de timeout possibles) — le scanner retry automatiquement</li>' +
                '<li><strong>DNS brute-force</strong> dépend de la qualité de la wordlist — une wordlist plus grande (Assetnote, 100k entrées) via <code>SURFACE_DNS_BRUTE_WORDLIST</code> donnera plus de résultats au prix de scans plus longs</li>' +
                '<li><strong>Takeover detection</strong> requiert une empreinte connue — un service SaaS vulnérable non listé dans la base est loupé</li>' +
            '</ul>',

        "help.usage_html":
            '<h1 class="heading-blue">Utilisation de Surface</h1>' +
            '<p class="text-muted">Guide des 6 panels principaux — de l\'inventaire au suivi des mesures correctives.</p>' +
            '<h2>Tableau de bord</h2>' +
            '<p>Vue d\'ensemble agrégée : nombre total de findings, findings non triagés (à traiter), findings en cours de correction, faux positifs, mesures créées et mesures terminées. Sous le compteur global, une répartition par sévérité (critical → info) permet de voir rapidement où se concentrent les problèmes.</p>' +
            '<div class="help-tip"><strong>À utiliser pour :</strong> la réunion de suivi hebdo avec la direction, le reporting mensuel, ou vérifier en 5 secondes si la situation se dégrade ou s\'améliore.</div>' +
            '<h2>Surveillance (Monitoring)</h2>' +
            '<p>Le <strong>périmètre surveillé</strong> — la liste des assets que Surface doit scanner automatiquement. Trois types :</p>' +
            '<ul>' +
                '<li><strong>Domaine</strong> — un nom de domaine racine (<code>example.com</code>). Les scanners de découverte (CT logs, DNS brute, email security, TLS, takeover, typosquat) s\'appliquent.</li>' +
                '<li><strong>Host</strong> — un host unique (<code>api.example.com</code> ou <code>1.2.3.4</code>). Les scanners d\'évaluation (nmap, TLS, nuclei, takeover) s\'appliquent.</li>' +
                '<li><strong>Plage CIDR</strong> — une plage d\'IPs (<code>192.168.1.0/24</code>). Un ping sweep identifie les IPs actives puis enrôle chaque host découvert.</li>' +
            '</ul>' +
            '<p>Pour chaque asset, vous pouvez configurer :</p>' +
            '<ul>' +
                '<li>La <strong>fréquence de scan automatique</strong> (1 h, 6 h, 24 h, 7 j, 30 j, ou manuel)</li>' +
                '<li>Les <strong>scanners actifs</strong> — tous les cocher ou seulement un sous-ensemble pour personnaliser</li>' +
                '<li>Un <strong>libellé</strong> et des <strong>notes</strong> internes</li>' +
                '<li>Un <strong>toggle actif / inactif</strong> pour désactiver temporairement sans supprimer</li>' +
            '</ul>' +
            '<h2>Hosts</h2>' +
            '<p>La vue « cartes » des hosts surveillés (manuels ou auto-découverts). Chaque carte affiche :</p>' +
            '<ul>' +
                '<li>Le hostname / IP en monospace</li>' +
                '<li>Un badge <strong>auto</strong> (découvert) ou <strong>manuel</strong> (ajouté à la main)</li>' +
                '<li>La date du dernier scan</li>' +
                '<li>Les <strong>compteurs par sévérité</strong> des findings actifs (new + to_fix)</li>' +
                '<li>L\'indicateur « N à traiter » en rouge</li>' +
            '</ul>' +
            '<p>Le champ de recherche filtre par hostname, libellé, notes ou source. Cliquer sur une carte ouvre la vue <strong>détail du host</strong> avec toutes les infos, les boutons d\'action (Scanner maintenant, Modifier, Supprimer) et le tableau des findings associés — où vous pouvez triager en unitaire ou en groupe (bulk) depuis cet écran.</p>' +
            '<h2>Scans (Jobs)</h2>' +
            '<p>Historique des jobs d\'exécution — chaque tick du scheduler et chaque scan manuel crée un job. Le tableau montre la cible, le type de scanner, la source (AUTO vs MANUEL), le statut (en attente / en cours / terminé / échoué), le nombre de findings créés et la durée. Les filtres par type et statut permettent d\'isoler les scans récents ou les échecs.</p>' +
            '<div class="help-tip"><strong>Utile pour :</strong> diagnostiquer pourquoi un scan n\'a rien trouvé (échec silencieux ? timeout ?), vérifier que le scheduler tourne bien, ou lancer un scan ponctuel sur une cible non surveillée.</div>' +
            '<h2>Findings</h2>' +
            '<p>Le cœur du triage. Tous les findings remontés par les scanners atterrissent ici avec les filtres :</p>' +
            '<ul>' +
                '<li><strong>Recherche texte</strong> (titre, cible, description, scanner)</li>' +
                '<li><strong>Statut</strong> : À traiter / À corriger / Faux positifs / Corrigés / Tous</li>' +
                '<li><strong>Sévérité</strong> : critical, high, medium, low, info (multi-select)</li>' +
                '<li><strong>Type de scan</strong> : par scanner qui a émis le finding (multi-select)</li>' +
            '</ul>' +
            '<h3>Triage unitaire</h3>' +
            '<p>Chaque ligne a deux boutons rapides : <strong>À corriger</strong> et <strong>Faux positif</strong>. Cliquer ouvre une modale demandant :</p>' +
            '<ul>' +
                '<li><strong>Pour « à corriger »</strong> : un nom de mesure, une description de remédiation, un responsable (optionnel), une échéance (optionnel). La mesure est créée et apparaît dans l\'onglet Mesures.</li>' +
                '<li><strong>Pour « faux positif »</strong> : une justification <strong>obligatoire</strong>, conservée pour audit. Le finding ne sera plus ré-émis lors des scans suivants (même ID = silenced au lieu de refresh).</li>' +
            '</ul>' +
            '<h3>Triage groupé (bulk)</h3>' +
            '<p>Cocher une ou plusieurs lignes via la case à gauche fait apparaître une <strong>barre d\'action en bas de page</strong>. Vous pouvez :</p>' +
            '<ul>' +
                '<li>Déclarer <strong>N findings en faux positif</strong> avec la même justification</li>' +
                '<li>Créer une <strong>mesure corrective groupée</strong> — une mesure par finding, toutes avec le même titre / description / responsable / échéance (utile pour « upgrader nginx sur 30 hosts »)</li>' +
                '<li><strong>Supprimer définitivement</strong> N findings (cascade delete des mesures liées)</li>' +
            '</ul>' +
            '<h3>Import JSON</h3>' +
            '<p>Le bouton « Importer JSON » permet de pousser des findings produits par des scanners externes (nmap manuel, Shodan, Burp, Trivy, SBOM, pentest...). Format attendu : tableau d\'objets <code>{scanner, type, severity, title, description, target, evidence}</code>. La dedup logic standard s\'applique.</p>' +
            '<h2>Mesures</h2>' +
            '<p>Les mesures correctives créées depuis les findings à corriger. Chaque mesure a un ID court (<code>SRF-XXXXXXXX</code>), un titre, un statut (À faire / En cours / Terminé), un responsable, une échéance. Éditable en place. Les mesures constituent le plan d\'action local — leur statut et leurs champs sont persistés dans Surface.</p>' +
            '<h2>Paramètres (roue crantée en haut)</h2>' +
            '<p>Trois sections :</p>' +
            '<ul>' +
                '<li><strong>Langue</strong> : bascule FR/EN instantanée de toute l\'interface</li>' +
                '<li><strong>Assistant IA</strong> : configuration du provider (Anthropic / OpenAI), modèle et clé API (stockée localement dans le navigateur, jamais envoyée au backend)</li>' +
                '<li><strong>Nuclei</strong> : version, nombre de templates, date de mise à jour, <strong>tuning éditable</strong> (rate-limit, concurrency, bulk-size, timeout, retries) qui s\'applique immédiatement au prochain scan. Bouton « Mettre à jour les templates » pour rafraîchir la base des templates depuis upstream.</li>' +
            '</ul>' +
            '<div class="help-tip"><strong>Conseil tuning Nuclei :</strong> sur des cibles clients ou des environnements surveillés par un WAF, baissez le rate-limit à 5-10 req/s pour éviter le blacklistage. Pour vos propres assets, 20-50 req/s est confortable.</div>' +
            '<h2>Workflow typique</h2>' +
            '<ol style="font-size:0.9em;line-height:1.8">' +
                '<li>Ajouter le domaine racine dans <strong>Surveillance</strong> avec tous les scanners cochés</li>' +
                '<li>Attendre le premier tick du scheduler ou lancer un scan manuel → les sous-domaines sont découverts et enrôlés comme hosts</li>' +
                '<li>Les hosts auto-découverts sont scannés aux ticks suivants (nmap, TLS, nuclei, takeover)</li>' +
                '<li>Consulter <strong>Findings</strong> filtré sur « À traiter » → triage des findings critical / high en priorité</li>' +
                '<li>Les faux positifs sont documentés et silenced, les vrais problèmes deviennent des mesures</li>' +
                '<li>Les mesures s\'ajoutent au plan d\'action, suivi avec le responsable assigné dans l\'onglet <strong>Mesures</strong></li>' +
                '<li>Les scans continuent en tâche de fond → nouveaux findings remontent automatiquement</li>' +
            '</ol>',

        // ── Dashboard ──────────────────────────────────────
        "dash.title":          "Tableau de bord",
        "dash.findings_total": "Findings totaux",
        "dash.not_triaged":    "Non triagés",
        "dash.to_fix":         "À corriger",
        "dash.false_positive": "Faux positifs",
        "dash.measures_done":  "Mesures terminées",
        "dash.empty":          "Aucun finding pour l'instant. Importez des résultats de surface ou ajoutez-en manuellement depuis l'onglet Findings.",
        "dash.headline_critical":    "{n} finding(s) critiques à traiter — attention immédiate requise",
        "dash.headline_high":        "{n} finding(s) haute sévérité à traiter",
        "dash.headline_ok":          "Situation sous contrôle — aucun finding critique ou haut non triagé",
        "dash.new_24h":              "Nouveaux (24 h)",
        "dash.top_exposed_hosts":    "Hosts les plus exposés",
        "dash.no_hosts_at_risk":     "Aucun host avec findings actifs",
        "dash.timeline_title":       "Évolution sur 30 jours",
        "dash.timeline_triaged":     "Triagés (cumulatif)",
        "dash.top_hosts":            "Top hosts à risque",
        "dash.top_types":            "Types de findings récurrents",
        "dash.top_scanners":         "Scanners les plus bruyants",
        "dash.no_active_findings":   "Aucun finding actif",
        "dash.no_findings":          "Aucun finding",
        "dash.surface_title":        "Inventaire surveillance",
        "dash.hosts_source":         "Hosts par source",
        "dash.measures_title":       "Plan d'action",
        "dash.measures_created_7d":  "créées 7j",
        "dash.measures_done_7d":     "terminées 7j",
        "dash.measures_delta":       "delta net",
        "dash.measures_overdue":     "{n} mesure(s) en retard",
        "dash.health_title":         "Santé du scanner",
        "dash.health_jobs_24h":      "Jobs 24 h",
        "dash.health_success_rate":  "Taux de succès",
        "dash.health_failed_24h":    "Échecs 24 h",
        "dash.health_running":       "En cours",
        "dash.health_last_job":      "Dernier job :",
        "dash.health_next":          "Prochain scan :",
        "dash.gaps_title":           "Couverture & lacunes",
        "dash.gaps_stale_hosts":     "Hosts obsolètes (> 7j)",
        "dash.gaps_sparse_hosts":    "Hosts peu couverts",
        "dash.gaps_disabled_long":   "Désactivés > 30j",
        "dash.gaps_stale_list":      "Détail hosts obsolètes",

        // ── Severity labels ────────────────────────────────
        "sev.critical": "Critique",
        "sev.high":     "Haute",
        "sev.medium":   "Moyenne",
        "sev.low":      "Basse",
        "sev.info":     "Info",

        // ── Status labels ──────────────────────────────────
        "status.to_fix":         "À corriger",
        "status.false_positive": "Faux positif",
        "status.fixed":          "Corrigé",
        "status.all":            "Tous",
        "status.to_triage":      "À traiter",

        // ── Kind labels ────────────────────────────────────
        "kind.domain":   "Domaine",
        "kind.host":     "Host",
        "kind.ip_range": "Plage CIDR",

        // ── Monitored / Surveillance ───────────────────────
        "monitored.title":            "Périmètre surveillé",
        "monitored.help":             "Domaines, IP et plages CIDR à surveiller. Le bouton Scanner déclenche un quick scan ports + TLS sur chaque cible. Les plages CIDR sont passées aux scanners externes via bulk-import.",
        "monitored.scan_all":         "Scanner tout",
        "monitored.add":              "Ajouter une cible",
        "monitored.empty":            "Aucun périmètre défini. Cliquez sur + Ajouter pour commencer (domaine, IP ou CIDR).",
        "monitored.search.placeholder": "Rechercher par valeur, libellé, type, scanner...",
        "monitored.no_match":         "Aucune cible ne correspond à la recherche.",
        "monitored.count":            "cible(s)",
        "monitored.col.type":         "Type",
        "monitored.col.value":        "Valeur",
        "monitored.col.label":        "Libellé",
        "monitored.col.scanners":     "Scanners",
        "monitored.col.frequency":    "Fréquence",
        "monitored.col.enabled":      "Actif",
        "monitored.col.last_scan":    "Dernier scan",
        "monitored.col.next_scan":    "Prochain",
        "monitored.frequency_hours":  "toutes les {n} h",
        "monitored.next.imminent":    "imminent",
        "monitored.next.disabled":    "désactivé",
        "monitored.last.never":       "jamais",
        "monitored.delete_confirm":   "Supprimer cette cible ?",

        // ── Hosts panel ────────────────────────────────────
        "hosts.title":            "Hosts",
        "hosts.count":            "host(s) surveillé(s)",
        "hosts.help":             "Liste de tous les hosts surveillés, ajoutés manuellement ou découverts automatiquement par les scanners (CT logs, SAN, ping sweep). Cliquez sur une carte pour voir le détail et les findings associés.",
        "hosts.search.placeholder": "Rechercher par hostname, IP, libellé, source...",
        "hosts.no_match":         "Aucun host ne correspond à la recherche.",
        "hosts.empty":            "Aucun host surveillé. Ajoutez-en via Surveillance ou lancez un scan CT logs sur un domaine pour découvrir des sous-domaines automatiquement.",
        "hosts.source.auto":      "auto",
        "hosts.source.manual":    "manuel",
        "hosts.badge.disabled":   "désactivé",
        "hosts.last_scan":        "Dernier scan",
        "hosts.findings.none":    "Aucun finding",
        "hosts.findings.to_triage": "à traiter",

        // ── Host detail ────────────────────────────────────
        "host.back":               "Hosts",
        "host.col.value":          "Valeur",
        "host.col.label":          "Libellé",
        "host.col.enabled":        "Actif",
        "host.col.frequency":      "Fréquence",
        "host.col.last_scan":      "Dernier scan",
        "host.col.scanners":       "Scanners actifs",
        "host.col.notes":          "Notes",
        "host.frequency_hours":    "{n} heures",
        "host.scan_now":           "Scanner maintenant",
        "host.edit":               "Modifier",
        "host.delete":             "Supprimer",
        "host.findings_title":     "Findings associés",
        "host.findings_empty":     "Aucun finding associé à ce host. Lancez un scan pour en générer.",
        "host.hide_fp":            "Masquer les {n} faux positif(s)",
        "host.delete_confirm":     "Supprimer ce host ? Les findings associés resteront dans la base mais ne seront plus rattachés à un asset surveillé.",

        // ── Findings panel ─────────────────────────────────
        "findings.title":             "Findings",
        "findings.quick_scan":        "Lancer un scan",
        "findings.bulk_import":       "Importer JSON",
        "findings.search.placeholder": "Rechercher titre, cible, description, scanner...",
        "findings.filter.status":     "Statut :",
        "findings.filter.severity":   "Sévérité :",
        "findings.filter.scanner":    "Type de scan :",
        "findings.filter.hint":       "(aucun filtre = toutes)",
        "findings.filter.hint_m":     "(aucun filtre = tous)",
        "findings.filter.reset":      "x reset",
        "findings.col.severity":      "Sev.",
        "findings.col.type":          "Type",
        "findings.col.title":         "Titre",
        "findings.col.target":        "Cible",
        "findings.col.status":        "Statut",
        "findings.col.datetime":      "Date & heure",
        "findings.count":             "findings",
        "findings.empty":             "Aucun finding ne correspond aux filtres.",

        // ── Bulk action bar ────────────────────────────────
        "bulk.selected":           "finding(s) sélectionné(s)",
        "bulk.false_positive":     "Faux positif",
        "bulk.to_fix":             "Créer une mesure corrective",
        "bulk.delete":             "Supprimer",
        "bulk.clear":              "Désélectionner",
        "bulk.fp_title":           "Déclarer {n} finding(s) comme faux positifs",
        "bulk.fp_help":            "La même justification sera enregistrée sur les {n} findings sélectionnés. Elle est obligatoire et reste attachée pour audit.",
        "bulk.fp_confirm":         "Confirmer le faux positif ({n})",
        "bulk.fp_justification":   "Justification *",
        "bulk.fp_placeholder":     "Expliquer pourquoi ces findings sont des faux positifs (contexte, exception documentée, configuration intentionnelle...)",
        "bulk.measure_title":      "Créer une mesure corrective pour {n} finding(s)",
        "bulk.measure_help":       "Une mesure corrective sera créée pour chaque finding sélectionné, toutes avec le même titre/description/responsable/échéance. Elles apparaîtront groupées dans l'onglet Mesures.",
        "bulk.measure_confirm":    "Créer {n} mesure(s)",
        "bulk.measure_name":       "Nom de la mesure *",
        "bulk.measure_name_ph":    "Ex: Mettre à jour nginx sur tous les hosts exposés",
        "bulk.measure_desc":       "Description / plan de remédiation",
        "bulk.measure_desc_ph":    "Plan de remédiation commun aux findings sélectionnés...",
        "bulk.measure_resp":       "Responsable (optionnel)",
        "bulk.measure_resp_ph":    "Email ou nom",
        "bulk.measure_due":        "Échéance (optionnel)",
        "bulk.delete_confirm":     "Supprimer définitivement {n} finding(s) ? Les mesures liées seront également supprimées (cascade).",

        // ── Common actions ─────────────────────────────────
        "action.cancel":  "Annuler",
        "action.confirm": "Confirmer",
        "action.save":    "Enregistrer",
        "action.edit":    "Modifier",
        "action.delete":  "Supprimer",

        // ── Kind help texts ────────────────────────────────
        "kind.help.domain":   "Nom de domaine racine — ex: example.com, medsecure.fr",
        "kind.help.host":     "Hôte unique — IP (1.2.3.4, ::1) ou nom DNS (api.example.com)",
        "kind.help.ip_range": "Plage CIDR pour les scanners externes — ex: 192.168.1.0/24",

        // ── Scanner labels (displayed in job listings) ─────
        "scanner.nmap":                 "Nmap (ports)",
        "scanner.scheduled_host":       "Auto host (ports + TLS)",
        "scanner.scheduled_domain":     "Auto domaine (email + typosquat + TLS)",
        "scanner.scheduled_discovery":  "Auto discovery (CIDR)",

        // ── Jobs panel ─────────────────────────────────────
        "jobs.title":           "Scans",
        "jobs.new":             "Nouveau scan",
        "jobs.help":            "Liste de tous les scans (manuels et automatiques). Les jobs s'executent en arriere-plan ; cette page se rafraichit automatiquement quand un job est en cours.",
        "jobs.filter.scanner":  "Type :",
        "jobs.filter.status":   "Statut :",
        "jobs.filter.all":      "Tous",
        "jobs.col.target":      "Cible",
        "jobs.col.scanner":     "Type",
        "jobs.col.source":      "Source",
        "jobs.col.status":      "Statut",
        "jobs.col.findings":    "Findings",
        "jobs.col.started":     "Lance le",
        "jobs.col.duration":    "Duree",
        "jobs.status.pending":  "En attente",
        "jobs.status.running":  "En cours",
        "jobs.status.completed":"Terminé",
        "jobs.status.failed":   "Échoué",
        "jobs.empty":           "Aucun scan n'a ete lance. Cliquez sur + Nouveau scan pour commencer.",
        "jobs.no_match":        "Aucun scan ne correspond aux filtres.",
        "jobs.rerun":           "Relancer",
        "jobs.rerun_started":   "Nouveau scan lancé sur {target}",
        "jobs.source.manual":   "manuel",
        "jobs.source.auto":     "auto",
        "jobs.new_title":       "Nouveau scan manuel (nmap)",
        "jobs.target":          "Cible",
        "jobs.target_help":     "Hostname, IP ou plage CIDR. Pour un /24, prévoir 1-2 minutes ; pour /16, plusieurs heures (utiliser le profil deep avec patience).",
        "jobs.target_placeholder": "example.com, 1.2.3.4 ou 192.168.1.0/24",
        "jobs.profile":         "Profil",
        "jobs.profile.quick":   "Quick",
        "jobs.profile.quick_help": "top 100 ports",
        "jobs.profile.standard":"Standard",
        "jobs.profile.standard_help": "top 1000 + version",
        "jobs.profile.deep":    "Deep",
        "jobs.profile.deep_help":"tous ports + scripts",
        "jobs.pick_monitored":  "Ou choisir une cible surveillée",
        "jobs.target_required": "Cible requise",
        "jobs.launch":          "Lancer",
        "jobs.launched":        "Scan lancé",

        // ── Monitored asset modal (add/edit) ──────────────
        "mon_modal.title_add":      "Ajouter une cible",
        "mon_modal.title_edit":     "Modifier la cible",
        "mon_modal.type":           "Type",
        "mon_modal.value":          "Valeur",
        "mon_modal.label":          "Libellé",
        "mon_modal.label_ph":       "Description courte (optionnel)",
        "mon_modal.notes":          "Notes",
        "mon_modal.notes_ph":       "Notes internes (optionnel)",
        "mon_modal.frequency":      "Fréquence des scans automatiques",
        "mon_modal.frequency_help": "0 = désactivé le scan automatique",
        "mon_modal.scanners":       "Scanners actifs",
        "mon_modal.scanners_help":  "Cochez les scanners a executer. Si aucun n'est coche, les defauts s'appliquent.",
        "mon_modal.enabled":        "Actif",
        "mon_modal.value_required": "La valeur est obligatoire",
        "mon_modal.added":          "Cible ajoutée",
        "mon_modal.updated":        "Cible mise à jour",
        "mon_modal.deleted":        "Cible supprimée",
        "mon_modal.scan_in_progress":"Scan en cours...",
        "mon_modal.scan_all_confirm":"Lancer un scan sur toutes les cibles activées ?",
        "mon_modal.scan_done":       "{n} finding(s) créé(s) sur {target}",
        "mon_modal.scan_all_in_progress":"Scan global en cours...",
        "mon_modal.scan_all_done":   "{scanned} cible(s) scannée(s), {n} finding(s) créé(s)",
        "mon_modal.scan_all_errors": "{n} erreur(s)",

        // ── Finding detail ────────────────────────────────
        "fd.back":                   "Findings",
        "fd.scanner":                "Scanner",
        "fd.type":                   "Type",
        "fd.target":                 "Cible",
        "fd.created":                "Créé le",
        "fd.triaged":                "Triage",
        "fd.triaged_by":             "par",
        "fd.description":            "Description",
        "fd.description_none":       "(aucune)",
        "fd.evidence":               "Evidence",
        "fd.notes":                  "Notes",
        "fd.triage":                 "Triage",
        "fd.triage_notes_ph":        "Notes (optionnel)...",
        "fd.triage_to_fix":          "À corriger (cree une mesure)",
        "fd.triage_fp":              "Faux positif",
        "fd.triage_reset":           "Reset (non trié)",
        "fd.delete":                 "Supprimer",
        "fd.delete_confirm":         "Supprimer ce finding ?",
        "fd.deleted":                "Finding supprimé",
        "fd.measure_linked":         "Mesure associée",
        "fd.measure_status":         "Statut",
        "fd.measure_owner":          "Responsable",
        "fd.measure_due":            "Échéance",

        // ── Triage modal (single) ─────────────────────────
        "tm.title_to_fix":           "Créer une mesure corrective",
        "tm.title_fp":               "Marquer comme faux positif",
        "tm.title_reset":            "Réinitialiser le triage",
        "tm.confirm_to_fix":         "Créer la mesure",
        "tm.confirm_fp":             "Confirmer le faux positif",
        "tm.confirm_reset":          "Réinitialiser",
        "tm.finding":                "Finding :",
        "tm.measure_name":           "Nom de la mesure *",
        "tm.measure_name_help":      "Ce nom apparaitra dans le plan d'action (onglet Mesures).",
        "tm.measure_desc":           "Description / plan de remédiation",
        "tm.measure_owner":          "Responsable (optionnel)",
        "tm.measure_owner_ph":       "Email ou nom",
        "tm.measure_due":            "Échéance (optionnel)",
        "tm.fp_justif":              "Justification *",
        "tm.fp_justif_ph":           "Expliquer pourquoi ce finding est un faux positif (contexte, exception documentee, configuration intentionnelle...)",
        "tm.fp_justif_help":         "Cette justification est obligatoire et reste attachée au finding pour audit. Le finding ne sera plus ré-émis lors des prochains scans.",
        "tm.reset_help":             "Réinitialiser le statut de ce finding à \"Nouveau\" ? La mesure associée (si elle existe) sera supprimée.",
        "tm.name_required":          "Le nom de la mesure est obligatoire",
        "tm.justif_required":        "La justification est obligatoire",

        // ── Measures panel ────────────────────────────────
        "measures.title":            "Mesures correctives",
        "measures.help":             "Plan d'action issu du triage des findings. Chaque mesure est liée au finding qui l'a générée.",
        "measures.empty":            "Aucune mesure créée. Les mesures apparaissent automatiquement quand vous triez un finding en 'À corriger'.",
        "measures.col.id":           "ID",
        "measures.col.title":        "Titre",
        "measures.col.status":       "Statut",
        "measures.col.owner":        "Responsable",
        "measures.col.due":          "Échéance",
        "measures.status.a_faire":   "À faire",
        "measures.status.en_cours":  "En cours",
        "measures.status.termine":   "Terminé",
        "measures.updated":          "Mesure mise à jour",

        // ── Quick prompts (utility actions) ───────────────
        "prompt.quick_scan_host":    "Host cible (ex: example.com) :",
        "prompt.findings_imported":  "findings importés",
        "prompt.findings_skipped":   "ignorés",
        "prompt.findings_on":        "finding(s) créé(s) sur",
        "prompt.job_delete_confirm": "Supprimer ce job ? (les findings déjà créés ne seront pas effacés)",

        // ── Generic & host/nuclei inline strings ──────────
        "common.error":              "Erreur",
        "triage.status_prefix":      "Finding",
        "host.deleted":               "Host supprimé",
        "nuclei.form.rate_limit":     "Rate limit (req/s)",
        "nuclei.form.concurrency":    "Concurrency",
        "nuclei.form.bulk_size":      "Bulk size",
        "nuclei.form.timeout":        "Timeout par requête (s)",
        "nuclei.form.retries":        "Retries",
        "nuclei.form.rate_limit_h":   "Nombre max de requêtes nuclei par seconde contre une cible",
        "nuclei.form.concurrency_h":  "Nombre de templates exécutés en parallèle",
        "nuclei.form.bulk_size_h":    "Taille du batch de hosts traités en parallèle",
        "nuclei.form.timeout_h":      "Timeout d'une requete HTTP individuelle",
        "nuclei.form.retries_h":      "Nombre de retentatives en cas d'échec réseau",
        "nuclei.form.def":            "def",
        "nuclei.form.min":            "min",
        "nuclei.form.max":            "max",
        "nuclei.saved":               "Tuning nuclei sauvegardé",
        "nuclei.save_error":          "Erreur sauvegarde",
        "nuclei.save_btn":            "Sauvegarder le tuning",
        "nuclei.update_btn":          "Mettre à jour les templates",
        "nuclei.updating":            "Mise à jour en cours (1-2 min)...",
        "nuclei.templates_after":     "templates après mise à jour",
        "nuclei.not_installed":       "Nuclei n'est pas installe dans ce container.",
        "nuclei.config_error":        "Erreur : config nuclei indisponible",
        "nuclei.version":             "Version :",
        "nuclei.templates":           "Templates :",
        "nuclei.last_update":         "dernière maj :",
        "nuclei.unknown":             "inconnu",
        "nuclei.help":                "Les valeurs sauvegardees ici ecrasent les variables d'environnement SURFACE_NUCLEI_* et s'appliquent immediatement au prochain scan.",
        "nuclei.section":             "Nuclei (scanner DAST)",
        "common.loading":             "Chargement...",

        // ── Shodan settings section ───────────────────────
        "shodan.section":             "Shodan API",
        "shodan.help":                "Shodan fournit un inventaire passif des services exposés sur Internet. Une clé API permet d'activer les scanners shodan_domain (gratuit, énumération de sous-domaines) et shodan_host (1 credit Shodan par lookup, enrichissement ports/services/CVE).",
        "shodan.warning_title":       "Aucune clé configurée.",
        "shodan.warning_body":        "Sans clé, les scanners Shodan sont inactifs. La clé est stockée côté serveur (AppSettings), jamais retournée au navigateur, et peut être supprimée à tout moment.",
        "shodan.key_label":           "Clé API Shodan",
        "shodan.key_help":            "32 caractères hex. Obtenir sur shodan.io → Account → API. La clé sera testée contre /account/profile avant d'être sauvegardée.",
        "shodan.key_required":        "La clé API est obligatoire.",
        "shodan.save":                "Sauvegarder & tester",
        "shodan.saved":               "Clé Shodan sauvegardée",
        "shodan.testing":             "Test de la clé en cours...",
        "shodan.configured":          "Clé API configurée",
        "shodan.last_check":          "Dernière vérification",
        "shodan.replace":              "Remplacer",
        "shodan.delete":              "Supprimer la clé",
        "shodan.delete_confirm":      "Supprimer la clé API Shodan ? Les scanners shodan_* ne pourront plus tourner jusqu'à ce qu'une nouvelle clé soit configurée.",
        "shodan.deleted":             "Clé Shodan supprimée",

        // ── Bulk import modal ──────────────────────────────
        "bulk_import.title":            "Importer des findings depuis un JSON",
        "bulk_import.intro":            "Injectez des findings produits par un outil externe (nmap, Shodan, Trivy, Burp, pentest manuel...) pour les centraliser dans Surface. La même logique de dédup que les scanners internes s'applique.",
        "bulk_import.spec_title":       "Voir la spécification des champs",
        "bulk_import.col_field":        "Champ",
        "bulk_import.col_required":     "Requis",
        "bulk_import.col_description":  "Description",
        "bulk_import.f_title":          "Titre court du finding. C'est la seule chaîne obligatoire.",
        "bulk_import.f_severity":       "Une des valeurs : info, low, medium, high, critical. Défaut : medium.",
        "bulk_import.f_scanner":        "Identifiant de l'outil (ex: nmap, shodan, trivy, burp, manual). Défaut : manual. Utilisé pour le filtrage et la déduplication.",
        "bulk_import.f_type":           "Sous-catégorie du scanner (ex: open_port, tls_expiring, xss). Défaut : other. Une même combinaison scanner+type+target est dédupliquée.",
        "bulk_import.f_target":         "Hostname, IP, ou format host:port auquel le finding se rapporte. Utilisé pour le scope et le lien avec les assets surveillés.",
        "bulk_import.f_description":    "Explication longue + recommandation de remédiation. Affichée dans le détail du finding.",
        "bulk_import.f_evidence":       "Objet JSON libre contenant les données brutes (ports, bannières, extraits de logs, CVE, URLs...).",
        "bulk_import.wrapper_note":     "Le JSON peut être soit un tableau direct [...], soit un objet {\"findings\": [...]}. Maximum 500 findings par appel.",
        "bulk_import.sample_label":     "Exemple de format",
        "bulk_import.download_template":"Télécharger le modèle",
        "bulk_import.copy_sample":      "Copier l'exemple",
        "bulk_import.use_sample":       "Pré-remplir avec cet exemple",
        "bulk_import.copied":           "Exemple copié dans le presse-papier",
        "bulk_import.upload_label":     "Fichier .json",
        "bulk_import.paste_label":      "Ou coller le JSON directement",
        "bulk_import.submit":           "Importer",
        "bulk_import.json_error":       "JSON invalide",
        "bulk_import.structure_error":  "Structure invalide : un tableau de findings ou {findings: [...]} est attendu.",
        "bulk_import.item_not_object":  "L'élément doit être un objet JSON.",
        "bulk_import.title_required":   "Le champ 'title' est obligatoire et non vide.",
        "bulk_import.invalid_severity": "Sévérité invalide, attendu info|low|medium|high|critical",
        "bulk_import.validation_failed":"Validation échouée :",
        "bulk_import.validation_ok":    "finding(s) valides, prêts à importer",
        "bulk_import.warnings":         "avertissement(s)",
    });
}
