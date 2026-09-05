if (typeof _registerTranslations === "function") {
    _registerTranslations("fr", {
        "ai.error": "Erreur : {msg}",
        "menu_file":              "Fichier",
        "menu.import_hosts":      "Importer hôtes",
        "menu.export_report":     "Exporter rapport",
        "feature.coming_soon":    "Fonctionnalité à venir",
        // ── Toolbar / nav ──────────────────────────────────
        "nav.monitored":   "Surveillance",
        "nav.hosts":       "Hosts",
        "nav.jobs":        "Scans",
        "nav.findings":    "Findings",
        "nav.measures":    "Plan d'action",
        "nav.audit":"Journal d'audit",
        "audit.title":"Journal d'audit",
        "audit.search":"Rechercher...",
        "audit.empty":"Aucune entree dans le journal",
        "audit.entries":"entrees",
        "audit.col_date":"Date",
        "audit.col_user":"Utilisateur",
        "audit.col_action":"Action",
        "audit.col_target":"Cible",
        "audit.col_details":"Details",
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
            '<div class="ct-help-tip"><strong>Pourquoi c\'est critique :</strong> 70 % des incidents documentés par l\'ANSSI et Mandiant en 2024-2025 ont comme point d\'entrée un asset que l\'organisation ignorait posséder, ou qu\'elle croyait désactivé (shadow IT, ancien site marketing, zone dev oubliée, bucket S3 abandonné, sous-domaine délégué à un SaaS disparu).</div>' +
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
                '<li><strong>Typosquatting</strong> — génération de variantes lookalike (omission, transposition, voisins QWERTY, TLD alternatifs — plafond réglable par domaine, 80 par défaut) avec corrélation optionnelle des CT logs, pour détecter les domaines enregistrés par des tiers.</li>' +
            '</ul>' +
            '<h3>3. Évaluation de la posture</h3>' +
            '<ul>' +
                '<li><strong>Scans de ports</strong> via nmap (profils quick / standard / deep)</li>' +
                '<li><strong>Analyse TLS</strong> : validité, chaîne, expiration, self-signed, hostname mismatch</li>' +
                '<li><strong>TLS grade (A-F)</strong> — probe des versions TLS 1.0/1.1/1.2/1.3 et SSL 3.0, inspection du cipher négocié, détection des suites faibles (RC4, 3DES, NULL, EXPORT, MD5). Une note globale matérialise l\'écart par rapport aux recommandations Mozilla.</li>' +
                '<li><strong>Security headers grade (A-F)</strong> — note HSTS, Content-Security-Policy (pénalisée si <code>unsafe-inline/eval</code>), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Produit un diagnostic Mozilla Observatory-lite sans dépendance externe.</li>' +
                '<li><strong>CVE matching NVD + EPSS + KEV</strong> — le scanner <code>cve_lookup</code> consomme la sortie tech-detect de nuclei (wappalyzer), interroge l\'API NVD 2.0, enrichit chaque CVE avec sa probabilité EPSS et un flag CISA KEV. Les détections sans version sont écartées pour éviter le bruit.</li>' +
                '<li><strong>Nuclei DAST</strong> : 12 000+ templates de la communauté ProjectDiscovery, rate-limitable pour ne pas être blacklisté</li>' +
            '</ul>' +
            '<h3>4. Détection des risques spécifiques</h3>' +
            '<ul>' +
                '<li><strong>Subdomain takeover</strong> — 25 services SaaS vulnérables (S3, GitHub Pages, Heroku, Azure, Vercel, Shopify, Fastly, ...) avec matching CNAME + empreinte HTTP + détection NXDOMAIN</li>' +
                '<li><strong>Dangling records DNS</strong> — CNAME pointant vers des ressources abandonnées</li>' +
                '<li><strong>Ports sensibles exposés</strong> — bases de données, RDP, SSH sans authentification forte, etc.</li>' +
            '</ul>' +
            '<h3>5. Secrets, misconfigurations et fuites</h3>' +
            '<p>Une 4<sup>ème</sup> phase orientée <em>post-découverte</em> examine les assets déjà connus à la recherche de fuites directement exploitables :</p>' +
            '<ul>' +
                '<li><strong>Fichiers sensibles exposés (<code>sensitive_files</code>)</strong> — probe 28 chemins critiques (<code>/.git/config</code>, <code>/.env</code>, <code>/backup.sql</code>, <code>/wp-config.php</code>, <code>/.aws/credentials</code>, <code>/phpinfo.php</code>, <code>/docker-compose.yml</code>, <code>/swagger.json</code>…) et ne flag que les réponses HTTP 200 dont le corps contient la signature attendue (réduction du bruit).</li>' +
                '<li><strong>Analyse de bundles JS (<code>js_analysis</code>)</strong> — télécharge chaque <code>&lt;script src&gt;</code> (borné 512 KB × 20 fichiers) du domaine cible et grep 12 patterns de secrets : AWS Access/Secret Key, Google API, Slack webhook, Stripe live, Sentry DSN, JWT, IP privée, buckets S3/Azure/GCS, Firebase. Les secrets critical/high sont stockés masqués (<code>abcd…wxyz</code>) pour ne pas les reproduire côté base.</li>' +
                '<li><strong>Énumération de buckets cloud (<code>cloud_buckets</code>)</strong> — génère 80 candidats de nom (préfixes <em>static-/cdn-/backup-</em>, suffixes <em>-prod/-staging/-dev/-backup</em>) et probe S3, Azure Blob, GCS, DigitalOcean Spaces. Un 200 sur <code>&lt;ListBucketResult&gt;</code> est flaggé high (contenu listable), un 403 medium (bucket existe).</li>' +
            '</ul>' +
            '<div class="ct-help-tip"><strong>Anti-SSRF :</strong> chacun de ces scanners passe par <code>_resolve_safe_target</code> (blocklist loopback / RFC1918 sensibles / metadata cloud / docker siblings) et re-valide chaque URL secondaire (scripts JS, redirects) avant fetch. Une page HTML hostile ne peut pas détourner <code>js_analysis</code> vers une ressource interne.</div>' +
            '<h2>Modèle de sévérité</h2>' +
            '<p>Chaque finding porte une sévérité sur 5 niveaux, avec l\'échelle de couleurs harmonisée de la suite (teinte / remplissage / aplat identiques dans tous les modules) :</p>' +
            '<table><thead><tr><th>Niveau</th><th>Signification</th><th>Attente de traitement</th></tr></thead><tbody>' +
            '<tr><td><strong>Critical</strong></td><td>Exploitable directement (takeover, secret exposé, CVE KEV)</td><td>Traitement immédiat</td></tr>' +
            '<tr><td><strong>High</strong></td><td>Risque élevé d\'exploitation ou d\'exposition de données</td><td>Sous quelques jours</td></tr>' +
            '<tr><td><strong>Medium</strong></td><td>Affaiblissement notable de la posture (config faible, service sensible)</td><td>Planifié</td></tr>' +
            '<tr><td><strong>Low</strong></td><td>Écart mineur aux bonnes pratiques</td><td>Opportuniste</td></tr>' +
            '<tr><td><strong>Info</strong></td><td>Trace d\'audit (scan propre, découverte, TLS valide)</td><td>Aucune action — jamais compté comme « à traiter »</td></tr>' +
            '</tbody></table>' +
            '<p>Les findings <em>info</em> sont exclus des compteurs d\'alerte et du score de risque : ils documentent, ils n\'alertent pas. Le <strong>score de risque par host (0-100)</strong> pondère les findings actifs par sévérité (critical ×10, high ×5, medium ×2, low ×0.5) puis multiplie par la <strong>criticité métier</strong> déclarée sur l\'asset (facteur 1 à 4) : un asset critique remonte avant un asset secondaire à findings égaux.</p>' +
            '<h2>Cycle de vie d\'un finding</h2>' +
            '<p>Quatre statuts : <strong>Nouveau</strong> (non triagé), <strong>À corriger</strong> (vrai problème, remédiation créée), <strong>Faux positif</strong> (justifié, silencé), <strong>Corrigé</strong>. La déduplication repose sur la clé <code>scanner|type|cible</code> — le même problème logique n\'est jamais dupliqué entre deux scans :</p>' +
            '<ul>' +
                '<li><strong>Nouveau</strong> re-détecté → contenu et sévérité rafraîchis, pas de doublon.</li>' +
                '<li><strong>Faux positif</strong> re-détecté → silencé : jamais ré-émis, la justification reste opposable en audit.</li>' +
                '<li><strong>À corriger</strong> avec remédiation non terminée → silencé (le travail est déjà planifié). Remédiation terminée mais problème re-détecté → <strong>réouvert</strong> en Nouveau : la remédiation n\'a pas tenu.</li>' +
                '<li><strong>Corrigé</strong> re-détecté → réouvert en Nouveau.</li>' +
            '</ul>' +
            '<h2>Doctrine de triage</h2>' +
            '<p>Chaque finding actionnable doit recevoir une décision explicite — c\'est la discipline qui distingue un ASM utile d\'une liste d\'alertes ignorées :</p>' +
            '<ul>' +
                '<li><strong>Prioriser par sévérité puis par criticité métier</strong> — traiter d\'abord les critical/high des assets critiques.</li>' +
                '<li><strong>À corriger</strong> engage : la décision crée une <strong>remédiation</strong> (titre, responsable, échéance) qui alimente le plan d\'action. Pas de triage « à corriger » sans remédiation.</li>' +
                '<li><strong>Faux positif</strong> exige une <strong>justification obligatoire</strong>, horodatée et conservée pour audit — un FP non justifié est une dette de traçabilité.</li>' +
                '<li><strong>Corrigé</strong> est une assertion vérifiable : le scan suivant la contredit en réouvrant le finding si le problème persiste.</li>' +
                '<li><strong>Triage assisté par IA</strong> : l\'analyse IA fournit un avis structuré (probabilité de faux positif, confiance, sévérité recommandée, remédiation, références) enrichi des données NVD. C\'est une aide à la décision — l\'IA propose, l\'humain décide et reste responsable du statut final.</li>' +
            '</ul>' +
            '<h2>Philosophie « continuous discovery »</h2>' +
            '<p>L\'ASM n\'est pas un scan ponctuel mais une <strong>surveillance continue</strong>. Surface exécute les scanners via un scheduler qui relance les checks selon une fréquence configurable par asset (par défaut 24 h). Les hosts découverts automatiquement sont enrôlés comme <code>MonitoredAsset</code> et scannés à leur tour — c\'est un effet boule de neige contrôlé par le scope.</p>' +
            '<div class="ct-help-tip"><strong>Scope :</strong> tous les scanners qui découvrent des hostnames filtrent les résultats selon le domaine parent surveillé. Une brute-force DNS sur <code>example.com</code> ne retiendra que <code>*.example.com</code>, pas les domaines externes qui pourraient apparaître dans un CT log.</div>' +
            '<h2>Intégration à la suite CISO Toolbox</h2>' +
            '<p>En déploiement suite, les <strong>remédiations</strong> de ce module remontent automatiquement dans le <strong>plan d\'action de Pilot</strong> (hub de gouvernance), y sont consolidées avec les items des autres modules sous le terme commun <strong>Action</strong>, et peuvent être regroupées en <strong>projets</strong> pour piloter l\'avancement transverse. Le module reste l\'autorité de son domaine — Pilot ne fait que consolider.</p>' +
            '<h2>Limites à connaître</h2>' +
            '<ul>' +
                '<li><strong>CT logs publics</strong> — un asset certifié par un cert privé (PKI interne) n\'y apparaîtra pas</li>' +
                '<li><strong>crt.sh est parfois lent</strong> (30-90 s de timeout possibles) — le scanner retry automatiquement</li>' +
                '<li><strong>DNS brute-force</strong> dépend de la qualité de la wordlist — une wordlist plus grande (Assetnote, 100k entrées) via <code>SURFACE_DNS_BRUTE_WORDLIST</code> donnera plus de résultats au prix de scans plus longs</li>' +
                '<li><strong>Takeover detection</strong> requiert une empreinte connue — un service SaaS vulnérable non listé dans la base est loupé</li>' +
            '</ul>',

        "help.usage_html":
            '<h1 class="heading-blue">Utilisation de Surface</h1>' +
            '<p class="text-muted">Guide des pages du module — Tableau de bord, Surveillance, Hosts, Scans, Findings, Plan d\'action, plus le Journal d\'audit (administrateurs). Les boutons FR/EN et clair/sombre sont dans la barre du haut.</p>' +
            '<h2>Tableau de bord</h2>' +
            '<p>Vue d\'ensemble en cartes :</p>' +
            '<ul>' +
                '<li><strong>Bandeau d\'alerte</strong> — compteurs Critical / High non triagés et « Nouveaux (24 h) ». Chaque tuile est cliquable et ouvre Findings pré-filtré.</li>' +
                '<li><strong>Hosts les plus exposés</strong> et <strong>Top hosts à risque</strong> — cliquer un host filtre Findings sur sa cible.</li>' +
                '<li><strong>Évolution sur 30 jours</strong> — une courbe par sévérité (cumul des findings existants) plus la courbe pointillée des triages cumulés.</li>' +
                '<li><strong>Types de findings récurrents</strong> et <strong>Scanners les plus bruyants</strong>.</li>' +
                '<li><strong>Inventaire surveillance</strong> — répartition par type d\'asset et hosts auto vs manuels.</li>' +
                '<li><strong>Plan d\'action</strong> — barre d\'avancement À faire / En cours / Terminé, delta 7 jours, remédiations en retard.</li>' +
                '<li><strong>Santé du scanner</strong> — jobs 24 h, taux de succès, échecs, scans en cours, prochain scan planifié.</li>' +
            '</ul>' +
            '<p>Boutons d\'en-tête : <strong>Scanner tout</strong>, <strong>Ajouter une cible</strong>, <strong>Importer JSON</strong>.</p>' +
            '<div class="ct-help-tip"><strong>À utiliser pour :</strong> la réunion de suivi hebdo, le reporting, ou vérifier en 5 secondes si la situation se dégrade ou s\'améliore.</div>' +
            '<h2>Surveillance</h2>' +
            '<p>Le <strong>périmètre surveillé</strong> — la liste des cibles que Surface scanne automatiquement. Trois types de base :</p>' +
            '<ul>' +
                '<li><strong>Domaine</strong> — un nom de domaine racine (<code>example.com</code>). Les scanners de découverte (CT logs, DNS brute, email security, TLS, takeover, typosquatting) s\'appliquent.</li>' +
                '<li><strong>Host</strong> — un host unique (<code>api.example.com</code> ou <code>1.2.3.4</code>). Les scanners d\'évaluation (nmap, TLS, nuclei, takeover) s\'appliquent.</li>' +
                '<li><strong>Plage CIDR</strong> — une plage d\'IPs (<code>192.168.1.0/24</code>). Un ping sweep identifie les IPs actives puis enrôle chaque host découvert.</li>' +
            '</ul>' +
            '<p>Des add-ons peuvent ajouter d\'autres types (ex. partage de fichiers SMB) — leur documentation apparaît dans cette aide quand ils sont installés. La modale <strong>Ajouter / Modifier une cible</strong> permet de configurer :</p>' +
            '<ul>' +
                '<li>La <strong>fréquence de scan automatique</strong> (1 h, 6 h, 24 h, 7 j, 30 j, ou 0 = manuel uniquement)</li>' +
                '<li>Les <strong>scanners actifs</strong> — la liste proposée dépend du type de cible ; cochez tout ou un sous-ensemble</li>' +
                '<li>La <strong>criticité métier</strong> (Low / Medium / High / Critical) — elle pondère le score de risque</li>' +
                '<li>Des <strong>tags</strong>, un <strong>libellé</strong> et des <strong>notes</strong> internes</li>' +
                '<li><strong>Auto-enrôler les sous-domaines découverts</strong> — les découvertes deviennent elles-mêmes des cibles surveillées</li>' +
                '<li>Le <strong>mode discret (anti-WAF)</strong> — scans moins agressifs</li>' +
                '<li>Un <strong>toggle actif / inactif</strong> pour suspendre sans supprimer</li>' +
            '</ul>' +
            '<p>La page offre une <strong>recherche libre</strong>, des <strong>pastilles de filtre par type de scan</strong>, et des cases à cocher pour les actions groupées : <strong>Forcer un scan</strong>, <strong>Appliquer des scans</strong> (même jeu de scanners sur N cibles ; pour un domaine unique, la boîte expose aussi les réglages typosquatting), <strong>Supprimer</strong>. Chaque ligne a ses boutons scan / éditer / supprimer, et affiche le dernier et le prochain scan planifié.</p>' +
            '<h2>Hosts</h2>' +
            '<p>La vue « cartes » des hosts surveillés (manuels ou auto-découverts). Les hostnames résolvant vers la même IP sont <strong>regroupés sur une seule carte</strong> (alias cliquables). Chaque carte affiche :</p>' +
            '<ul>' +
                '<li>Le hostname / IP, l\'IP résolue et les éventuels alias</li>' +
                '<li>Le <strong>score de risque (0-100)</strong> coloré par palier</li>' +
                '<li>Des badges <strong>auto</strong> / <strong>manuel</strong> / <strong>désactivé</strong> / <strong>partage</strong>, la criticité métier et les tags</li>' +
                '<li>Une <strong>miniature de capture d\'écran</strong> du service web quand elle existe</li>' +
                '<li>La date du dernier scan, les <strong>compteurs par sévérité</strong> des findings actifs et l\'indicateur « N à traiter »</li>' +
                '<li>Un pied de carte avec le nombre de scanners actifs et un bouton <strong>Configurer</strong> (choix rapide des scanners)</li>' +
            '</ul>' +
            '<p>Le champ de recherche filtre par hostname, libellé ou notes. Cliquer sur une carte ouvre la vue <strong>détail du host</strong> : fiche complète, boutons <strong>Scanner maintenant</strong> / <strong>Modifier</strong> / <strong>Supprimer</strong>, <strong>historique des scans</strong> (8 derniers jobs avec le différentiel +N nouveaux / ↻N réouverts), tuiles de synthèse par sévérité, case « Masquer les N faux positifs », et le tableau des findings associés — triables en unitaire ou en groupe exactement comme dans la page Findings. Pour un serveur de fichiers, la fiche liste tous ses partages avec leurs actions propres.</p>' +
            '<h2>Scans</h2>' +
            '<p>Historique des jobs — chaque tick du scheduler et chaque scan manuel crée un job. Le tableau montre la cible, le type de scanner, la source (AUTO vs MANUEL), le statut (<strong>En attente / En cours / Terminé / Partiel / Échoué</strong>), le nombre de findings avec le différentiel (+N nouveaux, ↻N réouverts), la date de lancement et la durée. Filtres par type de scanner et par statut. Chaque job terminé peut être <strong>relancé</strong> (bouton ↻) ou supprimé. La page se <strong>rafraîchit automatiquement</strong> tant qu\'un job tourne.</p>' +
            '<div class="ct-help-tip"><strong>Utile pour :</strong> diagnostiquer pourquoi un scan n\'a rien trouvé (échec silencieux ? timeout ?), vérifier que le scheduler tourne bien, ou relancer un scan qui a échoué.</div>' +
            '<h2>Findings</h2>' +
            '<p>Le cœur du triage. Tous les findings remontés par les scanners atterrissent ici avec les filtres :</p>' +
            '<ul>' +
                '<li><strong>Recherche texte</strong> (titre, cible, description, scanner, type)</li>' +
                '<li><strong>Statut</strong> : Ouverts (= Nouveau + À corriger, filtre par défaut) / Nouveau / À corriger / Faux positif / Corrigé / Tous</li>' +
                '<li><strong>Sévérité</strong> : Critical, High, Medium, Low, Info (multi-sélection)</li>' +
                '<li><strong>Type de scan</strong> : par scanner qui a émis le finding (multi-sélection)</li>' +
            '</ul>' +
            '<h3>Triage unitaire</h3>' +
            '<p>Chaque ligne offre deux boutons rapides : <strong>À corriger</strong> et <strong>Faux positif</strong>. Cliquer sur la ligne ouvre la <strong>vue détail</strong> (description, evidence, capture d\'écran éventuelle, remédiation liée) avec les boutons <strong>À corriger</strong>, <strong>Faux positif</strong>, <strong>Corrigé</strong>, <strong>Réinitialiser</strong> (retour à Nouveau), <strong>Analyse IA</strong> et <strong>Supprimer</strong>. La modale de triage demande :</p>' +
            '<ul>' +
                '<li><strong>À corriger</strong> : un nom de remédiation, une description, un responsable (annuaire, optionnel), une échéance (optionnel). La remédiation est créée et apparaît dans le Plan d\'action.</li>' +
                '<li><strong>Faux positif</strong> : une justification <strong>obligatoire</strong>, conservée pour audit. Le finding est silencé et ne sera plus ré-émis par les scans suivants.</li>' +
                '<li><strong>Corrigé</strong> : simple confirmation — le finding réapparaîtra s\'il est re-détecté au prochain scan.</li>' +
            '</ul>' +
            '<h3>Triage groupé (bulk)</h3>' +
            '<p>Cocher une ou plusieurs lignes via la case à gauche fait apparaître une <strong>barre d\'action en bas de page</strong>. Vous pouvez :</p>' +
            '<ul>' +
                '<li><strong>Créer une remédiation</strong> — UNE seule remédiation, liée aux N findings sélectionnés (utile pour « upgrader nginx sur 30 hosts »)</li>' +
                '<li>Marquer <strong>N findings Corrigé</strong> après confirmation</li>' +
                '<li>Déclarer <strong>N findings Faux positif</strong> avec la même justification</li>' +
                '<li><strong>Supprimer définitivement</strong> N findings (irréversible)</li>' +
            '</ul>' +
            '<h3>Lancer un scan / Import JSON</h3>' +
            '<p>Le bouton <strong>Lancer un scan</strong> déclenche un scan rapide ports + TLS sur un host saisi à la volée, même hors périmètre surveillé. Le bouton <strong>Importer JSON</strong> ouvre une modale complète : spécification du format inline, gabarit téléchargeable / copiable, import par fichier ou copier-coller, et validation avant envoi. Format attendu : tableau d\'objets <code>{scanner, type, severity, title, description, target, evidence}</code> (seul <code>title</code> est obligatoire). La déduplication standard s\'applique.</p>' +
            '<h2>Plan d\'action</h2>' +
            '<p>Les remédiations créées depuis les findings « à corriger ». Chaque remédiation a un ID court (<code>SRF-XXXXXXXX</code>), un titre, le nombre de findings couverts, un statut (À faire / En cours / Terminé), un responsable, une échéance (mise en évidence si dépassée). Cliquer sur une ligne ouvre la modale d\'édition, avec un <strong>journal de suivi</strong> pour horodater l\'avancement. Les cases à cocher permettent de marquer <strong>Terminé</strong> ou de <strong>Supprimer</strong> en masse.</p>' +
            '<h2>Digest hebdomadaire par email</h2>' +
            '<p>Une fois SMTP configuré (voir Paramètres), Surface envoie <strong>automatiquement</strong> un digest HTML chaque semaine : résumé des compteurs, top 10 findings à traiter, top 10 hosts exposés, statistiques scans et remédiations. Le scheduler vérifie toutes les heures si 7 jours se sont écoulés depuis le dernier envoi (<code>digest.last_sent_at</code> en base). Un bouton <strong>Envoyer maintenant</strong> dans la section SMTP permet d\'envoyer un digest ad-hoc (manuel) sans attendre le prochain tick hebdomadaire.</p>' +
            '<div class="ct-help-tip"><strong>Sécurité :</strong> le host SMTP est validé par la même blocklist anti-SSRF que les scanners (pas de <code>localhost</code>, pas de <code>surface-db</code>). Les adresses sender / recipients sont filtrées contre l\'injection d\'en-têtes (CRLF). Le mot de passe SMTP est stocké en base côté serveur et n\'est jamais renvoyé dans les réponses GET.</div>' +
            '<h2>Analyse IA</h2>' +
            '<p>Dans la vue détail d\'un finding, le bouton <strong>Analyse IA</strong> (icône éclair) envoie le finding au backend, qui construit le prompt méthodologique, l\'enrichit avec les données NVD et interroge le provider LLM configuré. Le résultat s\'affiche sous le finding :</p>' +
            '<ul>' +
                '<li><strong>Verdict</strong> — faux positif probable ou finding crédible, avec le niveau de confiance</li>' +
                '<li><strong>Sévérité recommandée</strong> si elle diverge de celle du scanner</li>' +
                '<li><strong>Résumé</strong> exécutif en 2-3 lignes</li>' +
                '<li><strong>Remédiation</strong> — étapes de correction</li>' +
                '<li><strong>Références</strong> — URLs (CVE, CWE, docs vendor)</li>' +
            '</ul>' +
            '<p>Le bouton n\'apparaît que si l\'assistant IA est activé dans <em>Paramètres → Assistant IA</em>. La décision finale reste manuelle : l\'IA ne clique pas sur « Faux positif » ou « À corriger » à votre place.</p>' +
            '<h2>Journal d\'audit (administrateurs)</h2>' +
            '<p>Réservé aux administrateurs, ce panneau trace qui a fait quoi (date, utilisateur, action, cible, détails, IP) avec une recherche libre — utile pour la conformité et les post-mortems.</p>' +
            '<h2>Paramètres (roue crantée en haut) — 6 sections accordéon</h2>' +
            '<p>La page <strong>Paramètres</strong> utilise un accordéon natif HTML : ouvrir une section referme automatiquement la précédente. Toutes les sections sont repliées par défaut.</p>' +
            '<ol>' +
                '<li><strong>Langue</strong> — bascule FR/EN instantanée de toute l\'interface</li>' +
                '<li><strong>Assistant IA</strong> — activation de l\'analyse IA ; selon le déploiement, l\'accès est géré par la suite (proxy backend) ou configuré avec votre propre provider / clé</li>' +
                '<li><strong>Fuseau horaire</strong> — picker de 30 zones IANA. La valeur par défaut suit le fuseau détecté par le navigateur. Toutes les dates (findings, scans, remédiations) sont affichées dans le fuseau choisi.</li>' +
                '<li><strong>Nuclei</strong> — version, nombre de templates, date de mise à jour, <strong>tuning éditable</strong> (rate-limit, concurrency, bulk-size, timeout, retries). Bouton « Mettre à jour les templates ».</li>' +
                '<li><strong>Shodan API</strong> — clé API stockée côté backend (masquée à l\'affichage). Active les scanners <code>shodan_domain</code> et <code>shodan_host</code>.</li>' +
                '<li><strong>Envoi email (digest hebdomadaire)</strong> — configuration SMTP complète : host, port, username/password, sender, recipients, toggle STARTTLS, bouton « Envoyer maintenant ».</li>' +
            '</ol>' +
            '<div class="ct-help-tip"><strong>Conseil tuning Nuclei :</strong> sur des cibles clients ou des environnements surveillés par un WAF, baissez le rate-limit à 5-10 req/s pour éviter le blacklistage. Pour vos propres assets, 20-50 req/s est confortable.</div>' +
            '<h2>Workflow typique</h2>' +
            '<ol style="font-size:var(--ct-text-data);line-height:1.8">' +
                '<li>Ajouter le domaine racine dans <strong>Surveillance</strong> avec tous les scanners cochés</li>' +
                '<li>Attendre le premier tick du scheduler ou lancer un scan manuel → les sous-domaines sont découverts et enrôlés comme hosts</li>' +
                '<li>Les hosts auto-découverts sont scannés aux ticks suivants (nmap, TLS, nuclei, takeover)</li>' +
                '<li>Consulter <strong>Findings</strong> filtré sur « Ouverts » → triage des findings critical / high en priorité</li>' +
                '<li>Les faux positifs sont documentés et silencés, les vrais problèmes deviennent des remédiations</li>' +
                '<li>Les remédiations sont suivies avec leur responsable et leur échéance dans l\'onglet <strong>Plan d\'action</strong></li>' +
                '<li>Les scans continuent en tâche de fond → nouveaux findings remontent automatiquement</li>' +
            '</ol>' +
            '<h2>Fonctionnalités nécessitant l\'IA</h2>' +
            '<p>Ces fonctionnalités appellent un modèle de langage et ne sont disponibles qu\'une fois l\'IA configurée. Elles sont <strong>optionnelles</strong> : sans configuration, elles sont masquées ou inactives et le reste du module fonctionne normalement.</p>' +
            '<ul>' +
            '<li><strong>Analyse IA d\'un finding</strong> : qualification, contexte d\'exploitation et détection des faux positifs probables</li>' +
            '</ul>' +
            '<p class="ct-help-tip">Où configurer : dans une installation autonome, via <strong>Réglages &rarr; IA</strong> du module (votre propre clé API). Dans la suite, les clés sont centralisées par <strong>Pilot</strong> et poussées aux modules &mdash; rien à saisir ici, et l\'accès à l\'IA se donne par utilisateur dans les habilitations.</p>',

        // ── Dashboard ──────────────────────────────────────
        "dash.title":          "Tableau de bord",
        "dash.findings_total": "Findings totaux",
        "dash.false_positive": "Faux positifs",
        "dash.measures_done":  "Remédiations terminées",
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
        "dash.measures_overdue":     "{n} remédiation(s) en retard",
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
        // Severity labels are kept in English on purpose — security
        // vulnerability levels (CVSS, OWASP, vendor advisories) are
        // canonically named in English and operators expect them that way.
        "sev.critical": "Critical",
        "sev.high":     "High",
        "sev.medium":   "Medium",
        "sev.low":      "Low",
        "sev.info":     "Info",

        // ── Status labels ──────────────────────────────────
        "status.open":           "Ouverts",
        "status.new":            "Nouveau",
        "status.to_fix":         "À corriger",
        "status.false_positive": "Faux positif",
        "status.fixed":          "Corrigé",
        "status.failed":         "Échoué",
        "status.all":            "Tous",
        "status.to_triage":      "À traiter",

        // ── Kind labels ────────────────────────────────────
        "kind.domain":   "Domaine",
        "kind.host":     "Host",
        "kind.ip_range": "Plage CIDR",
        "kind.file_share": "Partage de fichiers",

        // ── Monitored / Surveillance ───────────────────────
        "monitored.title":            "Périmètre surveillé",
        "monitored.help":             "Domaines, IP et plages CIDR à surveiller. Le bouton Scanner déclenche un quick scan ports + TLS sur chaque cible. Les plages CIDR sont passées aux scanners externes via bulk-import.",
        "monitored.scan_all":         "Scanner tout",
        "monitored.add":              "Ajouter une cible",
        "monitored.empty":            "Aucun périmètre défini. Cliquez sur + Ajouter pour commencer (domaine, IP ou CIDR).",
        "monitored.search.placeholder": "Rechercher par valeur, libellé, type, scanner...",
        "monitored.filter.scanner": "Type de scan :",
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
        "monitored.open_detail":      "Ouvrir le détail",
        "monitored.delete_confirm":   "Supprimer cette cible ?",
        "exclude.panel_title":        "Exclusions de scan",
        "exclude.panel_hint":         "Ces valeurs (host, IP, CIDR ou domaine) ne sont jamais scannées ni enrôlées automatiquement, même si redécouvertes.",
        "exclude.placeholder_value":  "host, IP, CIDR ou domaine",
        "exclude.placeholder_note":   "note (facultatif)",
        "exclude.add_btn":            "Exclure",
        "exclude.empty":              "Aucune exclusion.",
        "exclude.remove":             "Retirer l'exclusion",
        "exclude.removed":            "Exclusion retirée",
        "exclude.added":              "{value} exclu du scan",
        "exclude.value_required":     "Saisis une valeur à exclure",
        "monitored.bulk_delete":      "Supprimer",
        "monitored.bulk_delete_confirm": "Supprimer {count} cible(s) surveillée(s) ? Cette action est irréversible.",
        "monitored.bulk_delete_done": "{count} cible(s) supprimée(s)",
        "monitored.bulk_delete_partial": "{done} supprimée(s), {errors} erreur(s)",
        "monitored.bulk_scan":        "Forcer un scan",
        "monitored.bulk_scan_started": "Lancement de {n} scan(s)...",
        "monitored.bulk_scan_done":   "{n} scan(s) lancé(s)",
        "monitored.bulk_scan_partial": "{done} lancé(s), {errors} erreur(s)",

        // ── Hosts panel ────────────────────────────────────
        "hosts.title":            "Hosts",
        "hosts.view_cards": "Affichage en tuiles",
    "hosts.view_table": "Affichage en tableau",
    "hosts.col.host": "Hôte",
    "hosts.col.kind": "Type",
    "hosts.col.criticality": "Criticité",
    "hosts.col.ip": "IP résolue",
    "hosts.col.findings": "Actifs",
    "hosts.count":            "host(s) surveillé(s)",
        "hosts.help":             "Liste de tous les hosts surveillés, ajoutés manuellement ou découverts automatiquement par les scanners (CT logs, SAN, ping sweep). Cliquez sur une carte pour voir le détail et les findings associés.",
        "hosts.search.placeholder": "Rechercher par hostname, IP, libellé, source...",
        "hosts.no_match":         "Aucun host ne correspond à la recherche.",
        "hosts.empty":            "Aucun host surveillé. Ajoutez-en via Surveillance ou lancez un scan CT logs sur un domaine pour découvrir des sous-domaines automatiquement.",
        "hosts.source.auto":      "auto",
        "hosts.source.manual":    "manuel",
        "hosts.badge.disabled":   "désactivé",
        "hosts.badge.share":      "partage",
        "hosts.share_count":      "{n} partages",
        "hosts.last_scan":        "Dernier scan",
        "hosts.findings.none":    "Aucun finding",
        "hosts.findings.to_triage": "à traiter",

        // ── Host detail ────────────────────────────────────
        "host.back":               "Hosts",
        "host.back_monitored":     "Surveillance",
        "host.back_to_host":       "Retour au host",
        "host.col.value":          "Valeur",
        "host.col.label":          "Libellé",
        "host.col.enabled":        "Actif",
        "host.col.frequency":      "Fréquence",
        "host.col.last_scan":      "Dernier scan",
        "host.col.scanners":       "Scanners actifs",
        "host.col.subdomains":     "Sous-domaines",
        "host.col.notes":          "Notes",
        "host.frequency_hours":    "{n} heures",
        "host.scan_now":           "Scanner maintenant",
        "host.scan_all_shares":    "Scanner tous les partages",
        "host.shares":             "Partages",
        "host.edit":               "Modifier",
        "host.disable_scan":       "Désactiver le scan",
        "host.enable_scan":        "Activer le scan",
        "host.enabled_ok":         "Scan activé",
        "host.disabled_ok":        "Scan désactivé",
        "host.delete":             "Supprimer",
        "host.findings_title":     "Findings associés",
        "host.findings_empty":     "Aucun finding associé à ce host. Lancez un scan pour en générer.",
        "host.hide_fp":            "Masquer les {n} faux positif(s)",
        "host.delete_confirm":     "Supprimer ce host ? Les findings associés resteront dans la base mais ne seront plus rattachés à un asset surveillé.",

        // ── Findings panel ─────────────────────────────────
        "findings.title":             "Findings",
        // Finding labels rebuilt from type + evidence (see ct_findings.js)
        "finding.open_port.title":        "Port {port}/{protocol} ({service}) ouvert sur {address}",
        "finding.open_port.desc":         "Le service {service} écoute sur {address}:{port}/{protocol}.",
        "finding.open_port.sev.critical": "Service obsolète ou fortement exposé. À fermer immédiatement.",
        "finding.open_port.sev.high":     "Service sensible. Vérifier l'exposition intentionnelle, l'authentification et le niveau de correctif.",
        "finding.host_summary.title":     "Résumé nmap : {address}",
        "finding.host_summary.desc":      "{open_ports_count} port(s) ouvert(s) sur {address}.",
        "finding.host_down.title":        "Host {address} indisponible",
        "finding.host_down.desc":         "L'host n'a pas répondu pendant le scan.",
        // Vague 1 — findings actionnables (add-ons core)
        "finding.tls_grade.title":              "Grade TLS {grade} sur {target}",
        "finding.tls_grade.desc":               "Grade TLS {grade}. Protocoles supportés : {supported_versions_list}.",
        "finding.sensitive_file_exposed.title": "Fichier sensible exposé : {url}",
        "finding.sensitive_file_exposed.desc":  "Ce chemin est accessible publiquement (HTTP {http_status}). Le retirer ou le protéger immédiatement — il peut exposer des identifiants, du code source ou la configuration de l'infrastructure.",
        "finding.security_headers_grade.title": "En-têtes de sécurité : grade {grade} sur {target}",
        "finding.security_headers_grade.desc":  "Grade {grade}. Points à corriger : {weaknesses_list}.",
        "finding.subdomain_takeover.title":     "Prise de contrôle de sous-domaine possible sur {target} (via {service})",
        "finding.subdomain_takeover.desc":      "Le sous-domaine pointe (CNAME) vers {matched_cname} ({service}), mais la ressource cible est abandonnée. Un attaquant pourrait l'enregistrer et servir du contenu sous votre domaine. Supprimez ou corrigez l'enregistrement CNAME.",
        "finding.js_secret_leak.title":         "« {pattern} » trouvé dans un bundle JS de {target}",
        "finding.js_secret_leak.desc":          "Un motif de type « {pattern} » a été trouvé dans le bundle JS {js_url}. Extrait : {match}",
        "finding.mx_missing.title":             "Aucun MX configuré pour {target}",
        "finding.mx_missing.desc":              "Le domaine n'a aucun enregistrement MX. Aucun mail ne peut être reçu (peut être intentionnel).",
        "finding.spf_missing.title":            "SPF manquant sur {target}",
        "finding.spf_missing.desc":             "Aucun enregistrement SPF. N'importe qui peut envoyer des mails au nom de ce domaine. Recommandé : « v=spf1 -all » au minimum.",
        "finding.spf_weak.title":               "SPF trop permissif sur {target}",
        "finding.spf_weak.desc":                "Le SPF accepte tous les émetteurs (+all). SPF : {spf}",
        "finding.spf_neutral.title":            "SPF en mode neutre (?all) sur {target}",
        "finding.spf_neutral.desc":             "Le SPF est en mode neutre, sans politique de rejet. SPF : {spf}",
        "finding.dmarc_missing.title":          "DMARC manquant sur {target}",
        "finding.dmarc_missing.desc":           "Aucun enregistrement DMARC. Recommandé au minimum « v=DMARC1; p=none; rua=mailto:… » pour le monitoring, puis durcir vers p=quarantine ou p=reject.",
        "finding.dmarc_weak.title":             "DMARC en mode monitoring (p=none) sur {target}",
        "finding.dmarc_weak.desc":              "Le DMARC est en monitoring, pas en application. Après une période d'observation, durcir vers quarantine ou reject. DMARC : {dmarc}",
        "finding.dkim_missing.title":           "DKIM non détecté sur {target}",
        "finding.dkim_missing.desc":            "Aucun sélecteur DKIM commun n'a été trouvé. Vérifier la configuration DKIM avec votre fournisseur mail.",
        // smb_scan (add-on) — dynamic type (rule name) → per-scanner template
        "finding.smb_scan.title":               "Donnée sensible ({rule}) : {file}",
        "finding.smb_scan.desc":                "Un secret de type « {rule} » a été détecté dans un fichier de partage. Extrait : {match}",
        "finding.interesting_name.title":       "Fichier sensible par son nom : {file}",
        "finding.interesting_name.desc":        "Le nom ou l'extension évoque des données sensibles.",
        // Vague 2 — certificats TLS (scanner tls)
        "finding.tls_expiring.title":           "Certificat TLS bientôt expiré sur {target}",
        "finding.tls_expiring.desc":            "Le certificat de {target} approche de son expiration — planifier le renouvellement.",
        "finding.tls_expiring.sev.critical":    "Le certificat est déjà expiré.",
        "finding.tls_valid.title":              "Certificat TLS valide pour {target}",
        "finding.tls_valid.desc":               "Le certificat de {target} est valide jusqu'au {notAfter}.",
        "finding.tls_san_discovery.title":      "TLS SAN : {discovered_hosts_count} hostname(s) découvert(s) via {target}",
        "finding.tls_san_discovery.desc":       "Le certificat de {target} déclare d'autres hostnames dans le même périmètre. Ils sont ajoutés aux assets surveillés.",
        "finding.tls_reverse_cert.title":       "Reverse cert : {siblings_count} hostname(s) partagent le certificat de {target}",
        "finding.tls_reverse_cert.desc":        "crt.sh a identifié d'autres hostnames émis avec le même certificat. Ils sont ajoutés aux assets surveillés.",
        "finding.tls_error.title":              "TLS injoignable sur {target}:443",
        "finding.tls_error.desc":               "Impossible de récupérer le certificat de {target}.",
        "finding.tls_expired.title":            "Certificat TLS expiré sur {target}:443",
        "finding.tls_expired.desc":             "Le certificat de {target} a expiré. Le renouveler.",
        "finding.tls_not_yet_valid.title":      "Certificat TLS pas encore valide sur {target}:443",
        "finding.tls_not_yet_valid.desc":       "Le certificat de {target} n'est pas encore valide.",
        "finding.tls_hostname_mismatch.title":  "Certificat TLS ne couvre pas {target}",
        "finding.tls_hostname_mismatch.desc":   "Le certificat présenté par {target}:443 ne contient pas ce hostname. SAN déclarés : {san_dns_names_list}.",
        "finding.tls_self_signed.title":        "Certificat TLS auto-signé sur {target}:443",
        "finding.tls_self_signed.desc":         "Le certificat de {target} est auto-signé. Acceptable en interne, mais pas pour un service exposé publiquement.",
        "finding.tls_unverifiable.title":       "Certificat TLS non vérifiable sur {target}:443 (magasin CA limité)",
        "finding.tls_unverifiable.desc":        "La vérification système a échoué, mais l'analyse directe du certificat ne montre pas de problème — probablement une chaîne de confiance incomplète côté scanner. Aucun risque pour la cible.",
        // Wave 3 — discoveries & summaries (dns_brute, typosquat, ct_logs, discovery)
        "finding.dns_brute_discovery.title":    "DNS brute-force : {count} sous-domaine(s) découvert(s) pour {target}",
        "finding.dns_brute_discovery.desc":     "Le scan par force brute DNS a identifié {count} hostnames qui résolvent sous {target}.",
        "finding.typosquat_domain.title":       "Domaine lookalike actif : {lookalike}",
        "finding.typosquat_domain.desc":        "Variante ressemblant à {original} (classe : {class}). Risque : hameçonnage, usurpation de marque, redirection malveillante.",
        "finding.typosquat_summary.title":      "Typosquatting : analyse de {original}",
        "finding.typosquat_summary.desc":       "{permutations} permutations générées, {ct_checked} vérifiée(s) en Certificate Transparency.",
        "finding.ct_discovery.title":           "CT logs : {count} sous-domaine(s) découvert(s) pour {target}",
        "finding.ct_discovery.desc":            "Les logs Certificate Transparency (crt.sh) ont identifié {count} hostnames pour {target}. Ils sont ajoutés aux assets surveillés.",
        "finding.ct_error.title":               "CT logs : crt.sh injoignable pour {target}",
        "finding.ct_error.desc":                "La requête crt.sh a échoué. crt.sh est parfois lent ou ponctuellement indisponible — réessayer plus tard.",
        "finding.host_discovered.title":        "Nouvel host découvert sur {cidr} : {address}",
        "finding.host_discovered.desc":         "Un host est joignable sur {address}. Il a été ajouté aux hosts surveillés.",
        "finding.discovery_summary.title":      "Découverte sur {cidr} : {discovered_count} host(s) actif(s)",
        "finding.discovery_summary.desc":       "{discovered_count} hosts répondent au ping sweep sur {cidr}.",
        // Wave 4 — scan errors (generic title translated; technical detail left raw)
        "finding.scanner_error.title":          "Échec du scanner",
        "finding.scanner_timeout.title":        "Délai de scan dépassé",
        "finding.parse_error.title":            "Erreur d'analyse du scan",
        "finding.exception.title":              "Erreur du scanner",
        "finding.error.title":                  "Erreur du scanner",
        // Vague 5 — add-ons generic (shodan, nuclei, cve_lookup, cloud_buckets, screenshot)
        "finding.shodan_no_key.title":          "Shodan : clé API non configurée",
        "finding.shodan_no_key.desc":           "Le scanner Shodan est activé mais aucune clé API n'est configurée. Renseignez-la dans Paramètres → Shodan.",
        "finding.shodan_auth_error.title":      "Shodan : clé API invalide (401)",
        "finding.shodan_auth_error.desc":       "La clé API Shodan configurée n'est pas valide. Vérifiez-la dans les Paramètres.",
        "finding.shodan_no_data.title":         "Shodan : aucune donnée pour {target}",
        "finding.shodan_no_data.desc":          "Shodan ne dispose d'aucune donnée pour cette cible (jamais scannée ou résultats non indexés).",
        "finding.shodan_error.title":           "Shodan : erreur réseau pour {target}",
        "finding.shodan_domain_discovery.title":"Shodan : {count} sous-domaine(s) identifié(s) pour {target}",
        "finding.shodan_domain_discovery.desc": "L'API DNS de Shodan a remonté {count} sous-domaine(s) connu(s) pour {target}, issus de son banner grabbing passif.",
        "finding.shodan_vuln.title":            "Shodan : {cve} détectée sur {target}",
        "finding.shodan_vuln.desc":             "Shodan signale que {target} est potentiellement exposée à {cve}. Vérifier la version exacte du service concerné et corriger.",
        "finding.shodan_host_summary.title":    "Shodan : {ports_count} port(s) observé(s) sur {target}",
        "finding.shodan_host_summary.desc":     "Shodan a observé {ports_count} port(s) ouvert(s) sur cette cible via son scan passif d'Internet.",
        "finding.scanner_blocked.title":        "Scanner bloqué sur {target} ({error_rate_pct}% d'erreurs)",
        "finding.scanner_blocked.desc":         "De nombreuses requêtes ont été rejetées (WAF / anti-bot). Les résultats peuvent être partiels.",
        "finding.nuclei.title":                 "Détection nuclei : {template_id}",
        "finding.nuclei.desc":                  "Le template nuclei {template_id} a produit une correspondance.",
        "finding.cve_no_version.title":         "CVE lookup : {product} détecté sans version sur {target}",
        "finding.cve_no_version.desc":          "Le produit {product} a été identifié sur {target} mais sa version n'est pas exposée. Vérifier manuellement la version puis relancer.",
        "finding.cve_no_tech.title":            "CVE lookup : aucune technologie détectée sur {target}",
        "finding.cve_no_tech.desc":             "Aucun produit versionné identifié pour {target}. Le scanner nuclei (mode auto) doit tourner avant cve_lookup.",
        "finding.cve_match.title":              "{cve_id} — {product} sur {target}",
        "finding.cve_match.desc":               "CVSS : {cvss_score} ({cvss_severity}).\n\n{original}",
        "finding.cloud_bucket_exposed.title":   "Bucket cloud {provider} : {bucket_name} pour {target}",
        "finding.cloud_bucket_exposed.desc":    "Le bucket {bucket_name} existe sur {provider}. URL : {url}.",
        "finding.screenshot_disabled.title":    "Captures d'écran désactivées sur {target}",
        "finding.screenshot_disabled.desc":     "Le scanner de captures nécessite playwright + chromium. Installez-les puis relancez le scan.",
        "finding.screenshot.title":             "Capture d'écran de {target}",
        "finding.screenshot.desc":              "Capture visuelle de {url}.",
        // Scanner labels (localized; backend uses English as pivot)
        "scanner.nmap_quick.label":       "Nmap (top 100 ports)",
        "scanner.nmap_standard.label":    "Nmap (top 1000 + détection de services)",
        "scanner.nmap_deep.label":        "Nmap (tous les ports + détection de services)",
        "scanner.tls.label":              "Certificat TLS (+ découverte SAN)",
        "scanner.tls_grade.label":        "Note protocole/chiffrement TLS",
        "scanner.security_headers.label": "Note des en-têtes de sécurité",
        "scanner.takeover.label":         "Prise de contrôle de sous-domaine (empreinte CNAME)",
        "scanner.js_analysis.label":      "Analyse des bundles JavaScript (secrets & endpoints)",
        "scanner.sensitive_files.label":  "Exposition de fichiers sensibles",
        "scanner.dns_brute.label":        "Force brute de sous-domaines",
        "scanner.typosquatting.label":    "Typosquatting",
        "scanner.email_security.label":   "Sécurité email (SPF/DMARC/DKIM/MX)",
        "scanner.discovery.label":        "Découverte d'hosts (ping sweep)",
        "scanner.ct_logs.label":          "Découverte de sous-domaines (CT logs)",
        "scanner.shodan_domain.label":    "Shodan DNS (sous-domaines, passif, 0 crédit)",
        "scanner.shodan_host.label":      "Recherche d'host Shodan (ports/CVE, 1 crédit/req)",
        "scanner.nuclei.label":           "Nuclei (templates DAST)",
        "scanner.cve_lookup.label":       "Correspondance CVE (NVD + EPSS + KEV)",
        "scanner.cloud_buckets.label":    "Énumération de buckets cloud (S3/Azure/GCS)",
        "scanner.screenshot.label":       "Capture d'écran HTTP (optionnel)",
        "scanner.smb_scan_rs.label":      "Contenu de partages SMB — worker Rust (secrets & données sensibles)",
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
        "bulk.selected":                "{n} élément(s) sélectionné(s)",
        "bulk.findings_selected":       "{n} finding(s) sélectionné(s)",
        "bulk.delete_confirm_title":    "Supprimer {n} finding(s) ?",
        "bulk.delete_confirm_msg":      "Cette action est irréversible.",
        "bulk.fixed_confirm_title":     "Marquer {n} finding(s) comme corrigés ?",
        "bulk.fixed_confirm_msg":       "Les findings seront marqués comme corrigés. Ils réapparaîtront s'ils sont détectés au prochain scan.",
        "bulk.measure_default_title":   "Remédiation",
        "bulk.deleted":                 "supprimé(s)",
        "bulk.false_positive":     "Faux positif",
        "bulk.to_fix":             "Créer une remédiation",
        "bulk.fixed":              "Corrigé",
        "bulk.fixed_confirm":      "{n} finding(s) seront marqué(s) comme corrigé(s). Ils réapparaîtront si détectés au prochain scan.",
        "bulk.delete":             "Supprimer",
        "bulk.clear":              "Désélectionner",
        "bulk.fp_title":           "Déclarer {n} finding(s) comme faux positifs",
        "bulk.fp_help":            "La même justification sera enregistrée sur les {n} findings sélectionnés. Elle est obligatoire et reste attachée pour audit.",
        "bulk.fp_confirm":         "Confirmer le faux positif ({n})",
        "bulk.fp_justification":   "Justification *",
        "bulk.fp_placeholder":     "Expliquer pourquoi ces findings sont des faux positifs (contexte, exception documentée, configuration intentionnelle...)",
        "bulk.measure_title":      "Créer une remédiation couvrant {n} finding(s)",
        "bulk.measure_help":       "UNE seule remédiation sera créée et liée aux {n} findings sélectionnés.",
        "bulk.measure_confirm":    "Créer la remédiation",
        "bulk.delete_confirm":     "Supprimer définitivement {n} finding(s) ? Les remédiations liées seront également supprimées (cascade).",

        // ── Common actions ─────────────────────────────────
        "action.cancel":  "Annuler",
        "action.confirm": "Confirmer",
        "action.save":    "Enregistrer",
        "action.edit":    "Modifier",
        "action.delete":  "Supprimer",

        // ── Kind help texts ────────────────────────────────
        "kind.help.domain":   "Nom de domaine racine — ex: example.com, medsecure.example",
        "kind.help.host":     "Hôte unique — IP (1.2.3.4, ::1) ou nom DNS (api.example.com)",
        "kind.help.ip_range": "Plage CIDR pour les scanners externes — ex: 192.168.1.0/24",
        "kind.help.file_share": "Partage Windows SMB/CIFS — ex: \\\\serveur\\partage ou //serveur/partage",

        // ── Scanner labels (displayed in job listings) ─────
        "scanner.nmap":                 "Nmap (ports)",
        "scanner.scheduled_host":       "Scan host planifié",
        "scanner.scheduled_domain":     "Scan domaine planifié",
        "scanner.manual_host":          "Scan host manuel",
        "scanner.manual_domain":        "Scan domaine manuel",
        "scanner.manual_discovery":     "Découverte manuelle",
        // NB: key duplicated in the source ("Découverte planifiée" shadowed) —
        // only the last value won at runtime, kept here.
        "scanner.scheduled_discovery":  "Auto discovery (CIDR)",

        // ── Jobs panel ─────────────────────────────────────
        "jobs.title":           "Scans",
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
        "jobs.status.partial":  "Partiel",
        "jobs.status.failed":   "Échoué",
        "job.error.interrupted_by_restart": "Interrompu par un redémarrage du service",
        "jobs.partial.stopped": "Arrêté après {n} fichiers —",
        "jobs.partial.files":   "plafond max. atteint, reprise au prochain scan",
        "jobs.partial.time":    "budget temps atteint, reprise au prochain scan",
        "jobs.partial.inaccessible": "{n} dossier(s) inaccessible(s)",
        "jobs.scanned_files":   "{n} fichiers scannés",
        "jobs.empty":           "Aucun scan n'a ete lance. Les scans demarrent via la surveillance des actifs.",
        "jobs.no_match":        "Aucun scan ne correspond aux filtres.",
        "jobs.rerun":           "Relancer",
        "jobs.rerun_in_progress":"Scan en cours sur {target}…",
        "jobs.rerun_done":      "Scan terminé sur {target} — {n} finding(s)",
        "jobs.source.manual":   "manuel",
        "jobs.source.auto":     "auto",

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
        "mon_modal.fs_regex":       "Regex personnalisées",
        "mon_modal.fs_regex_ph":    "Une expression régulière par ligne",
        "mon_modal.fs_regex_help":  "Motifs à rechercher dans le corps des fichiers, en plus du jeu de secrets intégré.",
        "mon_modal.fs_ext":         "Extensions à scanner",
        "mon_modal.fs_ext_ph":      "pdf, docx, xlsx, pptx, txt, conf… (vide = défauts)",
        "mon_modal.fs_ext_help":    "Limite l'analyse à ces extensions. Vide = liste par défaut de l'addon.",
        "mon_modal.fs_maxsize":     "Taille max par fichier (Mo)",
        "mon_modal.fs_maxfiles":    "Nombre max de fichiers par scan",
        "mon_modal.fs_maxfiles_help": "Optionnel. Vide = aucune limite (tout le partage, dans la limite du budget temps). Si renseigné, chaque scan traite ce nombre de NOUVEAUX fichiers puis reprend à la suite au scan suivant ; le scan est alors marqué « Partiel » tant que le partage n'est pas entièrement couvert.",
        "mon_modal.fs_timebudget":  "Durée max du scan (minutes)",
        "mon_modal.fs_timebudget_help": "Temps maximal d'un scan (défaut 30 min). Au-delà, le scan s'arrête et est marqué « Partiel » (la suite au prochain passage si un plafond de fichiers est aussi défini). Augmenter pour couvrir un très gros partage en une fois.",
        "mon_modal.fs_user":        "Identifiant SMB",
        "mon_modal.fs_domain":      "Domaine",
        "mon_modal.fs_domain_ph":   "ex: CORP (vide si compte local)",
        "mon_modal.fs_pwd":         "Mot de passe SMB",
        "mon_modal.fs_pwd_ph":      "Mot de passe du compte de service",
        "mon_modal.fs_pwd_keep":    "•••••• (laisser vide pour conserver)",
        "mon_modal.fs_creds_help":  "Identifiants par cible (chiffrés). Si vides, le compte de service global (SURFACE_SMB_*) est utilisé.",
        "mon_modal.criticality":     "Criticité métier",
        "mon_modal.criticality_help":"Importance business de cet asset. Sert au calcul du risk score.",
        "mon_modal.crit_low":        "Faible",
        "mon_modal.crit_medium":     "Moyenne",
        "mon_modal.crit_high":       "Haute",
        "mon_modal.crit_critical":   "Critique",
        "mon_modal.tags":            "Tags",
        "mon_modal.tags_ph":         "production, dmz, pci-scope",
        "mon_modal.tags_help":       "Tags libres séparés par des virgules. Affichés sur la card host.",
        "crit.low":                  "Criticité faible",
        "crit.medium":               "Criticité moyenne",
        "crit.high":                 "Criticité haute",
        "crit.critical":             "Criticité maximale",
        "risk.score_tooltip":        "Score de risque (0-100) = sévérités actives × criticité métier",
        "risk.tier_critical":        "Critique",
        "risk.tier_high":            "Élevé",
        "risk.tier_medium":          "Modéré",
        "risk.tier_low":             "Faible",
        "risk.tier_clean":           "Sain",
        "host.scan_history":         "Historique des scans",
        "host.scan_done":            "Scan terminé sur {target} — {n} finding(s)",
        "host.scan_failed":          "Scan échoué sur {target}",
        "host.scan_timeout":         "Scan toujours en cours sur {target} après 6 min — vérifiez la page Scans",
        "hosts.scanners":            "scans",
        "hosts.configure":           "Configurer",
        "hosts.configure_scans":     "Configurer les scans",
        "hosts.disabled_section":    "Scan désactivé",
        "hosts.reactivate":          "Réactiver",
        "hosts.scanners_updated":    "Scans mis à jour sur {n} asset(s)",
        "hosts.bulk_configure_scans":"Appliquer des scans",
        "hosts.bulk_scanners_subtitle":"{n} assets sélectionnés",
        "mon_modal.no_scanners_for_kind":"Aucun scanner disponible pour ce type d'asset.",
        "mon_typo.title":            "Typosquatting — réglages",
        "mon_typo.max_variants":     "Variantes générées par passe",
        "mon_typo.use_ct":           "Vérifier Certificate Transparency (lookalikes à fort risque)",
        "mon_typo.max_ct":           "Max requêtes CT par passe",
        "hosts.groups":              "groupe(s) IP",
        "hosts.aliases":              "{n} alias :",
        "hosts.resolved_ip_tooltip":  "IP résolue au dernier scan — les hostnames avec la même IP sont regroupés",
        "host.col.resolved_ip":       "IP résolue",
        "host.col.aliases":           "Autres hostnames",
        "fd.ai_triage":               "Analyse IA",
        "fd.ai_not_configured":       "Assistant IA non configuré",
        "fd.ai_open_settings":        "Ouvrez Paramètres → Assistant IA pour activer la clé API.",
        "fd.ai_analyzing":            "Analyse en cours",
        "fd.ai_verdict":              "Verdict",
        "fd.ai_fp_probable":          "Faux positif probable",
        "fd.ai_genuine":              "Finding crédible",
        "fd.ai_sev_rec":              "Sévérité recommandée",
        "fd.ai_summary":              "Résumé",
        "fd.ai_remediation":          "Remédiation",
        "fd.ai_refs":                 "Références",
        "smtp.section":               "Envoi email (digest hebdo)",
        "smtp.help":                  "Configure le serveur SMTP pour l'envoi automatique du digest hebdomadaire par email.",
        "smtp.host":                  "Serveur",
        "smtp.port":                  "Port",
        "smtp.user":                  "Login",
        "smtp.password":              "Mot de passe",
        "smtp.password_ph":           "••••",
        "smtp.already_set":           "déjà configuré",
        "smtp.sender":                "Expéditeur",
        "smtp.recipients":            "Destinataires",
        "smtp.use_tls":               "STARTTLS (recommandé)",
        "smtp.save":                  "Enregistrer",
        "smtp.saved":                 "Config SMTP enregistrée",
        "smtp.send_now":              "Envoyer maintenant",
        "smtp.sending":               "Envoi du digest en cours…",
        "smtp.sent":                  "Digest envoyé à {n} destinataire(s)",
        "smtp.load_error":            "Erreur de chargement de la config SMTP",
        "tz.section":                 "Fuseau horaire",
        "tz.hint":                    "Toutes les dates affichées dans l'interface sont rendues dans ce fuseau.",
        "tz.browser":                 "Auto (navigateur)",
        "tz.saved":                   "Fuseau horaire mis à jour",
        "mon_modal.enabled":        "Actif",
        "mon_modal.auto_enroll":    "Auto-enrôler les sous-domaines découverts",
        "mon_modal.auto_enroll_help": "Si activé, les hostnames trouvés via CT logs, DNS brute, SAN ou Shodan deviennent automatiquement de nouveaux assets surveillés. Désactivé par défaut : seul l'asset que vous ajoutez est scanné, la découverte reste visible dans les findings.",
        "mon_modal.stealth":        "Mode discret (anti-WAF)",
        "mon_modal.stealth_help":   "Si activé, nuclei et nmap passent en mode lent avec User-Agent de navigateur (rate-limit 3 req/s, délai 1 s, timing T2). Permet de passer sous le radar de la plupart des WAF / anti-bot (Cloudflare, RocketCDN…) mais multiplie le temps de scan par 5 à 10. Recommandé pour les hosts qui déclenchent le finding 'scanner_blocked'.",
        "mon_modal.value_required": "La valeur est obligatoire",
        "mon_modal.added":          "Cible ajoutée",
        "mon_modal.updated":        "Cible mise à jour",
        "mon_modal.deleted":        "Cible supprimée",
        "mon_modal.scan_in_progress":"Scan en cours...",
        "mon_modal.scan_all_confirm":"Lancer un scan sur toutes les cibles activées ?",
        "mon_modal.scan_launched":   "Scan lancé sur {target}",
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
        "fd.evidence":               "Evidence",
        "fd.screenshot":             "Capture d'écran",
        "fd.notes":                  "Notes",
        "fd.triage":                 "Triage",
        "fd.triage_notes_ph":        "Notes (optionnel)...",
        "fd.triage_to_fix":          "À corriger (cree une remédiation)",
        "fd.triage_fp":              "Faux positif",
        "fd.triage_fixed":           "Corrigé",
        "fd.triage_reset":           "Reset (non trié)",
        "fd.delete":                 "Supprimer",
        "fd.delete_confirm":         "Supprimer ce finding ?",
        "fd.deleted":                "Finding supprimé",
        "fd.measure_linked":         "Remédiation associée",
        "fd.measure_status":         "Statut",
        "fd.measure_owner":          "Responsable",
        "fd.measure_due":            "Échéance",
        "fd.triage_ok":              "Triage enregistré",

        // ── Triage modal (single) ─────────────────────────
        "tm.title_to_fix":           "Créer une remédiation",
        "tm.title_fp":               "Marquer comme faux positif",
        "tm.title_reset":            "Réinitialiser le triage",
        "tm.confirm_to_fix":         "Créer la remédiation",
        "tm.confirm_fp":             "Confirmer le faux positif",
        "tm.finding":                "Finding :",
        "tm.fp_justif":              "Justification *",
        "tm.fp_justif_ph":           "Expliquer pourquoi ce finding est un faux positif (contexte, exception documentee, configuration intentionnelle...)",
        "tm.reset_help":             "Réinitialiser le statut de ce finding à \"Nouveau\" ? La remédiation associée (si elle existe) sera supprimée.",
        "tm.justif_required":        "La justification est obligatoire",

        // ── Measures panel ────────────────────────────────
        "measures.title":            "Plan d'action",
        "measures.help":             "Plan d'action issu du triage des findings. Chaque remédiation est liée au finding qui l'a générée.",
        "measures.empty":            "Aucune remédiation créée. Les remédiations apparaissent automatiquement quand vous triez un finding en 'À corriger'.",
        "measures.col.id":           "ID",
        "measures.col.title":        "Titre",
        "measures.col.status":       "Statut",
        "measures.col.owner":        "Responsable",
        "measures.col.due":          "Échéance",
        "measures.status.a_faire":   "À faire",
        "measures.status.en_cours":  "En cours",
        "measures.status.termine":   "Terminé",
        "measures.col.severity":     "Sévérité",
        "measures.updated":          "Remédiation mise à jour",

        // ── Quick prompts (utility actions) ───────────────
        "prompt.findings_imported":  "findings importés",
        "prompt.findings_skipped":   "ignorés",
        "prompt.job_delete_confirm": "Supprimer ce job ? (les findings déjà créés ne seront pas effacés)",

        // ── Generic & host/nuclei inline strings ──────────
        "common.error":              "Erreur",
        "error.bad_request":         "Requête invalide",
        "error.forbidden":           "Accès refusé",
        "error.not_found":           "Ressource introuvable",
        "error.server":              "Erreur serveur, veuillez réessayer",
        "error.generic":             "Une erreur est survenue",
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
        "settings.ai_privacy_warning": "En activant l'assistant IA :\n\n1. PARTAGE DE DONNÉES — Les données de votre analyse (contexte, exigences, remédiations) seront envoyées au fournisseur IA sélectionné. Assurez-vous que votre politique de confidentialité et vos engagements contractuels autorisent ce partage.\n\n2. EXPOSITION DE LA CLÉ API — La clé API est transmise depuis votre navigateur. Elle est visible dans les outils de développement (DevTools) et peut être capturée par des extensions navigateur. Utilisez de préférence un navigateur sans extensions ou un profil dédié.\n\n3. RÉSEAU — Les échanges sont chiffrés (HTTPS) mais peuvent être journalisés par un proxy d'entreprise.\n\nVoulez-vous continuer ?",
        "settings.ai_enable": "Activer l'assistant IA",
        "matrix.high": "Élevé",
        "matrix.significant": "Significatif",
        "settings.save": "Enregistrer",
        "settings.language": "Langue",
        "settings.saved": "Réglages enregistrés",
        "settings.ai_section": "Assistant IA",
        "matrix.low": "Faible",
        "matrix.moderate": "Modéré",
        "measures.marked_done": "Remédiation marquée comme corrigée",
        "matrix.y": "Vraisemblance",
        "measures.deleted": "Remédiation supprimée",
        "matrix.extreme": "Extrême",
        "measures.col.findings": "Findings",
        "settings.title": "Réglages",
        "matrix.x": "Impact",
        "matrix.critical": "Critique",
        "smtp.managed_notice": "Le serveur SMTP (hôte, authentification, expéditeur) est configuré dans Pilot → Paramètres et poussé automatiquement à ce module. Réglez ici uniquement les destinataires des rapports.",
    "smtp.not_configured": "non configuré — voir Pilot → Paramètres",
    "smtp.sent_confirm": "Rapport envoyé ✔\\n\\nDestinataires : {recipients}\\n\\nVérifiez la boîte de réception (et les spams au premier envoi).",
    "smtp.send_failed": "Échec de l'envoi :\\n{msg}",
});
}
