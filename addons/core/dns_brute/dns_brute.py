"""Subdomain DNS brute-force scanner — Surface core add-on."""
from __future__ import annotations

import os
import re
from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _int_env, _normalize_host, _in_scope,
)


# ═══════════════════════════════════════════════════════════════
# DNS brute-force (active, passive sources having missed subdomains)
# ═══════════════════════════════════════════════════════════════

# Curated default wordlist (~300 entries) covering generic, dev/test, security,
# infra, CI/CD, monitoring, CISO-specific modules and common corporate
# sub-domains. Not exhaustive — override with SURFACE_DNS_BRUTE_WORDLIST=<path>
# to point at a larger list (one word per line). Assetnote-style lists of
# 100k+ entries work fine, expect longer scan times (~5-10 minutes).
_DNS_BRUTE_DEFAULT_WORDS: tuple[str, ...] = (
    # Root / generic
    "www", "www2", "web", "m", "mobile", "old", "new", "legacy", "archive",
    "home", "main", "portal", "site", "sites", "root", "public", "private",
    "internal", "external", "intranet", "extranet",
    # Mail
    "mail", "mail1", "mail2", "mail3", "email", "webmail", "webmail2",
    "smtp", "smtp1", "smtp2", "smtp3", "smtpout", "smtp-out", "smtpin",
    "smtp-in", "mailout", "mail-out", "outbound", "inbound", "relay",
    "relay1", "relay2", "sender", "mailsender", "bounce", "return-path",
    "imap", "imap1", "imap2", "pop", "pop3",
    "mx", "mx1", "mx2", "mx3", "mxout", "mx-out",
    "exchange", "ex", "ex1", "ex2", "outlook", "owa", "ecp", "mapi",
    "activesync", "eas", "zimbra", "postfix", "sendmail",
    "mailgw", "mail-gw", "mailgateway", "mail-gateway", "mailserver",
    "mail-server", "mailhost", "autodiscover", "autoconfig",
    "mdaemon", "openrelay", "mailman", "listserv",
    # Microsoft 365 / Entra artifacts (useful even when the app proxy is off-domain)
    "msoid", "sts", "adfs", "adfs1", "adfs2", "sts1", "sts2",
    "lyncdiscover", "lyncweb", "sip", "meet", "dialin", "webex",
    # DNS / name services
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "resolver",
    # FTP / file transfer
    "ftp", "ftp2", "sftp", "tftp", "files", "file", "share", "download",
    "upload", "uploads", "fileshare", "sharepoint",
    # Web applications
    "api", "api2", "apis", "api-v1", "api-v2", "rest", "graphql", "soap",
    "app", "apps", "application", "admin", "administrator", "adm",
    "backend", "frontend", "console", "panel", "dashboard", "control",
    "manage", "manager", "management", "cpanel", "webmin", "plesk",
    "phpmyadmin", "pma", "adminer",
    # Environments
    "dev", "development", "devel", "devs", "developer", "developers",
    "test", "tests", "testing", "tester", "qa", "uat", "preprod",
    "pre-prod", "pre", "staging", "stage", "stg", "sandbox", "sbx",
    "demo", "demos", "lab", "labs", "poc", "mvp", "beta", "alpha",
    "canary", "perf", "load", "integration", "int",
    # Dev-prefixed common apps
    "dev-api", "dev-app", "dev-admin", "dev-web", "test-api", "test-app",
    "staging-api", "staging-app", "prod-api", "prod-app",
    "api-dev", "api-test", "api-staging", "api-prod", "api-preprod",
    # Identity / auth / security
    "sec", "security", "secure", "ssl", "tls",
    "sso", "auth", "oauth", "oauth2", "oidc", "saml", "login", "signin",
    "id", "identity", "iam", "keycloak", "okta", "adfs", "duo",
    "mfa", "2fa", "otp", "radius", "ldap", "ldaps", "ad", "kerberos",
    # VPN / remote access — generic names
    "vpn", "vpn1", "vpn2", "vpn3", "vpn4", "vpn-gw", "vpngw", "vpn-gateway",
    "vpn-prod", "vpn-dev", "vpn-test", "vpn-fr", "vpn-eu", "vpn-us",
    "vpn-admin", "vpn-user", "vpn-users", "vpn-ssl", "sslvpn", "ssl-vpn",
    "webvpn", "web-vpn", "vpn-web", "portal", "vpn-portal", "vpnportal",
    "mobilevpn", "mobile-vpn", "clientless", "clientless-vpn",
    "remote", "remote1", "remote2", "remoteaccess", "remote-access", "ra",
    "ra-vpn", "ravpn", "access", "access-gw", "accessgw", "access1",
    "access2", "access-vpn", "extranet-vpn",
    "tunnel", "tun", "tun0", "tun1", "ipsec", "ipsec-vpn", "l2tp", "pptp",
    "gre", "esp", "ikev2",
    # VPN / remote access — enterprise product names
    "globalprotect", "global-protect", "gp", "gp-portal", "gpportal",
    "gp-gw", "gpgw", "gp1", "gp2", "palo", "paloalto", "pa", "panos",
    "anyconnect", "any-connect", "ac", "ac1", "ac2", "ciscoanyconnect",
    "cisco-vpn", "cisco-asa", "asa", "asa1", "asa2", "asav",
    "ocserv", "openconnect", "ios-xe",
    "forti", "fortinet", "forticlient", "fortigate", "fortigate1",
    "fortigate2", "fortimail", "fortiweb", "fortimanager", "fortianalyzer",
    "fgt", "fgt1", "fgt2", "fg", "fg1", "fg2",
    "pulse", "pulsesecure", "pulse-secure", "ivanti", "ivanti-vpn", "psa",
    "psa1", "psa2", "junos-pulse",
    "zscaler", "zs", "zs-vpn", "zpa", "zia", "zsapp",
    "juniper", "ivc", "ivs", "junos",
    "checkpoint", "cp", "cpvpn", "cp-vpn", "ckp", "gaia", "mab", "mobile-access",
    "netscaler", "ns", "ns1", "ns2", "nsvpn", "citrix", "citrix-vpn",
    "citrix-gw", "citrixgw", "ctx", "ctx1", "ctx2", "ica", "ica-proxy",
    "xenapp", "storefront", "workspace", "wsa", "cag",
    "openvpn", "ovpn", "ovpn-access", "ovpn-admin", "ovpn1", "ovpn2",
    "wireguard", "wg", "wg0", "wg1", "wg2",
    "tailscale", "ts-vpn", "cato", "catocloud", "twingate",
    "zerotier", "zt", "zerotier-one",
    "cloudflareaccess", "cloudflare-access", "cfa", "warp", "teams",
    "zerotrust", "zero-trust", "ztna", "sse", "sase",
    # Remote desktop / terminal services
    "rdp", "rdg", "rdgw", "rd-gateway", "rdgateway", "rdpgateway",
    "rds", "ts", "tsgw", "rdweb", "rd-web", "remotedesktop",
    "remote-desktop", "remoteapp", "mstsc", "terminal", "terminalserver",
    "teamviewer", "tv", "anydesk", "rustdesk",
    # Gateway / firewall conventions
    "fw", "firewall", "fw1", "fw2", "fw01", "fw02", "fwint", "fwext",
    "gw", "gw1", "gw2", "gateway", "gateway1", "gateway2",
    "internetgw", "border", "edge", "edge1", "edge2", "perimeter",
    "nac", "nac-gw", "radiusnac",
    # Extranet / partner / B2B
    "extranet", "ext", "external", "partner", "partners", "partenaire",
    "partenaires", "supplier", "suppliers", "fournisseur", "fournisseurs",
    "client", "clients", "b2b", "b2c", "guest", "guests",
    # Monitoring / ops / observability
    "monitor", "monitoring", "grafana", "kibana", "elastic", "elastic-search",
    "elasticsearch", "es", "prom", "prometheus", "alertmanager", "metrics",
    "stats", "status", "health", "healthz", "uptime", "ping",
    "logs", "logging", "syslog", "splunk", "jaeger", "loki", "opensearch",
    "nagios", "zabbix", "cacti", "munin", "apm", "sentry", "newrelic",
    # CI/CD / dev tooling
    "ci", "cd", "build", "builds", "jenkins", "gitlab", "github", "git",
    "gogs", "gitea", "bitbucket", "svn", "cvs", "mercurial", "artifact",
    "artifacts", "nexus", "harbor", "registry", "docker", "dockerhub",
    "sonar", "sonarqube", "codecov", "coveralls", "argo", "argocd",
    "tekton", "drone", "circle", "circleci", "travis", "teamcity", "bamboo",
    # Collaboration / docs / tickets
    "jira", "confluence", "wiki", "wikis", "docs", "doc", "documentation",
    "readme", "manual", "help", "helpdesk", "support", "ticket", "tickets",
    "servicedesk", "otrs", "zendesk", "freshdesk", "mantis", "bugzilla",
    "redmine", "trello", "asana", "notion", "slack", "teams", "mattermost",
    "rocket", "rocketchat", "discord", "matrix",
    # CISO Toolbox modules (dogfooding)
    "pilot", "risk", "vendor", "compliance", "asset", "access", "scan",
    "surface", "watch", "audit", "ciso", "security-toolbox",
    # Storage / DB / middleware
    "db", "database", "mysql", "postgres", "postgresql", "pgsql",
    "mongo", "mongodb", "redis", "memcache", "memcached", "cache",
    "mariadb", "mssql", "oracle", "cassandra", "neo4j", "influx",
    "rabbitmq", "rabbit", "kafka", "zookeeper", "activemq", "nats",
    "s3", "minio", "ceph", "swift", "nas", "smb", "cifs", "nfs",
    "backup", "backups", "dr", "failover",
    # Finance / HR / ERP / CRM
    "crm", "erp", "sap", "hr", "rh", "finance", "accounting", "billing",
    "invoice", "invoices", "payment", "payments", "cart", "checkout",
    "shop", "store", "commerce", "marketplace", "salesforce", "oracle-crm",
    "sage", "dynamics",
    # Content / media / marketing
    "blog", "news", "press", "media", "stream", "video", "videos",
    "images", "img", "photos", "gallery", "cdn", "cdn2", "static",
    "static1", "static2", "assets", "asset", "resources", "res",
    "content", "cms", "wordpress", "drupal", "joomla", "magento",
    "ghost", "strapi", "contentful", "shopify",
    # Communication
    "chat", "im", "meeting", "meet", "conf", "conference", "webinar",
    "zoom", "webex", "jitsi", "bigbluebutton", "bbb",
    # Network / infra
    "gw", "gateway", "router", "switch", "fw", "firewall", "lb", "loadbalancer",
    "proxy", "reverse-proxy", "squid", "haproxy", "traefik", "envoy",
    "ingress", "ingress-controller",
    # Regional
    "fr", "en", "eu", "us", "uk", "de", "it", "es", "ch", "be", "ca",
    "asia", "apac", "emea", "amer", "latam", "africa",
    # Versions / instances
    "v1", "v2", "v3", "v4", "1", "2", "3", "01", "02", "03",
    "prod", "production", "live", "release",
    # Specialized / less common but worth trying
    "remote", "rdp", "ts", "teamviewer", "rustdesk", "anydesk",
    "ci-dev", "ci-prod", "registry-dev", "registry-prod",
    "captive", "guest", "wifi", "byod",
    "time", "ntp", "pool",
    "directory", "dir", "contacts", "phonebook",
    "survey", "surveys", "forms", "questionnaire",
    "kb", "knowledge", "faq", "training", "learn", "lms", "moodle",
    "elearning", "video-training",
)


# Base tokens from which we auto-generate compound permutations
# (a, b, ab, ba, a-b, b-a). This catches the naming convention chaos:
#   vpnssl vs sslvpn vs vpn-ssl vs ssl-vpn vs vpn.ssl (not a single label)
# A pairing across these bases produces ~160 extra wordlist entries — well
# worth a few seconds of extra DNS time.
_COMPOUND_TOKENS: tuple[str, ...] = (
    "vpn", "ssl", "sslvpn", "tls", "remote", "ra", "access", "portal",
    "web", "secure", "sec", "gw", "gateway", "connect", "connection",
    "client", "admin", "user", "entry", "login",
)


def _generate_compounds(tokens: tuple[str, ...]) -> list[str]:
    """Build compound words like (vpn, ssl) → [vpnssl, sslvpn, vpn-ssl,
    ssl-vpn]. Only pairs tokens from the same base set — enough to cover
    most real-world naming collisions without exploding the wordlist."""
    out: set[str] = set()
    for a in tokens:
        for b in tokens:
            if a == b:
                continue
            out.add(a + b)
            out.add(f"{a}-{b}")
    return sorted(out)


_WORDLIST_ALLOWED_DIRS = ("/data/wordlists", "/app/wordlists")


def _load_dns_brute_wordlist() -> list[str]:
    """Load the DNS brute-force wordlist. Override via SURFACE_DNS_BRUTE_WORDLIST
    pointing at a file inside /data/wordlists or /app/wordlists."""
    import pathlib
    path = os.environ.get("SURFACE_DNS_BRUTE_WORDLIST", "").strip()
    if path:
        try:
            resolved = pathlib.Path(path).resolve(strict=False)
            in_allowed = any(
                str(resolved).startswith(str(pathlib.Path(d).resolve()) + os.sep)
                for d in _WORDLIST_ALLOWED_DIRS
            )
            if not in_allowed:
                logger.warning("dns_brute: wordlist path outside allowed dirs: %s", path)
                path = ""
        except (OSError, RuntimeError) as e:
            logger.warning("dns_brute: cannot resolve %s: %s", path, e)
            path = ""
    if path and os.path.isfile(path):
        try:
            words: list[str] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if not w or w.startswith("#"):
                        continue
                    # Keep only valid DNS labels
                    if re.match(r"^[a-z0-9][a-z0-9_-]*$", w):
                        words.append(w)
            if words:
                # Dedupe while preserving order
                seen: set[str] = set()
                deduped = [w for w in words if not (w in seen or seen.add(w))]
                logger.info("dns_brute: loaded %d unique words from %s", len(deduped), path)
                return deduped
        except OSError as e:
            logger.warning("dns_brute: cannot read %s: %s", path, e)
    # Dedupe the embedded tuple (overlap can exist across sections) and
    # append auto-generated compounds for the VPN/remote-access vocabulary.
    seen2: set[str] = set()
    base = [w for w in _DNS_BRUTE_DEFAULT_WORDS if not (w in seen2 or seen2.add(w))]
    for c in _generate_compounds(_COMPOUND_TOKENS):
        if c not in seen2:
            seen2.add(c)
            base.append(c)
    return base


def _detect_dns_wildcard(domain: str) -> set[str]:
    """Return the set of IPs that a random `.domain` resolves to.
    Used to filter out wildcard DNS responses from brute-force hits."""
    import random
    import string
    import dns.resolver

    wildcard_ips: set[str] = set()
    # Try 2 random labels to catch wildcards that cycle IPs
    for _ in range(2):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            resolver.timeout = 3
            ans = resolver.resolve(f"{rnd}.{domain}", "A")
            for a in ans:
                wildcard_ips.add(str(a))
        except Exception:
            pass
    return wildcard_ips


def scan_domain_dns_brute(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Active DNS brute-force — resolves <word>.<domain> for each word in the
    wordlist concurrently. Filters out wildcard responses. Returns findings
    and the list of discovered hostnames for auto-enrollment.

    Tuning:
      SURFACE_DNS_BRUTE_CONCURRENCY  parallel queries (default 10)
      SURFACE_DNS_BRUTE_TIMEOUT      per-query timeout seconds (default 3)
      SURFACE_DNS_BRUTE_WORDLIST     override path (one word per line)
    """
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor, as_completed

    domain = _safe_target(domain).lower()
    words = _load_dns_brute_wordlist()
    concurrency = _int_env("SURFACE_DNS_BRUTE_CONCURRENCY", 10, 1, 100)
    timeout = _int_env("SURFACE_DNS_BRUTE_TIMEOUT", 3, 1, 30)

    wildcard_ips = _detect_dns_wildcard(domain)
    logger.info("dns_brute: %s — %d words, concurrency=%d, wildcard=%s",
                domain, len(words), concurrency, wildcard_ips or "none")

    discovered: set[str] = set()
    discovered_with_ips: dict[str, list[str]] = {}

    def _resolve_one(word: str) -> tuple[str, list[str]] | None:
        host = f"{word}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            ans = resolver.resolve(host, "A")
            ips = [str(a) for a in ans]
            return (host, ips)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(_resolve_one, w) for w in words]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if not res:
                continue
            host, ips = res
            # Drop wildcard false positives: if every IP returned is in the
            # wildcard set, the hostname does not really exist as a distinct
            # record.
            if wildcard_ips and all(ip in wildcard_ips for ip in ips):
                continue
            h = _normalize_host(host)
            # Scope = the seed domain exactly, NOT its registrable root.
            # This keeps discovery within what the user explicitly asked
            # to monitor (e.g. a seed `sub.example.com` should not leak
            # hits to `other.example.com`). TLS pivot uses _registrable
            # because its purpose is sibling discovery.
            if h and _in_scope(h, domain) and h != domain:
                discovered.add(h)
                discovered_with_ips[h] = ips

    hosts = sorted(discovered)
    findings: list[dict[str, Any]] = [{
        "scanner": "dns_brute",
        "type": "dns_brute_discovery",
        "severity": "info",
        "title": f"DNS brute-force : {len(hosts)} sous-domaine(s) decouvert(s) pour {domain}",
        "description": (
            f"Le scan de brute-force DNS avec {len(words)} mots-cles a identifie "
            f"{len(hosts)} hostnames qui resolvent sous {domain}. "
            + ("Wildcard DNS detecte sur " + ", ".join(sorted(wildcard_ips)) + " — les hits pointant uniquement vers ces IPs ont ete filtres." if wildcard_ips else "Pas de wildcard DNS detecte.")
        ),
        "target": domain,
        "evidence": {
            "wordlist_size": len(words),
            "concurrency": concurrency,
            "timeout_seconds": timeout,
            "wildcard_ips": sorted(wildcard_ips),
            "count": len(hosts),
            "hosts_sample": [{"host": h, "ips": discovered_with_ips.get(h, [])} for h in hosts[:50]],
        },
    }]
    return findings, hosts


SURFACE_SCANNERS = {"dns_brute": {"label": "Subdomain brute-force",
    "kinds": {"domain"}, "callable": scan_domain_dns_brute, "returns_discovered": True}}
