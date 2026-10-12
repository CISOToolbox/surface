"""BUG-101 — a name without an address still gets the scanners that never
connect to it.

A mail-only domain (MX and TXT, no A/AAAA) or a subdomain whose CNAME
dangles (the takeover case itself) has no address. Locks, with DNS and the
network replaced:
  - email_security, dns_brute, typosquatting, ct_logs, cloud_buckets and
    shodan_domain run on it: they query DNS, the CT logs or third-party
    services, never the name itself;
  - takeover runs on it and reports a dangling CNAME, without an HTTP
    request to the name (no address was validated to pin it to);
  - a name resolving to an internal address, or naming an internal
    service, stays refused;
  - a name that does not exist (NXDOMAIN) or a lookup that fails (a DNS
    outage) is not a name without an address: the scanner fails, as an
    error, instead of reporting the DNS records it could not read as
    missing. takeover alone runs on a name that does not exist when a
    CNAME leads to it (the dangling CNAME);
  - takeover says when, for want of an address, it could not fetch the
    name to look for a service's fingerprint;
  - a DNS query that fails (timeout, no nameserver answering) on such a
    name is an error too, not an empty answer: email_security would report
    SPF or DMARC missing, takeover a name without a CNAME.
"""
from __future__ import annotations

import socket

import dns.exception
import dns.resolver
import pytest

from conftest import load_core_addon

_NAME = "mail-only.medsecure.example"
_MISSING = "typo.medsecure.example"      # NXDOMAIN
_OUTAGE = "outage.medsecure.example"     # the resolver fails (SERVFAIL, timeout)


@pytest.fixture(autouse=True)
def _no_address(monkeypatch):
    def lookup(host, port=0, *a, **k):
        if host == "intranet.medsecure.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]
        if host == _MISSING:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        if host == _OUTAGE:
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        raise socket.gaierror(socket.EAI_NODATA, "No address associated with hostname")
    monkeypatch.setattr(socket, "getaddrinfo", lookup)


def _email(monkeypatch):
    mod = load_core_addon("email_security")
    asked = []
    monkeypatch.setattr(mod, "_dns_query", lambda d, rtype, **k: asked.append((d, rtype)) or [])
    return mod.scan_domain_email, asked


def _dns_brute(monkeypatch):
    mod = load_core_addon("dns_brute")
    asked = []
    monkeypatch.setattr(mod, "_load_dns_brute_wordlist", lambda: [])
    monkeypatch.setattr(mod, "_detect_dns_wildcard", lambda d: asked.append(d) or set())
    return mod.scan_domain_dns_brute, asked


def _typosquatting(monkeypatch):
    mod = load_core_addon("typosquatting")
    asked = []
    monkeypatch.setattr(mod, "_dnstwist_permutations", lambda d, n: asked.append(d) or [])
    monkeypatch.setattr(mod, "_builtin_permutations", lambda d: [])
    return mod.scan_domain_typosquatting, asked


def _ct_logs(monkeypatch):
    mod = load_core_addon("ct_logs")
    asked = []
    monkeypatch.setattr(mod, "_fetch_crt_sh", lambda q, timeouts, max_bytes: asked.append(q) or ([], None))
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    return mod.scan_domain_ct_logs, asked


def _cloud_buckets(monkeypatch):
    mod = load_core_addon("cloud_buckets")
    asked = []
    monkeypatch.setattr(mod, "_bucket_candidates", lambda d: asked.append(d) or [])
    return mod.scan_domain_cloud_buckets, asked


def _shodan(monkeypatch):
    mod = load_core_addon("shodan")
    asked = []
    monkeypatch.setattr(mod, "_get_shodan_api_key", lambda: asked.append("key") or "")
    return mod.SURFACE_SCANNERS["shodan_domain"]["callable"], asked


@pytest.mark.parametrize("scanner", [_email, _dns_brute, _typosquatting, _ct_logs, _cloud_buckets, _shodan])
def test_a_name_without_an_address_is_scanned(monkeypatch, scanner):
    scan, asked = scanner(monkeypatch)
    scan(_NAME)
    # About that name (shodan asks for its key first, then has none).
    assert asked and all(a == "key" or _NAME in str(a) for a in asked)


def test_email_security_reports_on_a_name_without_an_address(monkeypatch):
    scan, _asked = _email(monkeypatch)
    assert {"spf_missing", "dmarc_missing"} <= {f["type"] for f in scan(_NAME)}


@pytest.mark.parametrize("scanner", [_email, _dns_brute, _typosquatting, _ct_logs, _cloud_buckets, _shodan])
@pytest.mark.parametrize("name", [_MISSING, _OUTAGE])
def test_a_name_that_does_not_exist_or_a_failed_lookup_is_an_error(monkeypatch, scanner, name):
    scan, asked = scanner(monkeypatch)
    with pytest.raises(ValueError, match="non resolvable"):
        scan(name)
    assert not asked


@pytest.mark.parametrize("scanner", [_email, _dns_brute, _typosquatting, _ct_logs, _cloud_buckets, _shodan])
@pytest.mark.parametrize("name", ["intranet.medsecure.example", "surface-db"])
def test_an_internal_name_stays_refused(monkeypatch, scanner, name):
    scan, asked = scanner(monkeypatch)
    with pytest.raises(ValueError):
        scan(name)
    assert not asked


def _takeover(monkeypatch, chain=("medsecure-old.herokuapp.com",)):
    mod = load_core_addon("takeover")
    fetched = []
    monkeypatch.setattr(mod, "_resolve_cname_chain", lambda h, **k: list(chain))
    monkeypatch.setattr(mod, "_cname_target_is_nxdomain", lambda c: True)
    monkeypatch.setattr(mod, "_fetch_takeover_body", lambda t: fetched.append(t) or (None, ""))
    return mod, fetched


def test_takeover_reports_a_dangling_cname_without_fetching_the_name(monkeypatch):
    mod, fetched = _takeover(monkeypatch)
    [finding] = mod.scan_host_takeover(_NAME)
    assert finding["type"] == "subdomain_takeover" and finding["evidence"]["target_nxdomain"] is True
    assert finding["evidence"]["http_status_code"] is None
    assert fetched == []


def test_takeover_reports_a_cname_to_a_name_that_does_not_exist(monkeypatch):
    # getaddrinfo follows the CNAME: a dangling one is a name that does not
    # exist, which is the takeover case.
    mod, fetched = _takeover(monkeypatch)
    [finding] = mod.scan_host_takeover(_MISSING)
    assert finding["type"] == "subdomain_takeover" and fetched == []


def test_takeover_on_a_name_that_does_not_exist_without_a_cname_is_an_error(monkeypatch):
    mod, fetched = _takeover(monkeypatch, chain=())
    with pytest.raises(ValueError, match="non resolvable"):
        mod.scan_host_takeover(_MISSING)
    assert fetched == []


def test_takeover_on_a_name_without_an_address_nor_a_cname_finds_nothing(monkeypatch):
    mod, fetched = _takeover(monkeypatch, chain=())
    assert mod.scan_host_takeover(_NAME) == [] and fetched == []


def test_takeover_on_a_failed_lookup_is_an_error(monkeypatch):
    mod, fetched = _takeover(monkeypatch)
    with pytest.raises(ValueError, match="non resolvable"):
        mod.scan_host_takeover(_OUTAGE)
    assert fetched == []


def test_takeover_says_a_fingerprint_it_could_not_look_for(monkeypatch):
    # GitHub Pages: a fingerprint only, no NXDOMAIN rule. Without an address
    # the name is not fetched, and the scan says so instead of reading clean.
    mod, fetched = _takeover(monkeypatch, chain=("medsecure.github.io",))
    [finding] = mod.scan_host_takeover(_NAME)
    assert finding["type"] == "takeover_not_checked" and finding["severity"] == "info"
    assert finding["evidence"]["services"] == ["GitHub Pages"]
    assert finding["evidence"]["cname_chain"] == ["medsecure.github.io"]
    assert fetched == []


def test_takeover_says_a_fingerprint_it_could_not_look_for_when_the_cname_resolves(monkeypatch):
    # Heroku: NXDOMAIN rule and fingerprints. Its CNAME target exists, so
    # only the fingerprint could tell, and it was not looked for.
    mod, fetched = _takeover(monkeypatch)
    monkeypatch.setattr(mod, "_cname_target_is_nxdomain", lambda c: False)
    [finding] = mod.scan_host_takeover(_NAME)
    assert finding["type"] == "takeover_not_checked"
    assert finding["evidence"]["services"] == ["Heroku"]


def _dns_answers(monkeypatch, error):
    # The resolver itself: every query fails with ``error``.
    def resolve(self, qname, rdtype="A", *a, **k):
        raise error
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)


def _one_query_fails(monkeypatch, query, records=None):
    # That query alone fails; the others answer ``records`` or no record.
    class _Txt:
        def __init__(self, v):
            self.v = v

        def __str__(self):
            return self.v

    def resolve(self, qname, rdtype="A", *a, **k):
        if (str(qname), rdtype) == query:
            raise dns.exception.Timeout()
        if (str(qname), rdtype) in (records or {}):
            return [_Txt(records[(str(qname), rdtype)])]
        raise dns.resolver.NoAnswer()
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)


@pytest.mark.parametrize("query", [(_NAME, "MX"), (_NAME, "TXT"), (f"_dmarc.{_NAME}", "TXT")])
def test_email_security_on_a_failed_dns_query_is_an_error(monkeypatch, query):
    mod = load_core_addon("email_security")
    _one_query_fails(monkeypatch, query)
    with pytest.raises(ValueError, match="DNS"):
        mod.scan_domain_email(_NAME)


def test_a_failed_dkim_selector_query_keeps_the_other_findings(monkeypatch):
    # DKIM selectors are guessed: one whose query fails is skipped. Without
    # a key found, DKIM is said not checked rather than missing.
    mod = load_core_addon("email_security")
    _one_query_fails(monkeypatch, (f"default._domainkey.{_NAME}", "TXT"))
    findings = {f["type"]: f for f in mod.scan_domain_email(_NAME)}
    assert {"mx_missing", "spf_missing", "dmarc_missing"} <= set(findings)
    assert "dkim_missing" not in findings
    assert findings["dkim_not_checked"]["severity"] == "info"
    assert findings["dkim_not_checked"]["evidence"]["selectors_failed"] == ["default"]


def test_a_dkim_key_found_after_a_failed_selector_query_is_enough(monkeypatch):
    mod = load_core_addon("email_security")
    _one_query_fails(monkeypatch, (f"default._domainkey.{_NAME}", "TXT"),
                     {(f"google._domainkey.{_NAME}", "TXT"): "v=DKIM1; k=rsa; p=MIIB"})
    types = {f["type"] for f in mod.scan_domain_email(_NAME)}
    assert not types & {"dkim_missing", "dkim_not_checked"}


@pytest.mark.parametrize("none", [dns.resolver.NoAnswer, dns.resolver.NXDOMAIN])
def test_email_security_reads_no_record_as_missing(monkeypatch, none):
    # NXDOMAIN is the usual answer for a DKIM selector or _dmarc not set.
    mod = load_core_addon("email_security")
    _dns_answers(monkeypatch, none())
    types = {f["type"] for f in mod.scan_domain_email(_NAME)}
    assert {"mx_missing", "spf_missing", "dmarc_missing", "dkim_missing"} <= types


def test_takeover_on_a_failed_cname_query_of_a_name_without_an_address_is_an_error(monkeypatch):
    mod = load_core_addon("takeover")
    _dns_answers(monkeypatch, dns.resolver.NoNameservers())
    with pytest.raises(ValueError, match="DNS"):
        mod.scan_host_takeover(_NAME)


@pytest.mark.parametrize("none", [dns.resolver.NoAnswer, dns.resolver.NXDOMAIN])
def test_takeover_on_a_name_without_an_address_nor_a_cname_record_finds_nothing(monkeypatch, none):
    mod = load_core_addon("takeover")
    _dns_answers(monkeypatch, none())
    assert mod.scan_host_takeover(_NAME) == []


def test_takeover_says_a_service_whose_nxdomain_check_failed(monkeypatch):
    # SmugMug: NXDOMAIN rule only, no fingerprint. The query of its CNAME
    # target fails: neither vulnerable nor clean, and said.
    mod, fetched = _takeover(monkeypatch, chain=("medsecure.domains.smugmug.com",))
    monkeypatch.setattr(mod, "_cname_target_is_nxdomain", lambda c: None)
    [finding] = mod.scan_host_takeover(_NAME)
    assert finding["type"] == "takeover_not_checked"
    assert finding["evidence"]["services"] == ["SmugMug"]
    assert "DNS query" in finding["evidence"]["checks"][0]


@pytest.mark.parametrize("error, verdict", [(dns.resolver.NXDOMAIN, True), (dns.exception.Timeout, None),
                                            (dns.resolver.NoNameservers, None), (dns.resolver.NoAnswer, False)])
def test_the_nxdomain_check_tells_a_failed_query_apart(monkeypatch, error, verdict):
    mod = load_core_addon("takeover")
    _dns_answers(monkeypatch, error())
    assert mod._cname_target_is_nxdomain("medsecure.domains.smugmug.com") is verdict


def _with_address(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))])


def test_takeover_says_a_fingerprint_whose_page_could_not_be_fetched(monkeypatch):
    # The name has an address, but neither https nor http answered.
    mod, fetched = _takeover(monkeypatch, chain=("medsecure.github.io",))
    _with_address(monkeypatch)
    [finding] = mod.scan_host_takeover(_NAME)
    assert finding["type"] == "takeover_not_checked" and fetched == [_NAME]
    assert "could not be fetched" in finding["evidence"]["checks"][0]


def test_takeover_on_a_page_read_without_the_fingerprint_finds_nothing(monkeypatch):
    mod, fetched = _takeover(monkeypatch, chain=("medsecure.github.io",))
    _with_address(monkeypatch)
    monkeypatch.setattr(mod, "_fetch_takeover_body", lambda t: fetched.append(t) or (404, "nothing here"))
    assert mod.scan_host_takeover(_NAME) == [] and fetched == [_NAME]


def test_takeover_on_a_failed_cname_query_of_a_name_with_an_address_is_an_error(monkeypatch):
    mod = load_core_addon("takeover")
    _with_address(monkeypatch)
    _dns_answers(monkeypatch, dns.exception.Timeout())
    with pytest.raises(ValueError, match="DNS"):
        mod.scan_host_takeover(_NAME)


def test_a_cname_query_failing_after_the_first_hop_is_an_error(monkeypatch):
    # shop -> alias.cdn.example answers, the next hop times out: the service
    # it led to is unknown.
    mod = load_core_addon("takeover")

    class _Target:
        target = "alias.cdn.example."

    def resolve(self, qname, rdtype="A", *a, **k):
        if str(qname) == _NAME:
            return [_Target()]
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    with pytest.raises(ValueError, match="DNS query CNAME alias.cdn.example"):
        mod._resolve_cname_chain(_NAME, strict=True)
    assert mod._resolve_cname_chain(_NAME) == ["alias.cdn.example"]


def test_takeover_found_is_not_followed_by_a_not_checked(monkeypatch):
    # Heroku dangles (NXDOMAIN), GitHub Pages could not be fetched: the
    # takeover is the finding.
    mod, fetched = _takeover(monkeypatch, chain=("medsecure-old.herokuapp.com", "medsecure.github.io"))
    assert [f["type"] for f in mod.scan_host_takeover(_NAME)] == ["subdomain_takeover"]


def test_takeover_still_fetches_a_name_with_an_address(monkeypatch):
    mod, fetched = _takeover(monkeypatch)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))])
    mod.scan_host_takeover(_NAME)
    assert fetched == [_NAME]


@pytest.mark.parametrize("name", ["intranet.medsecure.example", "surface-db"])
def test_takeover_refuses_an_internal_name(monkeypatch, name):
    mod, fetched = _takeover(monkeypatch)
    with pytest.raises(ValueError):
        mod.scan_host_takeover(name)
    assert fetched == []
