"""Unit tests for the typosquatting core add-on (regression: ACME).

Locks the generation contract (offline — no DNS/CT here):
- a hyphenated domain also gets a de-hyphenated seed, so double mutations
  (drop the hyphen AND swap TLD) become reachable;
- dnstwist is invoked with a tld_dictionary, so TLD-swaps are emitted;
- the three lookalikes ACME declared for `acme-corp.example` are all
  generated within the DEFAULT variant cap (they were silently missing).
"""
import importlib.util
import os

import pytest

_HERE = os.path.dirname(__file__)
_MOD = os.path.join(_HERE, "..", "..", "addons", "core", "typosquatting", "typosquatting.py")


def _load():
    import sys
    sys.path.insert(0, os.path.join(_HERE, "..", ".."))  # make 'src' importable
    spec = importlib.util.spec_from_file_location("typosquatting_addon", _MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


typo = _load()
_HAS_DNSTWIST = importlib.util.find_spec("dnstwist") is not None


def test_seeds_add_dehyphenated_form():
    assert typo._seeds_for("acme-corp.example") == ["acme-corp.example", "acmecorp.example"]
    # no hyphen → single seed, no extra work
    assert typo._seeds_for("acme.com") == ["acme.com"]
    # composite TLD handled (sld only is de-hyphenated)
    assert typo._seeds_for("a-b-c.co.uk") == ["a-b-c.co.uk", "abc.co.uk"]


@pytest.mark.skipif(not _HAS_DNSTWIST, reason="dnstwist not installed")
def test_acme_lookalikes_generated_within_default_cap():
    # _DEF_MAX_VARIANTS is the real default the scheduled scan uses.
    perms = typo._dnstwist_permutations("acme-corp.example", typo._DEF_MAX_VARIANTS)
    generated = {d for d, _ in perms}
    for target in ("acmecorp.example", "acmecorp.example", "acme-corp.net"):
        assert target in generated, f"{target} manquant sous le cap par défaut"


@pytest.mark.skipif(not _HAS_DNSTWIST, reason="dnstwist not installed")
def test_tld_swaps_are_emitted():
    perms = typo._dnstwist_permutations("acme-corp.example", typo._DEF_MAX_VARIANTS)
    classes = {klass for _, klass in perms}
    assert "tld-swap" in classes, "aucun swap de TLD généré (tld_dictionary manquant ?)"
