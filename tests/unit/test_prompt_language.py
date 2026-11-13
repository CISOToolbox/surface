"""The language asked of the model is read whatever its spelling.

`fr-FR` is what a browser sends and ` fr ` what a setting may hold: both are
French, like `fr` and `FR`. Anything else is English. The route is called
too: it hands the language of the request to the prompt.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import ai  # noqa: E402
from src.routes.ai import _finding_analysis_system  # noqa: E402

FRENCH = ["fr", "FR", "fr-FR", "fr_FR", " fr ", "Fr-fr"]
ENGLISH = ["en", "EN", "en-GB", "", None, "de"]


@pytest.mark.parametrize("language", FRENCH)
def test_the_finding_triage_is_asked_in_french(language):
    assert "remediation steps in French" in _finding_analysis_system(language)


@pytest.mark.parametrize("language", ENGLISH)
def test_the_finding_triage_is_asked_in_english(language):
    system = _finding_analysis_system(language)
    assert "remediation steps in English" in system
    assert "French" not in system


# What a route receives: the spelling is read by the tests above.
SENT_FRENCH = ["fr-FR", " FR "]
SENT_ENGLISH = ["en", "", "de"]


class _Asked(Exception):
    """Raised by the fake provider: the handler stops once its prompt is known."""


def _asked_by(monkeypatch, handler, body, db=None):
    """The text the route hands to the model for `body`."""
    asked = {}

    async def provider_model(_db):
        return "anthropic", "a-model"

    async def complete(_db, system, user_prompt, _provider, _model):
        asked["text"] = system + "\n" + user_prompt
        raise _Asked

    monkeypatch.setattr(ai, "_check_ai_access", lambda _user: None)
    monkeypatch.setattr(ai, "_check_rate_limit", lambda _key: None)
    monkeypatch.setattr(ai, "_runtime_provider_model", provider_model)
    monkeypatch.setattr(ai, "_provider_complete", complete)
    with pytest.raises(_Asked):
        asyncio.run(handler(body, user=None, db=db))
    return asked["text"]


def _finding(**fields):
    return ai.FindingAnalyzeRequest(scanner="nuclei", title="Open port", **fields)


@pytest.mark.parametrize("language", SENT_FRENCH)
def test_the_route_asks_for_french(monkeypatch, language):
    asked = _asked_by(monkeypatch, ai.analyze_finding, _finding(language=language))
    assert "remediation steps in French" in asked


@pytest.mark.parametrize("language", SENT_ENGLISH)
def test_the_route_asks_for_english(monkeypatch, language):
    asked = _asked_by(monkeypatch, ai.analyze_finding, _finding(language=language))
    assert "remediation steps in English" in asked and "French" not in asked


def test_the_route_without_a_language_asks_for_english(monkeypatch):
    asked = _asked_by(monkeypatch, ai.analyze_finding, _finding())
    assert "remediation steps in English" in asked and "French" not in asked
