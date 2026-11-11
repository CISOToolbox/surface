"""The messages the API hands to a caller are written in English.

English is the product default and the backend has no translation layer: an
error detail, a refused target or a connector label written in another language
reaches every user as is, whatever the language of their interface.

The sweep reads the source, so a new message is covered the day it is written:
- the `detail=` of an HTTP error;
- the message of a raised exception (the validators' messages end up in a
  `detail`);
- the `label` and `error` values a scanner or connector add-on declares.

Finding titles and descriptions are stored data, not messages: they are not
covered here.
"""
import ast
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_GENERATED = "Generated file - do not edit"

# An accented letter, or a word no English message contains.
_FRENCH = re.compile(
    r"[àâçéèêëîïôùûœ]|\b(le|les|une|du|pour|est|pas|dans|sur|avec|ou|et|sont|"
    r"cle|cible|aucune?|invalides?|requise?s?|bloquee?|erreur|echec|trouve|"
    r"obligatoire|vide|manquants?|plage|partage|inconnu|adresse|destinataire|"
    r"trop|deja|interdite?s?|injoignable)\b",
    re.IGNORECASE,
)


def _text(node: ast.AST) -> str | None:
    """The literal part of a string or f-string, None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return " ".join(v.value for v in node.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _messages(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "detail":
            yield node.value
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            yield from node.exc.args
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in ("label", "error"):
                    yield value


def _sources():
    for top in ("src", "addons"):
        for path in sorted((_ROOT / top).rglob("*.py")):
            if path.name.startswith("test_") or "tests" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            # A generated file is fixed where it is written, not in this module.
            if _GENERATED in source[:400]:
                continue
            yield path, source


def test_the_sweep_recognises_french():
    assert _FRENCH.search("Cible requise")
    assert _FRENCH.search("un import est déjà en cours")
    assert not _FRENCH.search("Non-conformity not found")
    assert not _FRENCH.search("No finding found for the given ids")


def test_api_messages_are_english():
    french = []
    seen = 0
    for path, source in _sources():
        for node in _messages(ast.parse(source)):
            text = _text(node)
            if text is None:
                continue
            seen += 1
            if _FRENCH.search(text):
                french.append(f"{path.relative_to(_ROOT)}:{node.lineno}: {text!r}")
    assert seen > 100, "the sweep found almost no message: it reads the wrong tree"
    if french:
        pytest.fail("messages not written in English:\n" + "\n".join(french))
