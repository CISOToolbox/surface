"""Regression: SMB credentials are bound to their destination.

An editor could point a monitored `file_share` at a host they control and
have the scan authenticate there (NTLM capture or relay):
  - a share on a public host was accepted from an editor;
  - changing the host of a share kept its stored password;
  - without per-target credentials the worker used the deployment's service
    account (SURFACE_SMB_*) whatever the host.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "clef-de-test-suffisamment-longue-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402

import src.routes.monitored as mon  # noqa: E402
from conftest import load_core_addon  # noqa: E402
from src.models import MonitoredAsset  # noqa: E402
from src.scanners import SCANNER_REGISTRY  # noqa: E402

LAN_SHARE = r"\\10.20.0.5\finance"
PUBLIC_SHARE = r"\\198.51.100.7\finance"  # documentation block, outside the LAN


@pytest.fixture(autouse=True)
def _file_share_kind(monkeypatch):
    # The SMB add-on contributes the file_share kind; unit tests load core only.
    monkeypatch.setitem(SCANNER_REGISTRY, "smb_test", {"kinds": {"file_share"}})

    async def _no_log(*a, **k):
        return None
    monkeypatch.setattr(mon, "log_action", _no_log)


def _user(role: str):
    return SimpleNamespace(id=uuid.uuid4(), email=f"{role}@medsecure.example", _module_role=role)


class _DB:
    def __init__(self, asset=None):
        self.asset = asset

    async def get(self, _model, _id):
        return self.asset

    def add(self, obj):
        self.asset = obj

    async def commit(self):
        return None

    async def refresh(self, _obj):
        return None


def _create(value: str, role: str):
    body = mon.MonitoredAssetCreate(kind="file_share", value=value, enabled_scanners=[])
    return asyncio.run(mon.create_asset(body, request=None, user=_user(role), db=_DB()))


def _share(value: str = LAN_SHARE) -> MonitoredAsset:
    return MonitoredAsset(id=uuid.uuid4(), kind="file_share", value=value, enabled=True,
                          enabled_scanners=[], tags=[],
                          config={"smb_username": "svc-scan", "smb_password_enc": "ENC-OLD"})


def _patch(asset: MonitoredAsset, role: str = "editor", **fields):
    body = mon.MonitoredAssetUpdate(**fields)
    return asyncio.run(mon.update_asset(asset.id, body, request=None, user=_user(role), db=_DB(asset)))


class TestPublicShareNeedsAdmin:
    def test_editor_cannot_create_public_share(self):
        with pytest.raises(HTTPException) as e:
            _create(PUBLIC_SHARE, "editor")
        assert e.value.status_code == 403

    def test_editor_can_create_lan_share(self):
        assert _create(LAN_SHARE, "editor")["value"] == LAN_SHARE

    def test_admin_can_create_public_share(self):
        assert _create(PUBLIC_SHARE, "admin")["value"] == PUBLIC_SHARE

    def test_editor_can_edit_an_existing_public_share(self):
        # The edit form always sends kind and value, unchanged here.
        a = _share(PUBLIC_SHARE)
        _patch(a, kind="file_share", value=PUBLIC_SHARE, label="Finance (MedSecure)",
               config={"smb_username": "svc-scan", "custom_regex": ["IBAN"]})
        assert a.label == "Finance (MedSecure)"
        assert a.config["smb_password_enc"] == "ENC-OLD"

    def test_editor_cannot_move_share_to_another_public_host(self):
        with pytest.raises(HTTPException) as e:
            _patch(_share(PUBLIC_SHARE), kind="file_share", value=r"\\198.51.100.8\finance")
        assert e.value.status_code == 403

    def test_editor_cannot_move_share_to_public_host(self):
        with pytest.raises(HTTPException) as e:
            _patch(_share(), value=PUBLIC_SHARE)
        assert e.value.status_code == 403


class TestPasswordFollowsHost:
    def test_host_change_erases_password(self):
        a = _share()
        out = _patch(a, value=r"\\10.20.0.6\finance")
        assert "smb_password_enc" not in a.config
        assert out["config"]["smb_password_set"] is False
        assert a.config["smb_username"] == "svc-scan"

    def test_host_change_with_config_erases_password(self):
        a = _share()
        _patch(a, value=r"\\10.20.0.6\finance", config={"smb_username": "svc-scan"})
        assert "smb_password_enc" not in a.config

    def test_host_change_with_new_password_keeps_the_new_one(self):
        a = _share()
        _patch(a, value=r"\\10.20.0.6\finance", config={"smb_username": "svc", "smb_password": "n3w"})
        assert a.config["smb_password_enc"] not in ("", "ENC-OLD")

    def test_same_host_other_share_keeps_password(self):
        a = _share()
        _patch(a, value=r"\\10.20.0.5\hr", config={"smb_username": "svc-scan"})
        assert a.config["smb_password_enc"] == "ENC-OLD"


class TestServiceAccountStaysOnLan:
    @pytest.fixture
    def worker(self, monkeypatch, tmp_path):
        smb = load_core_addon("smb_scan_rs")
        captured: dict = {}

        class _Proc:
            stderr = None
            returncode = 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        def _popen(argv, env=None, **kw):
            captured.update(env or {})
            proc = _Proc()
            proc.stdout = list(lines)
            return proc

        lines: list[str] = []
        captured["_lines"] = lines

        binary = tmp_path / "ciso-smb-scan"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        monkeypatch.setattr(smb, "_BIN", str(binary))
        monkeypatch.setattr(smb.subprocess, "Popen", _popen)
        monkeypatch.setenv("SURFACE_SMB_USERNAME", "svc-global")
        monkeypatch.setenv("SURFACE_SMB_PASSWORD", "global-pass")
        monkeypatch.setenv("SURFACE_SMB_DOMAIN", "MEDSECURE")
        return smb, captured

    def test_lan_share_uses_service_account(self, worker):
        smb, env = worker
        smb.scan_smb_share_rs(LAN_SHARE, {})
        assert env.get("SMB_USER") == "svc-global" and env.get("SMB_PASS") == "global-pass"

    def test_public_share_without_credentials_gets_none(self, worker):
        smb, env = worker
        out = smb.scan_smb_share_rs(PUBLIC_SHARE, {})
        assert "SMB_PASS" not in env
        assert out and out[0]["title"] == "Missing SMB credentials"

    def test_public_share_with_target_username_never_gets_global_password(self, worker):
        smb, env = worker
        smb.scan_smb_share_rs(PUBLIC_SHARE, {"smb_username": "attacker"})
        assert env.get("SMB_PASS") != "global-pass"

    def test_lan_name_with_a_public_address_is_not_lan(self, worker, monkeypatch):
        smb, env = worker
        import src.scan_common as sc
        monkeypatch.setattr(sc.socket, "getaddrinfo", lambda *a, **k: [
            (2, 1, 6, "", ("10.20.0.5", 0)), (2, 1, 6, "", ("198.51.100.7", 0))])
        smb.scan_smb_share_rs(r"\\files.medsecure.example\finance", {})
        assert env.get("SMB_PASS") != "global-pass"

    def test_service_account_goes_to_the_vetted_address(self, worker, monkeypatch):
        # A LAN name: the worker connects to the address just checked, not to
        # what the name resolves to later; its output keeps the name.
        smb, env = worker
        import json
        import src.scan_common as sc
        monkeypatch.setattr(sc.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.20.0.5", 0))])
        share = r"\\Files.medsecure.example\finance"
        env["_lines"][:] = [
            json.dumps({"type": "secret", "title": "Secret in file", "target": r"\\10.20.0.5\finance\pay.xlsx",
                        "evidence": {"file": r"\\10.20.0.5\finance\pay.xlsx"}}),
            json.dumps({"type": "smb_status", "title": "Connexion SMB échouée : 10.20.0.5",
                        "target": r"\\10.20.0.5\finance", "evidence": {}}),
        ]
        out = smb.scan_smb_share_rs(share, {})
        assert env["SMB_TARGET"] == r"\\10.20.0.5\finance" and env["SMB_PASS"] == "global-pass"
        content = [f for f in out if f["type"] == "secret"][0]
        assert content["target"] == r"\\Files.medsecure.example\finance\pay.xlsx"
        assert content["evidence"]["file"] == r"\\Files.medsecure.example\finance\pay.xlsx"
        status = [f for f in out if f["type"] == "smb_status"][0]
        assert status["title"] == "Connexion SMB échouée : Files.medsecure.example"
        assert status["target"] == share

    def test_pins_the_ipv4_when_an_ipv6_ula_is_listed_first(self, worker, monkeypatch):
        smb, env = worker
        import src.scan_common as sc
        monkeypatch.setattr(sc.socket, "getaddrinfo", lambda *a, **k: [
            (10, 1, 6, "", ("fd12:3456::5", 0, 0, 0)), (2, 1, 6, "", ("10.20.0.5", 0))])
        smb.scan_smb_share_rs(r"\\files.medsecure.example\finance", {})
        assert env["SMB_TARGET"] == r"\\10.20.0.5\finance" and env["SMB_PASS"] == "global-pass"

    def test_target_credentials_are_not_pinned(self, worker, monkeypatch):
        smb, env = worker
        import src.scan_common as sc
        monkeypatch.setattr(sc.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.20.0.5", 0))])
        monkeypatch.setattr("src.crypto.decrypt_secret", lambda enc: "own-pass")
        share = r"\\files.medsecure.example\finance"
        smb.scan_smb_share_rs(share, {"smb_username": "own", "smb_password_enc": "ENC"})
        assert env["SMB_TARGET"] == share and env["SMB_PASS"] == "own-pass"
