"""FEAT-37 — connector configuration persistence.

What is verified here fits one sentence: **a secret goes in, it does not come
back out, and it is encrypted at rest**. That is acceptance criterion 8 of the
spec, and the only one whose failure shows too late — in a database dump or an
interface screenshot.

The other tests cover the partial-save trap: the interface never re-displays a
secret, so it sends an empty string for an unchanged one. Overwriting at that
moment would erase the credentials as soon as a typo in the tenant id is
fixed.
"""
from __future__ import annotations

import os
import sys

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
# Without a key, settings_crypto stores cleartext (and logs it): the
# at-rest-encryption test would be green for the wrong reason.
os.environ.setdefault("ENCRYPTION_KEY", "clef-de-test-suffisamment-longue-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.connectors_config import (add_instance, is_configured, is_enabled,  # noqa: E402
                                   key_for, list_instances, read_config,
                                   read_public, record_run, remove_instance,
                                   save_config)
from src.models import AppSettings, Base  # noqa: E402
from src.settings_crypto import is_secret_key  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

SCHEMA = [
    {"key": "tenant_id", "label": "Tenant", "type": "text", "required": True},
    {"key": "client_id", "label": "App id", "type": "text", "required": True},
    {"key": "client_secret", "label": "Secret", "type": "password",
     "secret": True, "required": True},
]
META = {"label": "Defender", "interval_hours": 6, "config_schema": SCHEMA}
NOM = "defender"
SECRET = "s3cr3t-tres-identifiable"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://",
                                 connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


async def _seed(db, **extra):
    values = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": SECRET}
    values.update(extra)
    await save_config(db, NOM, SCHEMA, values, enabled=True)
    await db.commit()


def test_the_key_naming_triggers_encryption():
    """The historical pattern still covers the standard schema — but the
    schema is what decides (see the jeton test below)."""
    for f in SCHEMA:
        k = key_for(NOM, f["key"])
        if f.get("secret"):
            assert is_secret_key(k), f"{k} will NOT be encrypted at rest"
        else:
            assert not is_secret_key(k)


@pytest.mark.asyncio
async def test_the_secret_is_encrypted_at_rest(db):
    await _seed(db)
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == key_for(NOM, "client_secret"))
    )).scalar_one()
    assert SECRET not in row.value, "the secret is stored in cleartext"
    assert row.value.startswith("enc:v1:"), "encryption marker missing"
    # …and it stays readable for execution.
    assert (await read_config(db, NOM, SCHEMA))["client_secret"] == SECRET


@pytest.mark.asyncio
async def test_the_secret_never_reaches_the_ui(db):
    await _seed(db)
    pub = await read_public(db, NOM, META)
    assert SECRET not in repr(pub), "a secret leaked to the interface"
    field = next(f for f in pub["fields"] if f["key"] == "client_secret")
    assert field["value"] == ""
    assert field["set"] is True, "the interface can no longer tell a secret exists"
    # A non-secret field DOES re-display: otherwise the form erases itself.
    assert next(f for f in pub["fields"] if f["key"] == "tenant_id")["value"] == "t-1"


@pytest.mark.asyncio
async def test_saving_a_neighbour_field_keeps_the_secret(db):
    """The trap: the interface sends "" for an unchanged secret."""
    await _seed(db)
    await save_config(db, NOM, SCHEMA,
                      {"tenant_id": "t-2", "client_secret": ""}, enabled=None)
    await db.commit()
    cfg = await read_config(db, NOM, SCHEMA)
    assert cfg["tenant_id"] == "t-2"
    assert cfg["client_secret"] == SECRET, "the secret was erased by a save"


@pytest.mark.asyncio
async def test_a_secret_can_still_be_cleared_explicitly(db):
    await _seed(db)
    await save_config(db, NOM, SCHEMA, {"client_secret": None}, enabled=None)
    await db.commit()
    assert (await read_config(db, NOM, SCHEMA))["client_secret"] == ""
    assert await is_configured(db, NOM, SCHEMA) is False


@pytest.mark.asyncio
async def test_unknown_fields_are_ignored(db):
    """The schema is the boundary: an invented field creates no key."""
    await save_config(db, NOM, SCHEMA, {"admin": "1", "tenant_id": "t"}, enabled=None)
    await db.commit()
    keys = [k for (k,) in (await db.execute(select(AppSettings.key))).all()]
    assert key_for(NOM, "admin") not in keys


@pytest.mark.asyncio
async def test_enabled_and_configured_are_independent(db):
    """Enabled without credentials must not read as configured: the scheduler
    relies on both to avoid hammering the upstream API."""
    await save_config(db, NOM, SCHEMA, {}, enabled=True)
    await db.commit()
    assert await is_enabled(db, NOM) is True
    assert await is_configured(db, NOM, SCHEMA) is False


@pytest.mark.asyncio
async def test_a_failed_run_is_still_timestamped(db):
    """Without a timestamp on failure, the scheduler would relaunch the
    connector on every 60 s tick and get the service account blocked."""
    await _seed(db)
    await record_run(db, NOM, {"ok": False, "error": "HTTP 401", "hosts": 0,
                               "findings": 0, "closed": 0, "duration_s": 0.2})
    await db.commit()
    pub = await read_public(db, NOM, META)
    assert pub["last_run_at"], "a failure was not timestamped"
    assert pub["last_result"]["ok"] is False
    assert pub["last_result"]["error"] == "HTTP 401"


@pytest.mark.asyncio
async def test_the_schema_decides_encryption_not_the_key_name(db):
    """A secret field whose key escapes the historical naming pattern
    (`connector_x_jeton`) must STILL be encrypted: the schema declares it
    secret. This is the exact defect of the first version of the module —
    the secret went to the database in cleartext, silently."""
    schema = [{"key": "jeton", "label": "Jeton", "type": "password",
               "secret": True, "required": True}]
    assert not is_secret_key(key_for(NOM, "jeton"))   # the pattern misses it…
    await save_config(db, NOM, schema, {"jeton": SECRET}, enabled=None)
    await db.commit()
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == key_for(NOM, "jeton"))
    )).scalar_one()
    assert SECRET not in row.value                    # …the schema catches it
    assert row.value.startswith("enc:v1:")
    assert (await read_config(db, NOM, schema))["jeton"] == SECRET


@pytest.mark.asyncio
async def test_instances_register_configure_and_remove_cleanly(db):
    """An extra instance gets its own config namespace; removing it deletes
    the config — and only its config."""
    key = await add_instance(db, NOM, "Tenant ACME")
    assert key == "defender:tenant-acme"
    assert (await list_instances(db))[key]["type"] == NOM

    await save_config(db, key, SCHEMA,
                      {"tenant_id": "t-acme", "client_secret": SECRET}, enabled=True)
    await _seed(db)                       # default instance, its own values
    assert (await read_config(db, key, SCHEMA))["tenant_id"] == "t-acme"
    assert (await read_config(db, NOM, SCHEMA))["tenant_id"] == "t-1"

    await remove_instance(db, key)
    await db.commit()
    assert key not in await list_instances(db)
    assert (await read_config(db, key, SCHEMA))["tenant_id"] == ""
    # The default instance's config is untouched.
    assert (await read_config(db, NOM, SCHEMA))["tenant_id"] == "t-1"


@pytest.mark.asyncio
async def test_an_instance_secret_is_encrypted_too(db):
    """The instance key contains a colon — the historical naming pattern
    surely does not match it, so only the schema protects the secret."""
    key = await add_instance(db, NOM, "acme")
    await save_config(db, key, SCHEMA, {"client_secret": SECRET}, enabled=None)
    await db.commit()
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == key_for(key, "client_secret"))
    )).scalar_one()
    assert SECRET not in row.value
    assert row.value.startswith("enc:v1:")


@pytest.mark.asyncio
async def test_duplicate_or_invalid_instance_labels_are_rejected(db):
    await add_instance(db, NOM, "acme")
    with pytest.raises(ValueError):
        await add_instance(db, NOM, "acme")
    with pytest.raises(ValueError):
        await add_instance(db, NOM, "!!!")


@pytest.mark.asyncio
async def test_removing_an_instance_spares_its_sibling(db):
    """The regression the review reproduced: "_" is a single-character SQL
    LIKE wildcard, so deleting "acme" also purged every "acme-prod" key —
    encrypted credentials included — while the sibling stayed registered and
    enabled. The prefix match must escape the wildcards."""
    a = await add_instance(db, NOM, "acme")
    b = await add_instance(db, NOM, "acme-prod")
    await save_config(db, a, SCHEMA, {"tenant_id": "t-a", "client_secret": SECRET}, True)
    await save_config(db, b, SCHEMA, {"tenant_id": "t-b", "client_secret": SECRET}, True)
    await db.commit()

    await remove_instance(db, a)
    await db.commit()

    cfg_b = await read_config(db, b, SCHEMA)
    assert cfg_b["tenant_id"] == "t-b", "the sibling instance's config was purged"
    assert cfg_b["client_secret"] == SECRET, "the sibling instance's SECRET was purged"
    # And reads do not bleed between sibling prefixes either.
    assert (await read_config(db, a, SCHEMA))["tenant_id"] == ""


@pytest.mark.asyncio
async def test_a_pristine_default_instance_is_hidden_from_the_list(db, monkeypatch):
    """The page starts empty: every visible connector is one the admin chose
    to add. A default instance that carries config or history stays visible
    (it predates the add-a-connector flow)."""
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://t:t@localhost:5432/t"
    import src.routes.connectors as rc
    monkeypatch.setattr(rc, "CONNECTOR_REGISTRY", {NOM: META}, raising=False)

    listed = await rc.list_connectors(user=None, db=db)
    assert listed == [], "a pristine default instance leaked into the list"

    types = await rc.list_connector_types(user=None)
    assert [t["name"] for t in types] == [NOM]

    await _seed(db)                      # configured → visible again
    listed = await rc.list_connectors(user=None, db=db)
    assert [e["name"] for e in listed] == [NOM]
    assert listed[0]["deletable"] is False

    key = await add_instance(db, NOM, "acme")
    await db.commit()
    listed = await rc.list_connectors(user=None, db=db)
    assert [e["name"] for e in listed] == [NOM, key]
    assert listed[1]["deletable"] is True


@pytest.mark.asyncio
async def test_the_scanners_catalog_reflects_installed_connectors(db, monkeypatch):
    """The host scanner picker lists connector instances as scanners, so a
    just-added instance becomes selectable without any hardcoded list."""
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://t:t@localhost:5432/t"
    import src.routes.monitored as rm
    import src.scanners as sc
    # scanners_catalog imports CONNECTOR_REGISTRY from src.scanners locally,
    # so the patch must land there.
    monkeypatch.setattr(sc, "CONNECTOR_REGISTRY", {NOM: META}, raising=False)

    cat = await rm.scanners_catalog(user=None, db=db)
    host_names = [s["name"] for s in cat["host"]["scanners"]]
    assert NOM in host_names, "the default connector is not offered as a host scanner"

    key = await add_instance(db, NOM, "acme")
    await db.commit()
    cat = await rm.scanners_catalog(user=None, db=db)
    host_names = [s["name"] for s in cat["host"]["scanners"]]
    assert key in host_names, "a new instance is not reflected in the catalog"
