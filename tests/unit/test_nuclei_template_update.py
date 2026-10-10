"""BUG-93 — the nuclei template refresh actually refreshes.

Surface refreshes the community templates twice: the scheduler every
``NUCLEI_AUTO_UPDATE_HOURS`` and the admin route ``POST
/nuclei/update-templates``. Both ran ``nuclei -ut -disable-update-check``;
in nuclei 3.x ``-disable-update-check`` also turns ``-ut`` off, so the
command exited 0 having done nothing, and the scheduler recorded a
successful refresh. And where the templates directory is read-only (the
suite runs Surface on a read-only root filesystem), nuclei finds the
templates outdated, writes nothing and still exits 0: there the templates
come with the image, pinned and checksummed by the add-on's install.sh.
Locks:
  - writable directory: both call sites run ``-ut`` without
    ``-disable-update-check``;
  - read-only directory: the scheduler runs nothing and records nothing, the
    admin route answers 409 (before taking a scan quota unit), and the nuclei
    config says the templates cannot be updated in place;
  - success is read in nuclei's output, not in its exit code: without
    network, or behind a blocked proxy, ``nuclei -ut`` prints its banner and
    exits 0 having updated nothing. Then the scheduler logs a warning and
    records nothing, and the admin route answers 502;
  - a templates directory not created yet is not "read-only".
"""
from __future__ import annotations

import os
import sys
import types

import pytest
import pytest_asyncio
from fastapi import HTTPException

# Same reason as test_connectors_scheduling.py: src.database builds a pooled
# engine at import, which SQLite rejects; it is never connected here.
os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import scheduler  # noqa: E402
from src.models import AppSettings  # noqa: E402
from src.routes import scans  # noqa: E402


@pytest.fixture(autouse=True)
def templates_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def read_only(templates_dir, monkeypatch):
    """The templates directory on a read-only filesystem (EROFS), whoever
    the test runs as."""
    real_access = os.access

    def access(path, mode, *a, **kw):
        if os.fspath(path) == str(templates_dir) and mode & os.W_OK:
            return False
        return real_access(path, mode, *a, **kw)

    monkeypatch.setattr("os.access", access)


_UPDATED = b"[INF] Successfully updated nuclei-templates (v10.5.0) to /opt/nuclei-templates. GoodLuck!\n"
_BANNER = b"   __     _\n  / /  projectdiscovery.io\n"  # what -ut prints without network, exit 0


@pytest.fixture
def nuclei_output():
    """What the next nuclei command prints on stderr (an update by default)."""
    return {"stderr": _UPDATED}


@pytest.fixture
def nuclei_calls(monkeypatch, nuclei_output):
    """Every nuclei command run, through the real subprocess entry point."""
    calls: list[list[str]] = []

    def run(args, **_kw):
        calls.append(list(args))
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=nuclei_output["stderr"])

    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr("subprocess.run", run)
    return calls


def _update_command(calls: list[list[str]]) -> list[str]:
    updates = [c for c in calls if "-ut" in c]
    assert len(updates) == 1, calls
    return updates[0]


@pytest_asyncio.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(scheduler, "async_session", factory)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_scheduled_refresh_runs_a_real_update(nuclei_calls, session_factory, monkeypatch):
    monkeypatch.setattr(scheduler, "NUCLEI_AUTO_UPDATE_HOURS", 24)
    await scheduler._maybe_update_nuclei_templates()
    assert "-disable-update-check" not in _update_command(nuclei_calls)
    async with session_factory() as db:
        stamped = (await db.execute(select(AppSettings).where(
            AppSettings.key == scheduler.NUCLEI_UPDATE_KEY))).scalar_one_or_none()
    assert stamped is not None


@pytest.mark.asyncio
async def test_the_admin_refresh_runs_a_real_update(nuclei_calls):
    await scans.nuclei_update_templates(user=None)  # authentication disabled
    assert "-disable-update-check" not in _update_command(nuclei_calls)


async def _stamp(session_factory):
    async with session_factory() as db:
        return (await db.execute(select(AppSettings).where(
            AppSettings.key == scheduler.NUCLEI_UPDATE_KEY))).scalar_one_or_none()


@pytest.mark.asyncio
async def test_read_only_templates_are_not_refreshed_by_the_scheduler(
        read_only, nuclei_calls, session_factory, monkeypatch):
    monkeypatch.setattr(scheduler, "NUCLEI_AUTO_UPDATE_HOURS", 24)
    await scheduler._maybe_update_nuclei_templates()
    assert not [c for c in nuclei_calls if "-ut" in c]
    assert await _stamp(session_factory) is None


@pytest.mark.asyncio
async def test_read_only_templates_make_the_admin_refresh_say_so(read_only, nuclei_calls):
    with pytest.raises(HTTPException) as exc:
        await scans.nuclei_update_templates(user=None)
    assert exc.value.status_code == 409
    assert not [c for c in nuclei_calls if "-ut" in c]


def test_the_nuclei_config_says_whether_templates_can_be_updated(nuclei_calls, request):
    assert scans._nuclei_environment_info(True)["templates_updatable"] is True
    request.getfixturevalue("read_only")
    assert scans._nuclei_environment_info(True)["templates_updatable"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("line", [b"[INF] No new updates found for nuclei templates\n",
                                  b"[INF] Successfully installed nuclei-templates at /opt/nuclei-templates\n"])
async def test_an_update_or_up_to_date_templates_are_a_success(nuclei_calls, nuclei_output, session_factory,
                                                              monkeypatch, line):
    nuclei_output["stderr"] = line
    monkeypatch.setattr(scheduler, "NUCLEI_AUTO_UPDATE_HOURS", 24)
    await scheduler._maybe_update_nuclei_templates()
    assert await _stamp(session_factory) is not None


@pytest.mark.asyncio
async def test_an_update_that_did_nothing_is_not_recorded(nuclei_calls, nuclei_output, session_factory,
                                                          monkeypatch, caplog):
    import logging
    nuclei_output["stderr"] = _BANNER
    monkeypatch.setattr(scheduler, "NUCLEI_AUTO_UPDATE_HOURS", 24)
    with caplog.at_level(logging.WARNING):
        await scheduler._maybe_update_nuclei_templates()
    assert await _stamp(session_factory) is None
    assert [r for r in caplog.records if "nuclei" in r.getMessage()]


@pytest.mark.asyncio
@pytest.mark.parametrize("rc,stderr,cause", [
    (0, _BANNER, "could not reach"),                       # no network: exit 0, nothing done
    (1, b"[FTL] no space left on device\n", "exit 1"),     # a real failure, not the network
])
async def test_the_admin_refresh_reports_why_the_update_failed(monkeypatch, nuclei_output, caplog,
                                                                rc, stderr, cause):
    import logging
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda args, **kw: types.SimpleNamespace(
        returncode=rc, stdout=b"", stderr=stderr))
    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as exc:
        await scans.nuclei_update_templates(user=None)
    assert exc.value.status_code == 502 and cause in exc.value.detail
    assert [r for r in caplog.records if stderr.decode().strip()[:20] in r.getMessage()]  # kept server-side


@pytest.mark.asyncio
async def test_a_refused_refresh_takes_no_scan_quota(read_only, nuclei_calls, monkeypatch):
    taken = []
    monkeypatch.setattr(scans, "check_scan_quota", lambda who: taken.append(who))
    with pytest.raises(HTTPException):
        await scans.nuclei_update_templates(user=None)
    assert taken == []


def test_a_templates_directory_not_created_yet_is_updatable(nuclei_calls, templates_dir, monkeypatch):
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(templates_dir / "nuclei-templates"))  # not there yet
    assert scans._nuclei_environment_info(True)["templates_updatable"] is True



# BUG-95: nuclei's output stays server-side, on failure and on success; the
# log keeps stdout as well as stderr; an accepted refresh takes a quota unit.

_PROXY_LINE = b"[ERR] proxyconnect tcp: dial tcp proxy.medsecure.example:3128: connection refused\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("rc", [0, 1])
async def test_a_failed_admin_refresh_keeps_the_output_out_of_its_answer(monkeypatch, caplog, rc):
    import logging
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda args, **kw: types.SimpleNamespace(
        returncode=rc, stdout=b"[INF] stdout says why\n", stderr=_PROXY_LINE))
    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as exc:
        await scans.nuclei_update_templates(user=None)
    assert "proxy.medsecure.example" not in exc.value.detail and "stdout says" not in exc.value.detail
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "proxy.medsecure.example" in logged and "stdout says why" in logged


@pytest.mark.asyncio
async def test_a_successful_admin_refresh_returns_no_output(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda args, **kw: types.SimpleNamespace(
        returncode=0, stdout=b"via proxy.medsecure.example\n", stderr=_UPDATED + _PROXY_LINE))
    answer = await scans.nuclei_update_templates(user=None)
    assert "proxy.medsecure.example" not in repr(answer)
    assert "templates_count" in answer and "updated_at" in answer


@pytest.mark.asyncio
async def test_the_scheduler_logs_stdout_too(monkeypatch, session_factory, caplog):
    import logging
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda args, **kw: types.SimpleNamespace(
        returncode=1, stdout=b"[INF] stdout says why\n", stderr=b""))
    monkeypatch.setattr(scheduler, "NUCLEI_AUTO_UPDATE_HOURS", 24)
    with caplog.at_level(logging.WARNING):
        await scheduler._maybe_update_nuclei_templates()
    assert [r for r in caplog.records if "stdout says why" in r.getMessage()]


@pytest.mark.asyncio
async def test_an_accepted_refresh_takes_one_scan_quota_unit(nuclei_calls, monkeypatch):
    taken = []
    monkeypatch.setattr(scans, "check_scan_quota", lambda who: taken.append(who))
    await scans.nuclei_update_templates(user=None)
    assert taken == ["anonymous"]


def test_the_logged_output_hides_proxy_credentials():
    from src.scanners import nuclei_template_update_output
    proc = types.SimpleNamespace(stdout=b"via http://ops:s3c@ret/x@proxy.medsecure.example:3128\n",
                                 stderr=b"[ERR] proxyconnect http://ops:s3cret@proxy.medsecure.example:3128 refused\n")
    out = nuclei_template_update_output(proc)
    assert "s3c" not in out and "ret/x" not in out and "ops:" not in out
    assert "proxy.medsecure.example:3128" in out
