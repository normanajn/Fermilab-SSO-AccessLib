"""
Tests for fermi_sso_jar: per-site status from a jar, the JarManager's
offline edits, priming and verifying through the scripted SSO adapter,
the prompt-only-when-needed rule, the command line's subcommands and exit
statuses, setup's generated files, and open_session().
"""

import json
import os
import time

import pytest

import fermi_sso_jar as tool
import fermi_sso_sites as sites
import requests_fermi_sso as rfs
from conftest import (
    FINAL_PAGE,
    LOGIN_PAGE,
    OIDC_FINAL_PAGE,
    OIDC_RESUME,
    OIDC_TARGET,
    PLAIN_PAGE,
    POSTBACK_PAGE,
    RESUME,
    SP,
    SP_COOKIE,
    TARGET,
    CHOOSE_PAGE,
    OIDC_CHOOSE_PAGE,
    OIDC_LOGIN_PAGE,
    ScriptedAdapter,
)

# Real time, so that cookies the tests mark expired are expired for the
# library's load_cookies and purge too. Status arithmetic passes now=NOW
# explicitly, so remaining-time assertions stay exact.
NOW = int(time.time())

# A JavaScript-redirect site, ServiceNow style, on the SAML connection,
# with its own resume path at the IdP so the handler can tell its postback
# from DocDB's.
JS_SP = "https://sn.example"
JS_START = JS_SP + "/navpage.do"
JS_STUB = """<html><body><script>
var location_href = 'x'; window.location = 'https://sn.example/saml/start?x=1&amp;y=2';
</script></body></html>"""
JS_FINAL = "<html><head><title>Now Home</title></head><body>Welcome Home</body></html>"
JS_RESUME = "/idp/JSJSJSJSJS/resumeSAML20/idp/SSO.ping"
JS_CHOOSE_PAGE = CHOOSE_PAGE.replace(RESUME, JS_RESUME)
JS_LOGIN_PAGE = LOGIN_PAGE.replace(RESUME, JS_RESUME)
JS_POSTBACK_PAGE = POSTBACK_PAGE.replace(SP + "/mellon/postResponse", JS_SP + "/saml/acs").replace(TARGET, JS_START)

OIDC_CALLBACK = "https://mu2e-shifts.fnal.gov/oidc/callback?code=abc&state=xyz"
PF_COOKIE = "PF=idp-1; Path=/; Secure; HttpOnly"


def full_handler(request):
    """
    Three sites behind one IdP. The IdP sets its PF session cookie at the
    login POST. Cookies are per host, so a second site never shows PF to
    its own server: it serves the choose page as always, and it is the
    IdP's resume URL, which does see PF, that skips the login form. That is
    how a primed jar signs a second site in with no password.
    """
    url, method = request.url, request.method
    cookies = request.headers.get("Cookie", "")
    idp_session = "PF=" in cookies

    # DocDB (SAML)
    if url.startswith(SP + "/mellon/postResponse"):
        return FINAL_PAGE, [f"{SP_COOKIE}=sess-1; Path=/; Secure; HttpOnly"]
    if RESUME in url:
        if method == "POST" or idp_session:
            return POSTBACK_PAGE, [PF_COOKIE]
        return LOGIN_PAGE
    if url.startswith(TARGET):
        if SP_COOKIE + "=" in cookies:
            return FINAL_PAGE
        return CHOOSE_PAGE

    # shift scheduler (OIDC): the IdP answers with a 302 to the callback
    if OIDC_RESUME in url:
        if method == "POST" or idp_session:
            return "", [PF_COOKIE], 302, {"Location": OIDC_CALLBACK}
        return OIDC_LOGIN_PAGE
    if url.startswith(OIDC_CALLBACK.split("?")[0]):
        return OIDC_FINAL_PAGE, ["shifts_session=sh-1; Path=/; Secure"]
    if url.startswith(OIDC_TARGET):
        if "shifts_session=" in cookies:
            return OIDC_FINAL_PAGE
        return OIDC_CHOOSE_PAGE

    # JavaScript-redirect site (SAML)
    if url.startswith(JS_SP + "/saml/acs"):
        return JS_FINAL, ["glide=g-1; Path=/; Secure"]
    if JS_RESUME in url:
        if method == "POST" or idp_session:
            return JS_POSTBACK_PAGE, [PF_COOKIE]
        return JS_LOGIN_PAGE
    if url.startswith(JS_START):
        if "glide=" in cookies:
            return JS_FINAL
        return JS_STUB
    if url.startswith(JS_SP + "/saml/start"):
        return JS_CHOOSE_PAGE
    return PLAIN_PAGE


def _catalog():
    cat = sites.Catalog()
    cat.merge(
        {
            "docdb": {"url": TARGET, "expect": "DocDB Home", "connection": "saml", "domains": ["mu2e-docdb.fnal.gov"]},
            "shifts": {"url": OIDC_TARGET, "expect": "Shifts", "connection": "oidc", "domains": ["mu2e-shifts.fnal.gov"]},
            "sn": {"url": JS_START, "expect": "Welcome", "connection": "saml", "js_redirect": True, "domains": ["sn.example"]},
        },
        "test",
    )
    return cat


def _records(now=NOW):
    cookies = [
        rfs._make_cookie("mellon-cookie", "abcdefgh", "mu2e-docdb.fnal.gov", "/", True, None, True, host_only=True),
        rfs._make_cookie("PF", "xyz", "pingprod.fnal.gov", "/", True, now + 7200, True, host_only=True),
        rfs._make_cookie("shifts_session", "s", "mu2e-shifts.fnal.gov", "/", True, now + 600, False, host_only=True),
        rfs._make_cookie("glide", "g", "sn.example", "/", True, now - 60, False, host_only=True),
        rfs._make_cookie("stray", "1", ".other.example", "/", False, now + 86400, False),
    ]
    from fermi_sso_cookies import cookie_record

    return cookies, [cookie_record(c, now) for c in cookies]


@pytest.fixture
def adapter():
    return ScriptedAdapter(full_handler)


@pytest.fixture
def mounted(monkeypatch, adapter):
    """Make every session the tool builds talk to the scripted adapter."""

    class Mounted(rfs.FermiSSOSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.mount("https://", adapter)

    monkeypatch.setattr(tool, "FermiSSOSession", Mounted)
    return adapter


@pytest.fixture
def mgr(tmp_path):
    return tool.JarManager(str(tmp_path / "jar.cookies"), _catalog(), margin=1800)


@pytest.fixture(autouse=True)
def isolate_user_files(tmp_path, monkeypatch):
    monkeypatch.setattr(sites, "USER_SITES_FILE", str(tmp_path / "user-sites.yaml"))
    monkeypatch.setattr(tool, "USER_SITES_FILE", str(tmp_path / "user-sites.yaml"))
    monkeypatch.delenv(sites.ENV_SITES_FILE, raising=False)
    monkeypatch.delenv(tool.probe.ENV_COOKIE_FILE, raising=False)
    monkeypatch.delenv(tool.probe.ENV_PASSWORD, raising=False)
    monkeypatch.delenv(tool.probe.ENV_AUTH, raising=False)
    monkeypatch.delenv(tool.ENV_MARGIN, raising=False)


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------


def test_site_status_states():
    _, recs = _records()
    cat = _catalog()
    by = {s.key: s for s in [tool.site_status(cat.get(k), recs, 1800) for k in cat.sites]}
    assert by["docdb"].state == "session" and by["docdb"].cookies == 1
    assert by["shifts"].state == "soon" and by["shifts"].remaining == 600
    assert by["sn"].state == "expired" and by["sn"].remaining == -60
    idp = tool.idp_status(recs, margin=1800)
    assert idp.state == "live" and idp.key == tool.IDP_KEY and idp.names == ["PF"]
    assert tool.site_status(sites.normalize_site("x", {"url": "https://nowhere.example/"}), recs).state == "absent"
    assert by["shifts"].expiry_text.startswith("in ") and "ago" in by["sn"].expiry_text
    assert by["docdb"].expiry_text == "session cookies only"


def test_manager_status_stale_and_unclaimed(mgr):
    cookies, _ = _records()
    tool._write_jar(mgr.jar, "netscape", cookies)
    statuses = mgr.status(now=NOW)
    assert [s.key for s in statuses] == ["idp", "docdb", "shifts", "sn"]
    assert mgr.stale_keys(NOW) == ["shifts", "sn"]
    assert mgr.stale_keys(NOW, include_session=True) == ["docdb", "shifts", "sn"]
    assert [r["name"] for r in mgr.unclaimed(NOW)] == ["stray"]
    only = mgr.status(["sn"], NOW)
    assert [s.key for s in only] == ["idp", "sn"]


def test_manager_without_a_jar_reports_everything_absent(mgr):
    assert mgr.records() == []
    assert all(s.state == "absent" for s in mgr.status())
    assert mgr.clear(["docdb"]) == 0 and mgr.purge_expired() == 0


def test_clear_and_purge_rewrite_the_jar_mode_600(mgr):
    cookies, _ = _records()
    tool._write_jar(mgr.jar, "netscape", cookies)
    assert mgr.clear(["docdb"]) == 1
    assert mgr.clear([], idp=True) == 1
    names = sorted(c.name for c in tool.read_jar(mgr.jar)[1])
    assert names == ["glide", "shifts_session", "stray"]
    assert mgr.purge_expired() == 1
    assert sorted(c.name for c in tool.read_jar(mgr.jar)[1]) == ["shifts_session", "stray"]
    if os.name != "nt":
        assert (os.stat(mgr.jar).st_mode & 0o777) == 0o600
    with pytest.raises(sites.SiteError):
        mgr.clear(["nope"])


# --------------------------------------------------------------------------
# priming through the scripted IdP
# --------------------------------------------------------------------------


def test_prime_logs_in_saves_and_second_site_rides_the_idp_session(mgr, mounted):
    cred = tool.Credential("password", "testuser", "s3cret")
    r = mgr.prime("docdb", cred)
    assert r.ok and r.logged_in and r.saved and r.error is None, r
    assert "ok (logged in, jar saved)" == r.summary()
    assert os.path.isfile(mgr.jar)
    by = {s.key: s for s in mgr.status()}
    assert by["docdb"].state == "session" and by["idp"].state == "session"

    # the OIDC site: no login form, the PF cookie carries it
    before = len(mounted.calls)
    r2 = mgr.prime("shifts", cred)
    assert r2.ok and not r2.logged_in and r2.saved
    assert "POST" not in [c.method for c in mounted.calls[before:]]
    assert {s.key: s.state for s in mgr.status()}["shifts"] == "session"


def test_prime_follows_a_javascript_redirect_stub(mgr, mounted):
    cred = tool.Credential("password", "testuser", "s3cret")
    r = mgr.prime("sn", cred)
    assert r.ok, r
    assert r.final_url.startswith(JS_SP + "/saml/acs")
    assert "glide" in {s.key: s for s in mgr.status()}["sn"].names
    # without js_redirect the stub is where it stops
    mgr.catalog.sites["sn"]["js_redirect"] = False
    mgr.clear(["sn"])
    r = mgr.prime("sn", cred)
    assert r.ok is False or r.final_url == JS_START


def test_verify_is_cookies_only_and_fails_without_a_session(mgr, mounted):
    r = mgr.verify("docdb")
    assert not r.ok and not r.logged_in and not r.saved
    assert any("cookie file did not yield a live session" in reason for reason in r.reasons)
    assert r.summary().startswith("FAILED")
    mgr.prime("docdb", tool.Credential("password", "testuser", "s3cret"))
    r = mgr.verify("docdb")
    assert r.ok and not r.logged_in


def test_prime_many_prompts_only_when_the_jar_fails_and_only_once(mgr, mounted):
    asked = []

    def prompt():
        asked.append(1)
        return "s3cret"

    cred = tool.Credential("password", "testuser", None, None, prompt)
    assert cred.can_login()
    results = mgr.prime_many(["docdb", "shifts", "sn"], cred)
    assert [r.ok for r in results] == [True, True, True]
    assert len(asked) == 1
    # everything is now in the jar: a second run never asks
    results = mgr.prime_many(["docdb", "shifts"], cred)
    assert all(r.ok for r in results) and len(asked) == 1


def test_prime_many_with_a_cancelled_prompt_reports_the_failure(mgr, mounted):
    cred = tool.Credential("password", "testuser", None, None, lambda: None)
    results = mgr.prime_many(["docdb"], cred)
    assert len(results) == 1 and not results[0].ok and not results[0].logged_in


def test_prime_many_stops_on_the_throttle_page(mgr, monkeypatch):
    from conftest import DELAY_PAGE

    class Throttled(rfs.FermiSSOSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.mount("https://", ScriptedAdapter(lambda req: DELAY_PAGE))

    monkeypatch.setattr(tool, "FermiSSOSession", Throttled)
    seen = []
    results = mgr.prime_many(
        ["docdb", "shifts"], tool.Credential("password", "u", "p"), progress=lambda k, r: seen.append((k, r is None))
    )
    assert len(results) == 1 and "throttling" in results[0].reasons[0]
    assert seen == [("docdb", True), ("docdb", False)]


def test_prime_reports_transport_errors_without_raising(mgr, monkeypatch):
    class Broken(rfs.FermiSSOSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)

            def boom(req):
                raise ConnectionError("no route to host")

            self.mount("https://", ScriptedAdapter(boom))

    monkeypatch.setattr(tool, "FermiSSOSession", Broken)
    r = mgr.prime("docdb", tool.Credential("password", "u", "p"))
    assert not r.ok and r.error.startswith("ConnectionError") and r.status_code is None
    assert r.summary().startswith("ERROR")


def test_prime_reports_setup_errors(mgr, mounted, monkeypatch):
    r = mgr.prime("docdb", tool.Credential("password", None, "pw"))
    assert r.error == "a password needs a username"
    # a machine with the YubiKey tools installed would pass the readiness
    # check and go on to the (scripted) network; force a missing tool
    import fermi_sso_yubikey

    monkeypatch.setattr(
        fermi_sso_yubikey.YubiKeyCertHop, "check",
        lambda self: [("openssl", False, "not found")],
    )
    r = mgr.prime("docdb", tool.Credential("yubikey"))
    assert r.error and r.error.startswith("yubikey prerequisites missing: openssl")


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------


def test_resolve_credential_precedence():
    environ = {"USER": "shelluser", tool.probe.ENV_PASSWORD: "envpw"}
    dotenv = {tool.probe.ENV_USER: "dotuser", tool.probe.ENV_PASSWORD: "dotpw"}
    settings = {"user": "setuser", "auth": "kerberos"}
    c = tool.resolve_credential(environ, dotenv, settings)
    assert c.user == "dotuser" and c.password == "envpw" and c.auth_method == "kerberos"
    c = tool.resolve_credential(environ, {}, settings)
    assert c.user == "setuser"
    c = tool.resolve_credential(environ, {}, {})
    assert c.user == "shelluser" and c.auth_method == "password"
    c = tool.resolve_credential(environ, dotenv, settings, auth="password", user="cli", password="clipw")
    assert (c.auth_method, c.user, c.password) == ("password", "cli", "clipw")
    c = tool.resolve_credential({"MYPW": "x"}, {}, {}, password_env="MYPW")
    assert c.password == "x"
    with pytest.raises(ValueError):
        tool.resolve_credential({}, {}, {}, password_env="MISSING")
    with pytest.raises(ValueError):
        tool.resolve_credential({}, {}, {"auth": "magic"})
    # a prompt is dropped for the non-password methods
    c = tool.resolve_credential({}, {}, {}, auth="kerberos", prompt=lambda: "x")
    assert c.prompt is None and c.can_login() and c.describe() == "Kerberos ticket"
    assert tool.Credential().describe() == "cookies only" and not tool.Credential().can_login()


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def _common(mgr, *extra):
    return ["--no-env-file", "-c", mgr.jar, "--no-builtin-sites", *extra]


@pytest.fixture
def cli_catalog(monkeypatch, tmp_path):
    """Make the command line load the test catalog from a sites file."""
    path = tmp_path / "test-sites.json"
    raw = {
        "docdb": {"url": TARGET, "expect": "DocDB Home", "connection": "saml", "domains": ["mu2e-docdb.fnal.gov"]},
        "shifts": {"url": OIDC_TARGET, "expect": "Shifts", "connection": "oidc", "domains": ["mu2e-shifts.fnal.gov"]},
        "sn": {"url": JS_START, "expect": "Welcome", "connection": "saml", "js_redirect": True, "domains": ["sn.example"]},
    }
    path.write_text(json.dumps({"sites": raw}), encoding="utf-8")
    monkeypatch.setenv(sites.ENV_SITES_FILE, str(path))
    return str(path)


def test_main_status_default_table_json_and_stale(mgr, cli_catalog, capsys):
    cookies, _ = _records()
    tool._write_jar(mgr.jar, "netscape", cookies)
    assert tool.main(_common(mgr)) == 0
    out, _ = capsys.readouterr()
    assert "SITE" in out and "shifts" in out and "jar     :" in out
    assert tool.main(_common(mgr, "status", "--stale", "-q")) == 1
    capsys.readouterr()
    assert tool.main(_common(mgr, "-j", "docdb")) == 0
    out, _ = capsys.readouterr()
    data = json.loads(out)
    assert [s["key"] for s in data["sites"]] == ["idp", "docdb"]
    assert data["unclaimed"][0]["name"] == "stray"
    assert tool.main(_common(mgr, "status", "--cookies", "-q")) == 0
    out, _ = capsys.readouterr()
    assert "[docdb]" in out and "[not in the catalog]" in out and "mellon-cookie" in out


def test_main_status_unknown_site_is_a_usage_error(mgr, cli_catalog, capsys):
    assert tool.main(_common(mgr, "nope")) == 2
    _, err = capsys.readouterr()
    assert "unknown site" in err


def test_main_prime_refresh_verify_and_clear(mgr, cli_catalog, mounted, capsys, monkeypatch):
    monkeypatch.setenv(tool.probe.ENV_PASSWORD, "s3cret")
    assert tool.main(_common(mgr, "prime", "-n", "-u", "testuser", "docdb")) == 0
    out, err = capsys.readouterr()
    assert "docdb" in out and "ok (logged in, jar saved)" in out and "priming 1 site" in err

    assert tool.main(_common(mgr, "verify", "docdb", "-q")) == 0
    assert tool.main(_common(mgr, "verify", "shifts", "-q")) == 0  # IdP session carries it, jar saved
    capsys.readouterr()

    assert tool.main(_common(mgr, "refresh", "-n", "-u", "testuser")) == 0
    out, _ = capsys.readouterr()
    assert "sn" in out  # the only absent site was primed
    assert tool.main(_common(mgr, "refresh", "-n", "-u", "testuser")) == 0
    out, _ = capsys.readouterr()
    assert "nothing to refresh" in out

    assert tool.main(_common(mgr, "clear", "shifts")) == 0
    out, _ = capsys.readouterr()
    assert out.startswith("removed 1 cookie")
    assert tool.main(_common(mgr, "clear")) == 2
    assert tool.main(_common(mgr, "clear", "--all", "--idp")) == 0
    assert all(s.state == "absent" for s in mgr.status())


def test_main_prime_without_credentials_is_a_usage_error(mgr, cli_catalog, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", open(os.devnull))
    assert tool.main(_common(mgr, "prime", "-n", "docdb")) == 2
    _, err = capsys.readouterr()
    assert "nothing to log in with" in err


def test_main_refresh_with_stale_sites_and_no_credential_exits_1(mgr, cli_catalog, capsys):
    assert tool.main(_common(mgr, "refresh", "-n")) == 1
    _, err = capsys.readouterr()
    assert "stale:" in err


def test_main_refresh_verify_re_logs_in_session_only_sites(mgr, cli_catalog, mounted, capsys, monkeypatch):
    monkeypatch.setenv(tool.probe.ENV_PASSWORD, "s3cret")
    tool.main(_common(mgr, "prime", "-n", "-u", "testuser"))
    capsys.readouterr()
    # drop the IdP cookie so the session-only sites no longer verify
    mgr.clear([], idp=True)
    # docdb's own mellon cookie still signs in; strip it too
    mgr.clear(["docdb"])
    assert tool.main(_common(mgr, "refresh", "--verify", "-n", "-u", "testuser")) == 0
    out, _ = capsys.readouterr()
    assert "verify:" in out and "docdb" in out


def test_main_sites_list_show_add_remove(mgr, cli_catalog, capsys, tmp_path):
    assert tool.main(_common(mgr, "sites")) == 0
    out, _ = capsys.readouterr()
    assert out.splitlines()[0].startswith("docdb")
    assert tool.main(_common(mgr, "sites", "list", "-j")) == 0
    out, _ = capsys.readouterr()
    assert set(json.loads(out)) == {"docdb", "shifts", "sn"}
    assert tool.main(_common(mgr, "sites", "show", "sn")) == 0
    out, _ = capsys.readouterr()
    assert "js_redirect: yes" in out
    assert tool.main(_common(mgr, "sites", "show", "nope")) == 2

    user_file = str(tmp_path / "user-sites.yaml")
    assert tool.main(_common(mgr, "sites", "add", "mine", "https://mine.example/sso", "-x", "Hello", "-D", "mine.example", "--connection", "oidc")) == 0
    out, _ = capsys.readouterr()
    assert out.startswith("wrote mine to")
    _, raw = sites.read_sites_file(user_file)
    assert raw["mine"]["expect"] == "Hello" and raw["mine"]["connection"] == "oidc"
    # it is now in the merged catalog
    assert tool.main(_common(mgr, "sites", "show", "mine")) == 0
    assert tool.main(_common(mgr, "sites", "add", "Bad Key", "https://x/")) == 2
    assert tool.main(_common(mgr, "sites", "remove", "mine")) == 0
    assert tool.main(_common(mgr, "sites", "remove", "mine")) == 2


def test_main_sites_add_with_test_verifies(mgr, cli_catalog, mounted, capsys):
    assert tool.main(_common(mgr, "sites", "add", "docdb2", TARGET, "-x", "DocDB Home", "--test")) == 1
    out, _ = capsys.readouterr()
    assert "FAILED" in out


def test_main_setup_dry_run_and_write(mgr, cli_catalog, capsys, tmp_path, monkeypatch):
    env_path = tmp_path / "my.env"
    argv = _common(mgr, "setup", "--non-interactive", "-u", "me", "-a", "kerberos", "--write-env", str(env_path), "--scheduler", "--shell", "sh")
    assert tool.main(argv + ["--dry-run"]) == 0
    out, _ = capsys.readouterr()
    assert not env_path.exists()
    assert "FERMI_USER=me" in out and "FERMI_SSO_AUTH=kerberos" in out
    assert "export FERMI_SSO_ENV_FILE=" in out
    # the scheduler recipe is platform specific (cron, launchd plist, schtasks)
    assert "refresh" in out and ("crontab" in out or "launchctl" in out or "schtasks" in out)

    assert tool.main(argv) == 0
    out, _ = capsys.readouterr()
    assert env_path.exists()
    if os.name != "nt":
        assert (env_path.stat().st_mode & 0o777) == 0o600
    values = tool.probe.load_env_file(str(env_path))
    assert values[tool.probe.ENV_USER] == "me" and values[tool.probe.ENV_COOKIE_FILE] == mgr.jar
    assert os.path.isfile(str(tmp_path / "user-sites.yaml"))
    # re-running merges: an existing password line survives
    env_path.write_text(env_path.read_text() + "FERMI_PASSWORD=keep me\n")
    assert tool.main(argv) == 0
    assert tool.probe.load_env_file(str(env_path))[tool.probe.ENV_PASSWORD] == "keep me"
    # an auth method from the environment is checked by the tool, not argparse
    monkeypatch.setenv(tool.probe.ENV_AUTH, "magic")
    assert tool.main(_common(mgr, "setup", "--non-interactive", "--dry-run", "--write-env", str(env_path))) == 2


def test_main_env_file_and_format_errors(mgr, capsys, tmp_path, monkeypatch):
    assert tool.main(["-e", str(tmp_path / "no.env")]) == 2
    _, err = capsys.readouterr()
    assert "env file not found" in err
    monkeypatch.setenv(tool.probe.ENV_COOKIE_FORMAT, "yaml")
    assert tool.main(["--no-env-file", "-c", mgr.jar]) == 2
    monkeypatch.delenv(tool.probe.ENV_COOKIE_FORMAT)
    monkeypatch.setenv(tool.ENV_MARGIN, "soon")
    assert tool.main(["--no-env-file", "-c", mgr.jar]) == 2
    _, err = capsys.readouterr()
    assert "integer" in err


def test_main_settings_from_catalog_and_margin_precedence(mgr, tmp_path, monkeypatch, capsys):
    cat_file = tmp_path / "cat.json"
    cat_file.write_text(json.dumps({"settings": {"cookie_file": mgr.jar, "margin": 60}, "sites": {}}))
    monkeypatch.setenv(sites.ENV_SITES_FILE, str(cat_file))
    assert tool.main(["--no-env-file", "--no-builtin-sites"]) == 0
    out, _ = capsys.readouterr()
    assert f"jar     : {mgr.jar}" in out and "margin  : 1m 0s" in out
    monkeypatch.setenv(tool.ENV_MARGIN, "120")
    tool.main(["--no-env-file", "--no-builtin-sites"])
    out, _ = capsys.readouterr()
    assert "margin  : 2m 0s" in out
    tool.main(["--no-env-file", "--no-builtin-sites", "--margin", "180"])
    out, _ = capsys.readouterr()
    assert "margin  : 3m 0s" in out


# --------------------------------------------------------------------------
# setup helpers
# --------------------------------------------------------------------------


def test_render_env_file_quotes_awkward_values():
    text = tool.render_env_file({"A": "plain", "B": "has #hash", "C": "", "D": None})
    assert "A=plain" in text and 'B="has #hash"' in text and "C=" not in text and "D" not in text


def test_shell_and_scheduler_snippets():
    assert tool.shell_snippet("~/e", "~/j", "csh").startswith("setenv FERMI_SSO_ENV_FILE")
    assert "$env:FERMI_SSO_COOKIE_FILE" in tool.shell_snippet("~/e", "~/j", "powershell")
    assert "export FERMI_SSO_COOKIE_FILE=" in tool.shell_snippet("~/e", "~/j")
    assert "crontab" in tool.scheduler_snippet("~/e", "~/j", system="Linux", interval_minutes=15)
    assert "*/15 * * * *" in tool.scheduler_snippet("~/e", "~/j", system="Linux", interval_minutes=15)
    assert "launchctl" in tool.scheduler_snippet("~/e", "~/j", system="Darwin")
    assert "schtasks" in tool.scheduler_snippet("~/e", "~/j", system="Windows")


# --------------------------------------------------------------------------
# programmatic access
# --------------------------------------------------------------------------


def test_open_session_primes_then_returns_a_cookies_only_session(mgr, mounted, monkeypatch):
    monkeypatch.setenv(tool.probe.ENV_PASSWORD, "s3cret")
    monkeypatch.setenv(tool.probe.ENV_USER, "testuser")
    s = tool.open_session("docdb", jar=mgr.jar, catalog=mgr.catalog, env_file=os.devnull)
    assert s.login_form_data is None  # the password never reaches the returned session
    assert s.cookies_loaded >= 1
    resp = s.get(TARGET)
    assert "DocDB Home" in resp.text and s.login_count == 0


def test_open_session_raises_when_it_cannot_sign_in(mgr, mounted, monkeypatch):
    monkeypatch.delenv(tool.probe.ENV_PASSWORD, raising=False)
    with pytest.raises(RuntimeError, match="cannot sign in to docdb"):
        tool.open_session("docdb", jar=mgr.jar, catalog=mgr.catalog, env_file=os.devnull, credential=tool.Credential())


def test_open_session_without_a_site_just_loads_the_jar(mgr, mounted):
    cookies, _ = _records()
    tool._write_jar(mgr.jar, "netscape", cookies)
    s = tool.open_session(jar=mgr.jar, catalog=mgr.catalog, env_file=os.devnull, credential=tool.Credential())
    assert s.cookies_loaded == 4  # the expired glide cookie is skipped
