"""
Tests for fermi_sso_probe: .env parsing, the settings precedence chain, and
the success/failure classifier.
"""

import pytest

import fermi_sso_probe as probe
from requests_fermi_sso import FermiSSOSession

from conftest import (
    CHOOSE_PAGE,
    FINAL_PAGE,
    LOGIN_PAGE,
    POSTBACK_PAGE,
    SP,
    TARGET,
    make_response,
)

# --------------------------------------------------------------------------
# .env parsing
# --------------------------------------------------------------------------


def test_parse_env_file_basic():
    parsed = probe.parse_env_file("FERMI_USER=alice\nFERMI_PASSWORD=hunter2\n")
    assert parsed == {"FERMI_USER": "alice", "FERMI_PASSWORD": "hunter2"}


def test_parse_env_file_ignores_comments_and_blanks():
    text = "# a comment\n\n  \nFERMI_USER=alice\n#FERMI_USER=bob\n"
    assert probe.parse_env_file(text) == {"FERMI_USER": "alice"}


def test_parse_env_file_strips_export_prefix():
    assert probe.parse_env_file("export FERMI_USER=alice\n") == {"FERMI_USER": "alice"}


def test_parse_env_file_strips_quotes():
    parsed = probe.parse_env_file("A='single'\nB=\"double\"\n")
    assert parsed == {"A": "single", "B": "double"}


def test_parse_env_file_quoted_values_keep_specials():
    """A quoted password may legitimately contain # or spaces."""
    parsed = probe.parse_env_file('FERMI_PASSWORD="pa ss#word"\n')
    assert parsed["FERMI_PASSWORD"] == "pa ss#word"


def test_parse_env_file_strips_inline_comment_when_unquoted():
    parsed = probe.parse_env_file("FERMI_USER=alice # my account\n")
    assert parsed["FERMI_USER"] == "alice"


def test_parse_env_file_keeps_equals_in_value():
    parsed = probe.parse_env_file("FERMI_SSO_URL=https://x/y?a=b&c=d\n")
    assert parsed["FERMI_SSO_URL"] == "https://x/y?a=b&c=d"


def test_parse_env_file_skips_lines_without_equals():
    assert probe.parse_env_file("garbage line\nA=1\n") == {"A": "1"}


def test_load_env_file_reads_from_disk(tmp_path):
    path = tmp_path / ".env"
    path.write_text("FERMI_USER=alice\n")
    assert probe.load_env_file(str(path))["FERMI_USER"] == "alice"


def test_load_env_file_returns_empty_for_missing(tmp_path):
    assert probe.load_env_file(str(tmp_path / "nope.env")) == {}


def test_load_env_file_returns_empty_for_none():
    assert probe.load_env_file(None) == {}


def test_load_env_file_warns_when_world_readable(tmp_path):
    import os

    path = tmp_path / ".env"
    path.write_text("FERMI_PASSWORD=hunter2\n")
    os.chmod(str(path), 0o644)
    warnings = []
    probe.load_env_file(str(path), warn=warnings.append)
    assert any("readable by group/other" in w for w in warnings)


def test_load_env_file_quiet_when_mode_is_600(tmp_path):
    import os

    path = tmp_path / ".env"
    path.write_text("FERMI_PASSWORD=hunter2\n")
    os.chmod(str(path), 0o600)
    warnings = []
    probe.load_env_file(str(path), warn=warnings.append)
    assert warnings == []


# --------------------------------------------------------------------------
# env file discovery
# --------------------------------------------------------------------------


def test_find_env_file_prefers_explicit_argument():
    assert probe.find_env_file("/tmp/custom.env", {}) == "/tmp/custom.env"


def test_find_env_file_uses_environment_variable():
    environ = {probe.ENV_ENV_FILE: "/tmp/from-env.env"}
    assert probe.find_env_file(None, environ) == "/tmp/from-env.env"


def test_find_env_file_argument_beats_environment():
    environ = {probe.ENV_ENV_FILE: "/tmp/from-env.env"}
    assert probe.find_env_file("/tmp/cli.env", environ) == "/tmp/cli.env"


def test_find_env_file_expands_tilde():
    result = probe.find_env_file("~/x.env", {})
    assert result and not result.startswith("~")


def test_find_env_file_returns_none_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(probe, "DEFAULT_ENV_FILES", (".env", str(tmp_path / "no.env")))
    assert probe.find_env_file(None, {}) is None


def test_find_env_file_finds_cwd_dotenv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("A=1\n")
    assert probe.find_env_file(None, {}) == ".env"


# --------------------------------------------------------------------------
# precedence
# --------------------------------------------------------------------------


def test_resolve_prefers_commandline():
    got = probe.resolve("cli", "KEY", {"KEY": "env"}, {"KEY": "dotenv"}, "default")
    assert got == "cli"


def test_resolve_falls_back_to_environment():
    got = probe.resolve(None, "KEY", {"KEY": "env"}, {"KEY": "dotenv"}, "default")
    assert got == "env"


def test_resolve_falls_back_to_dotenv():
    got = probe.resolve(None, "KEY", {}, {"KEY": "dotenv"}, "default")
    assert got == "dotenv"


def test_resolve_falls_back_to_default():
    assert probe.resolve(None, "KEY", {}, {}, "default") == "default"


def test_resolve_treats_empty_environment_value_as_absent():
    assert probe.resolve(None, "KEY", {"KEY": ""}, {"KEY": "dotenv"}, "d") == "dotenv"


# --------------------------------------------------------------------------
# password resolution
# --------------------------------------------------------------------------


def _args(**overrides):
    argv = overrides.pop("argv", [])
    args = probe.build_parser().parse_args(argv)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_password_from_commandline():
    got = probe.resolve_password(_args(argv=["-p", "cli-pass"]), {}, {})
    assert got == "cli-pass"


def test_password_from_named_environment_variable():
    args = _args(argv=["--password-env", "MY_PASS"])
    assert probe.resolve_password(args, {"MY_PASS": "from-env"}, {}) == "from-env"


def test_password_env_missing_is_an_error():
    args = _args(argv=["--password-env", "MY_PASS"])
    with pytest.raises(ValueError, match="MY_PASS"):
        probe.resolve_password(args, {}, {})


def test_password_from_default_environment_variable():
    environ = {probe.ENV_PASSWORD: "from-fermi-password"}
    assert probe.resolve_password(_args(), environ, {}) == "from-fermi-password"


def test_password_from_dotenv():
    dotenv = {probe.ENV_PASSWORD: "from-dotenv"}
    assert probe.resolve_password(_args(), {}, dotenv) == "from-dotenv"


def test_password_commandline_beats_everything():
    args = _args(argv=["-p", "cli"])
    environ = {probe.ENV_PASSWORD: "env"}
    assert probe.resolve_password(args, environ, {probe.ENV_PASSWORD: "dot"}) == "cli"


def test_password_environment_beats_dotenv():
    environ = {probe.ENV_PASSWORD: "env"}
    assert (
        probe.resolve_password(_args(), environ, {probe.ENV_PASSWORD: "dot"}) == "env"
    )


def test_password_prompts_as_last_resort():
    assert probe.resolve_password(_args(), {}, {}, prompt=lambda: "typed") == "typed"


def test_password_returns_none_without_a_prompt():
    assert probe.resolve_password(_args(), {}, {}) is None


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------


def test_url_can_be_positional():
    assert probe.build_parser().parse_args(["https://x/y"]).url == "https://x/y"


def test_url_can_be_an_option():
    assert (
        probe.build_parser().parse_args(["-U", "https://x/y"]).url_opt == "https://x/y"
    )


def test_url_defaults_to_none_so_precedence_applies():
    args = probe.build_parser().parse_args([])
    assert args.url is None and args.url_opt is None


def test_default_url_is_the_docdb_sso_entry_point():
    assert probe.DEFAULT_URL.startswith("https://mu2e-docdb.fnal.gov/cgi-bin/sso/")


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------


def _resp(text, url):
    import requests

    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


@pytest.fixture
def session():
    return FermiSSOSession()


def test_classify_success(session):
    ok, reasons = _classify(session, FINAL_PAGE, SP + "/DocDB")
    assert ok and reasons == []


def test_classify_detects_login_page():
    session = FermiSSOSession(userpass="u:p")
    ok, reasons = _classify(session, LOGIN_PAGE, "https://pingprod.fnal.gov/idp/x")
    assert not ok
    assert any("still on the login form" in r for r in reasons)
    assert any("MFA" in r for r in reasons)


def test_classify_login_page_without_credentials_blames_the_cookies(session):
    """With no userpass the only way in was the cookie jar, so say so."""
    ok, reasons = _classify(session, LOGIN_PAGE, "https://pingprod.fnal.gov/idp/x")
    assert not ok
    assert any("cookie file" in r and "no password" in r for r in reasons)


def test_classify_detects_choose_page(session):
    ok, reasons = _classify(session, CHOOSE_PAGE, "https://pingprod.fnal.gov/idp/x")
    assert not ok
    assert any("choose-authentication" in r for r in reasons)


def test_classify_detects_unsubmitted_postback(session):
    ok, reasons = _classify(session, POSTBACK_PAGE, "https://pingprod.fnal.gov/idp/x")
    assert not ok
    assert any("postback" in r for r in reasons)


def test_classify_detects_stranded_on_idp(session):
    ok, reasons = _classify(session, "<html>huh</html>", "https://pingprod.fnal.gov/x")
    assert not ok
    assert any("stranded" in r for r in reasons)


def test_classify_honours_expect_text(session):
    ok, reasons = _classify(session, FINAL_PAGE, SP + "/DocDB", expect="DocDB Home")
    assert ok
    ok, reasons = _classify(session, FINAL_PAGE, SP + "/DocDB", expect="Not Present")
    assert not ok
    assert any("not found" in r for r in reasons)


def test_classify_ignores_idp_host_when_blank(session):
    ok, _ = _classify(session, FINAL_PAGE, "https://pingprod.fnal.gov/x", idp_host="")
    assert ok


def test_classify_rejects_an_application_signin_page(session):
    """
    django-allauth's SSO confirmation page is off the IdP and matches none of
    the IdP patterns, but it is still a sign-in page. Seen at
    mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/, 2026-09-02.
    """
    page = '<html><head><title>Sign In via SSO \u2014 Mu2eTalks</title></head><body><form method="post"></form></body></html>'
    ok, reasons = _classify(
        session, page, "https://mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/"
    )
    assert not ok
    assert any("application sign-in page" in r for r in reasons)


def test_classify_accepts_ordinary_titles(session):
    for title in ("Dashboard | Mu2eTalks", "Mu2e Document Database", "Shift Calendar"):
        page = f"<html><head><title>{title}</title></head><body>ok</body></html>"
        ok, _ = _classify(session, page, SP + "/x")
        assert ok, title


def _classify(session, text, url, idp_host=probe.DEFAULT_IDP_HOST, expect=None):
    return probe.classify(session, _resp(text, url), idp_host, expect)


# --------------------------------------------------------------------------
# main()
# --------------------------------------------------------------------------


def test_main_errors_without_a_username(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv(probe.ENV_USER, raising=False)
    assert probe.main(["--no-env-file", "-n"]) == 2
    assert "no username" in capsys.readouterr().err


def test_main_errors_without_a_password(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    assert probe.main(["--no-env-file", "-n", "-u", "alice"]) == 2
    assert "no password" in capsys.readouterr().err


def test_main_rejects_a_colon_in_the_password(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    argv = ["--no-env-file", "-n", "-u", "alice", "-p", "has:colon"]
    assert probe.main(argv) == 2
    assert "contains ':'" in capsys.readouterr().err


def test_main_errors_on_missing_explicit_env_file(tmp_path, capsys):
    argv = ["-e", str(tmp_path / "absent.env"), "-u", "alice", "-n"]
    assert probe.main(argv) == 2
    assert "env file not found" in capsys.readouterr().err


def test_main_reads_credentials_from_an_env_file(monkeypatch, tmp_path, capsys):
    """A full run against the scripted transport, credentials from .env only."""
    env_path = tmp_path / "creds.env"
    env_path.write_text("FERMI_USER=testuser\nFERMI_PASSWORD=s3cret\n")
    monkeypatch.delenv(probe.ENV_USER, raising=False)
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    _patch_session(monkeypatch)

    code = probe.main(["-e", str(env_path), "-x", "DocDB Home", TARGET])

    assert code == 0
    assert "RESULT: login SUCCEEDED" in capsys.readouterr().err


def test_main_reports_failure_when_expect_text_is_absent(monkeypatch, tmp_path, capsys):
    _patch_session(monkeypatch)
    argv = ["--no-env-file", "-u", "testuser", "-p", "s3cret", "-x", "nope", TARGET]
    assert probe.main(argv) == 1
    assert "RESULT: login FAILED" in capsys.readouterr().err


def test_main_writes_body_to_output_file(monkeypatch, tmp_path, capsys):
    _patch_session(monkeypatch)
    out = tmp_path / "body.html"
    argv = ["--no-env-file", "-u", "u", "-p", "p", "-o", str(out), TARGET]
    assert probe.main(argv) == 0
    assert "DocDB Home" in out.read_text()


def _patch_session(monkeypatch):
    """Make probe.main build sessions bound to the scripted adapter."""
    from conftest import ScriptedAdapter, sso_handler

    real = probe.FermiSSOSession

    def factory(*args, **kwargs):
        session = real(*args, **kwargs)
        session.mount("https://", ScriptedAdapter(sso_handler))
        return session

    monkeypatch.setattr(probe, "FermiSSOSession", factory)


# --------------------------------------------------------------------------
# cookie file handling in main()
# --------------------------------------------------------------------------


def test_cookie_file_option_parses():
    args = probe.build_parser().parse_args(
        ["-c", "/tmp/j.txt", "--cookie-format", "json"]
    )
    assert args.cookie_file == "/tmp/j.txt"
    assert args.cookie_format == "json"
    assert args.no_save_cookies is False


def test_cookie_file_resolves_from_environment_and_dotenv():
    environ = {probe.ENV_COOKIE_FILE: "/from/env"}
    assert probe.resolve(None, probe.ENV_COOKIE_FILE, environ, {}) == "/from/env"
    dotenv = {probe.ENV_COOKIE_FILE: "/from/dotenv"}
    assert probe.resolve(None, probe.ENV_COOKIE_FILE, {}, dotenv) == "/from/dotenv"
    assert probe.resolve("/cli", probe.ENV_COOKIE_FILE, environ, dotenv) == "/cli"


def test_main_login_writes_cookie_file_then_reuses_it(monkeypatch, tmp_path, capsys):
    """First run: password login populates the jar. Second run: no password."""
    _patch_session(monkeypatch)
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    jar = tmp_path / "cookies.txt"

    argv = ["--no-env-file", "-u", "testuser", "-p", "s3cret", "-c", str(jar), TARGET]
    assert probe.main(argv) == 0
    err = capsys.readouterr().err
    assert jar.exists()
    assert "login     : performed" in err
    assert f"saved to {jar}" in err

    argv = ["--no-env-file", "-n", "-c", str(jar), "-x", "DocDB Home", TARGET]
    assert probe.main(argv) == 0
    err = capsys.readouterr().err
    assert "with cookies only" in err
    assert "login     : not needed" in err
    assert "RESULT: login SUCCEEDED" in err


def test_main_cookie_file_from_env_needs_no_password(monkeypatch, tmp_path, capsys):
    _patch_session(monkeypatch)
    jar = tmp_path / "cookies.txt"
    probe.main(
        ["--no-env-file", "-u", "testuser", "-p", "s3cret", "-c", str(jar), TARGET]
    )
    capsys.readouterr()

    monkeypatch.setenv(probe.ENV_COOKIE_FILE, str(jar))
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    monkeypatch.delenv(probe.ENV_USER, raising=False)
    monkeypatch.delenv("USER", raising=False)
    assert probe.main(["--no-env-file", "-n", TARGET]) == 0
    assert "RESULT: login SUCCEEDED" in capsys.readouterr().err


def test_main_missing_cookie_file_still_requires_a_password(
    monkeypatch, tmp_path, capsys
):
    _patch_session(monkeypatch)
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    argv = [
        "--no-env-file",
        "-n",
        "-u",
        "alice",
        "-c",
        str(tmp_path / "new.txt"),
        TARGET,
    ]
    assert probe.main(argv) == 2
    assert "no password" in capsys.readouterr().err


def test_main_stale_cookies_without_password_fail_clearly(
    monkeypatch, tmp_path, capsys
):
    _patch_session(monkeypatch)
    jar = tmp_path / "cookies.txt"
    jar.write_text("mu2e-docdb.fnal.gov\tFALSE\t/\tTRUE\t0\tunrelated\tx\n")
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    assert probe.main(["--no-env-file", "-n", "-c", str(jar), TARGET]) == 1
    err = capsys.readouterr().err
    assert "RESULT: login FAILED" in err
    assert "no password was supplied" in err


def test_main_no_save_cookies_leaves_jar_untouched(monkeypatch, tmp_path, capsys):
    _patch_session(monkeypatch)
    jar = tmp_path / "cookies.txt"
    jar.write_text("# nothing useful\n")
    argv = [
        "--no-env-file",
        "-u",
        "u",
        "-p",
        "p",
        "-c",
        str(jar),
        "--no-save-cookies",
        TARGET,
    ]
    assert probe.main(argv) == 0
    assert jar.read_text() == "# nothing useful\n"
    assert "cookies not saved" in capsys.readouterr().err


def test_main_unreadable_cookie_file_is_a_usage_error(monkeypatch, tmp_path, capsys):
    _patch_session(monkeypatch)
    jar = tmp_path / "bad.json"
    jar.write_text("{not json")
    argv = ["--no-env-file", "-n", "-c", str(jar), TARGET]
    assert probe.main(argv) == 2
    assert "cannot load cookie file" in capsys.readouterr().err
