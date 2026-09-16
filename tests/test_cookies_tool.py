"""
Tests for fermi_sso_cookies: jar reading in each format (expired cookies
kept), record flattening, filters, the three output views, value masking,
and the command line's exit statuses.
"""

import json
import os
import stat
import time

import pytest

import fermi_sso_cookies as tool
import requests_fermi_sso as rfs

NOW = 1_800_000_000  # fixed "now" so remaining-time arithmetic is exact


def _cookies():
    """One of each interesting kind, mirroring test_cookies._jar_session."""
    return [
        rfs._make_cookie(
            "mellon-cookie", "abcdefgh1234", "mu2e-docdb.fnal.gov", "/", True, None, True, host_only=True
        ),
        rfs._make_cookie("PF", "xyz789", "pingprod.fnal.gov", "/", True, NOW + 600, False, host_only=True),
        rfs._make_cookie("wide", "1", ".fnal.gov", "/", False, NOW + 3 * 86400 + 4 * 3600, False),
        rfs._make_cookie("stale", "zzz", "old.fnal.gov", "/app", True, NOW - 7200, False, host_only=True),
    ]


def _records():
    return [tool.cookie_record(c, NOW) for c in _cookies()]


def _write(tmp_path, name, text, mode=0o600):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return str(path)


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, formatter, fmt",
    [
        ("jar.cookies", rfs.format_netscape_cookies, "netscape"),
        ("jar.lwp", rfs.format_lwp_cookies, "lwp"),
        ("jar.json", rfs.format_json_cookies, "json"),
    ],
)
def test_read_jar_detects_format_and_keeps_expired(tmp_path, name, formatter, fmt):
    path = _write(tmp_path, name, formatter(_cookies()))
    got_fmt, cookies = tool.read_jar(path)
    assert got_fmt == fmt
    # load_cookies would drop "stale"; the listing tool must not
    assert sorted(c.name for c in cookies) == ["PF", "mellon-cookie", "stale", "wide"]


def test_read_jar_explicit_format_overrides_detection(tmp_path):
    path = _write(tmp_path, "odd.txt", rfs.format_json_cookies(_cookies()))
    fmt, cookies = tool.read_jar(path, "json")
    assert fmt == "json" and len(cookies) == 4


def test_read_jar_rejects_unknown_format(tmp_path):
    path = _write(tmp_path, "jar.cookies", "")
    with pytest.raises(ValueError):
        tool.read_jar(path, "yaml")


# --------------------------------------------------------------------------
# records
# --------------------------------------------------------------------------


def test_cookie_record_fields():
    by_name = {r["name"]: r for r in _records()}
    m = by_name["mellon-cookie"]
    assert m["domain"] == "mu2e-docdb.fnal.gov" and m["host_only"]
    assert m["secure"] and m["httponly"]
    assert m["expires"] is None and m["remaining"] is None and m["state"] == "session"

    pf = by_name["PF"]
    assert pf["expires"] == NOW + 600 and pf["remaining"] == 600 and pf["state"] == "soon"
    assert not pf["httponly"]

    wide = by_name["wide"]
    assert wide["domain"] == ".fnal.gov" and not wide["host_only"]
    assert wide["state"] == "live" and not wide["secure"]

    stale = by_name["stale"]
    assert stale["state"] == "expired" and stale["remaining"] == -7200
    assert stale["path"] == "/app"


def test_summarize_counts_states():
    assert tool.summarize(_records()) == {
        "total": 4,
        "live": 1,
        "soon": 1,
        "session": 1,
        "expired": 1,
    }


# --------------------------------------------------------------------------
# filters
# --------------------------------------------------------------------------


def test_domain_matches_exact_subdomain_and_glob():
    assert tool.domain_matches("pingprod.fnal.gov", "fnal.gov")
    assert tool.domain_matches(".fnal.gov", "fnal.gov")
    assert tool.domain_matches("pingprod.fnal.gov", ".fnal.gov")
    assert tool.domain_matches("PingProd.FNAL.gov", "pingprod.fnal.gov")
    assert not tool.domain_matches("notfnal.gov", "fnal.gov")
    assert not tool.domain_matches("fnal.gov.evil.com", "fnal.gov")
    assert tool.domain_matches("mu2e-docdb.fnal.gov", "mu2e-*.fnal.gov")
    assert not tool.domain_matches("pingprod.fnal.gov", "mu2e-*.fnal.gov")


def test_select_by_domain_name_and_state():
    recs = _records()
    assert [r["name"] for r in tool.select(recs, domains=["pingprod.fnal.gov"])] == ["PF"]
    assert sorted(r["name"] for r in tool.select(recs, domains=["fnal.gov"])) == [
        "PF",
        "mellon-cookie",
        "stale",
        "wide",
    ]
    assert [r["name"] for r in tool.select(recs, names=["mellon*"])] == ["mellon-cookie"]
    assert [r["name"] for r in tool.select(recs, states=["expired"])] == ["stale"]
    live = tool.select(recs, states=["live", "soon", "session"])
    assert sorted(r["name"] for r in live) == ["PF", "mellon-cookie", "wide"]
    # groups AND together, alternatives within a group OR together
    assert [r["name"] for r in tool.select(recs, domains=["old.fnal.gov", "pingprod.fnal.gov"], states=["soon"])] == [
        "PF"
    ]


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------


def test_mask_value():
    assert tool.mask_value("abcdefgh1234") == "abcd… (12 chars)"
    assert tool.mask_value("abc") == "*** (3 chars)"
    assert tool.mask_value("") == "(empty)"
    assert tool.mask_value("abcdefgh1234", show=True) == "abcdefgh1234"


def test_format_duration():
    assert tool.format_duration(3 * 86400 + 4 * 3600 + 5) == "3d 4h"
    assert tool.format_duration(2 * 3600 + 15 * 60) == "2h 15m"
    assert tool.format_duration(9 * 60 + 59) == "9m 59s"
    assert tool.format_duration(45) == "45s"
    assert tool.format_duration(-7200) == "-2h 0m"


def test_format_table_masks_values_and_flags_expiry():
    text = tool.format_table(_records())
    assert text.startswith("DOMAIN")
    assert "abcd… (12 chars)" in text and "abcdefgh1234" not in text
    assert "expired 2h 0m ago" in text
    assert "in 9m 59s" in text or "in 10m 0s" in text
    assert "session" in text
    assert "secure,httponly,host-only" in text
    assert "subdomains" in text


def test_format_table_empty():
    assert tool.format_table([]) == "(no cookies)\n"


def test_format_long_shows_values_when_asked():
    text = tool.format_long(_records(), show_values=True, utc=True)
    assert "value    : abcdefgh1234" in text
    assert "expires  : session" in text
    assert "UTC" in text
    assert "(this host only)" in text and "(and subdomains)" in text


def test_format_json_structure():
    out = json.loads(tool.format_json(_records(), file="/x", format="netscape"))
    assert out["file"] == "/x" and out["format"] == "netscape"
    names = {c["name"]: c for c in out["cookies"]}
    assert names["mellon-cookie"]["value_masked"] is True
    assert names["mellon-cookie"]["value"].endswith("(12 chars)")
    assert names["stale"]["remaining"] == -7200
    assert names["PF"]["expires"] == NOW + 600
    shown = json.loads(tool.format_json(_records(), show_values=True))
    assert {c["name"]: c for c in shown["cookies"]}["PF"]["value"] == "xyz789"
    assert "value_masked" not in shown["cookies"][0]


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def _live_jar(tmp_path, mode=0o600):
    """Same shape as _cookies() but with expiry relative to the real clock."""
    now = int(time.time())
    cookies = [
        rfs._make_cookie("mellon-cookie", "abcdefgh1234", "mu2e-docdb.fnal.gov", "/", True, None, True, host_only=True),
        rfs._make_cookie("PF", "xyz789", "pingprod.fnal.gov", "/", True, now + 3600, False, host_only=True),
        rfs._make_cookie("stale", "zzz", "old.fnal.gov", "/", True, now - 7200, False, host_only=True),
    ]
    return _write(tmp_path, "jar.cookies", rfs.format_netscape_cookies(cookies), mode)


def test_main_table_default(tmp_path, capsys):
    path = _live_jar(tmp_path)
    rc = tool.main([path, "--no-env-file"])
    out, err = capsys.readouterr()
    assert rc == 0
    assert f"file    : {path}" in out
    assert "format  : netscape" in out
    assert "cookies : 3 total, 1 live, 1 session, 1 expired" in out
    assert "mellon-cookie" in out and "xyz789" not in out
    assert err == ""


def test_main_warns_on_loose_permissions(tmp_path, capsys):
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    path = _live_jar(tmp_path, mode=0o644)
    assert tool.main([path, "--no-env-file"]) == 0
    _, err = capsys.readouterr()
    assert "mode 644" in err and "chmod 600" in err
    # --quiet suppresses it along with the header
    tool.main([path, "--no-env-file", "-q"])
    out, err = capsys.readouterr()
    assert err == "" and not out.startswith("file")


def test_main_filters_and_exit_status(tmp_path, capsys):
    path = _live_jar(tmp_path)
    assert tool.main([path, "--no-env-file", "-q", "--expired"]) == 0
    out, _ = capsys.readouterr()
    assert "stale" in out and "PF" not in out
    assert tool.main([path, "--no-env-file", "-q", "--live"]) == 0
    out, _ = capsys.readouterr()
    assert "stale" not in out and "PF" in out and "mellon-cookie" in out
    # nothing matched: status 1 and the empty marker
    assert tool.main([path, "--no-env-file", "-q", "-D", "nowhere.example"]) == 1
    out, _ = capsys.readouterr()
    assert out.strip() == "(no cookies)"


def test_main_json_and_show_values(tmp_path, capsys):
    path = _live_jar(tmp_path)
    assert tool.main([path, "--no-env-file", "-j", "-s", "-N", "PF"]) == 0
    out, _ = capsys.readouterr()
    data = json.loads(out)
    assert data["format"] == "netscape" and data["shown"] == 1
    assert data["counts"]["total"] == 3
    assert data["cookies"][0]["value"] == "xyz789"


def test_main_long_view(tmp_path, capsys):
    path = _live_jar(tmp_path)
    assert tool.main([path, "--no-env-file", "-l", "-q", "-N", "mellon-cookie"]) == 0
    out, _ = capsys.readouterr()
    assert "domain   : mu2e-docdb.fnal.gov  (this host only)" in out
    assert "httponly : yes" in out
    assert "expires  : session" in out


def test_main_path_from_environment_and_option_precedence(tmp_path, capsys, monkeypatch):
    path = _live_jar(tmp_path)
    monkeypatch.setenv(tool.ENV_COOKIE_FILE, path)
    assert tool.main(["--no-env-file", "-q"]) == 0
    other = _write(tmp_path, "other.cookies", rfs.format_netscape_cookies([]))
    # the option beats the environment
    assert tool.main(["--no-env-file", "-q", "-c", other]) == 1
    out, _ = capsys.readouterr()
    assert "(no cookies)" in out


def test_main_path_from_env_file(tmp_path, capsys):
    path = _live_jar(tmp_path)
    env = _write(tmp_path, "probe.env", f"FERMI_SSO_COOKIE_FILE={path}\n")
    assert tool.main(["-e", env, "-q"]) == 0
    out, _ = capsys.readouterr()
    assert "mellon-cookie" in out


def test_main_usage_errors(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(tool.ENV_COOKIE_FILE, raising=False)
    assert tool.main(["--no-env-file"]) == 2
    _, err = capsys.readouterr()
    assert "no cookie file" in err

    assert tool.main(["--no-env-file", str(tmp_path / "absent.cookies")]) == 2
    _, err = capsys.readouterr()
    assert "not found" in err

    assert tool.main(["-e", str(tmp_path / "no.env")]) == 2
    _, err = capsys.readouterr()
    assert "env file not found" in err

    monkeypatch.setenv(tool.ENV_COOKIE_FORMAT, "yaml")
    assert tool.main(["--no-env-file", _live_jar(tmp_path)]) == 2
    _, err = capsys.readouterr()
    assert "FERMI_SSO_COOKIE_FORMAT" in err


def test_main_unparseable_jar(tmp_path, capsys):
    path = _write(tmp_path, "bad.json", "{not json")
    assert tool.main(["--no-env-file", path]) == 2
    _, err = capsys.readouterr()
    assert "cannot read cookie file" in err
