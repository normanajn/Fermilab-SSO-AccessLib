"""
Tests for cookie persistence in FermiSSOSession: file format round trips,
format detection, browser-export compatibility, and the end-to-end reuse
of a saved jar to skip the login sequence.
"""

import json
import os
import stat
import time

import pytest
import requests

import requests_fermi_sso as rfs
from requests_fermi_sso import FermiSSOSession

from conftest import FINAL_PAGE, SP, SP_COOKIE, TARGET, ScriptedAdapter, sso_handler


def _jar_session():
    """A session holding one of each interesting kind of cookie."""
    s = FermiSSOSession()
    s.cookies.set_cookie(
        rfs._make_cookie(
            SP_COOKIE,
            "abc",
            "mu2e-docdb.fnal.gov",
            "/",
            True,
            None,
            True,
            host_only=True,
        )
    )
    s.cookies.set_cookie(
        rfs._make_cookie(
            "PF",
            "xyz",
            "pingprod.fnal.gov",
            "/",
            True,
            int(time.time()) + 3600,
            False,
            True,
        )
    )
    s.cookies.set_cookie(
        rfs._make_cookie("wide", "1", ".fnal.gov", "/", False, None, False)
    )
    return s


def _by_name(session):
    return {c.name: c for c in session.cookies}


# --------------------------------------------------------------------------
# round trips
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt,ext", [("netscape", "txt"), ("lwp", "lwp"), ("json", "json")]
)
def test_round_trip_preserves_cookies(tmp_path, fmt, ext):
    path = str(tmp_path / f"jar.{ext}")
    written = _jar_session().save_cookies(path, fmt)
    assert written == 3

    loaded = FermiSSOSession(cookie_file=path)
    assert loaded.cookies_loaded == 3
    got = _by_name(loaded)

    # host-only session cookie, HttpOnly, secure
    assert got[SP_COOKIE].value == "abc"
    assert got[SP_COOKIE].domain == "mu2e-docdb.fnal.gov"
    assert got[SP_COOKIE].expires is None
    assert got[SP_COOKIE].secure
    assert rfs._is_httponly(got[SP_COOKIE])
    # persistent cookie keeps its expiry
    assert got["PF"].expires is not None and got["PF"].expires > time.time()
    assert not rfs._is_httponly(got["PF"])
    # domain cookie keeps its leading dot
    assert got["wide"].domain == ".fnal.gov"


@pytest.mark.parametrize("ext", ["txt", "lwp", "json"])
def test_loaded_cookies_are_sent_to_the_right_hosts(tmp_path, ext):
    path = str(tmp_path / f"jar.{ext}")
    _jar_session().save_cookies(path)
    s = FermiSSOSession(cookie_file=path)

    docdb = s.prepare_request(requests.Request("GET", SP + "/cgi-bin/x"))
    idp = s.prepare_request(requests.Request("GET", "https://pingprod.fnal.gov/idp/x"))
    other = s.prepare_request(requests.Request("GET", "https://example.org/"))

    assert SP_COOKIE + "=abc" in docdb.headers["Cookie"]
    assert "wide=1" in docdb.headers["Cookie"]
    assert "PF=" not in docdb.headers["Cookie"]
    assert "PF=xyz" in idp.headers["Cookie"]
    assert SP_COOKIE not in idp.headers["Cookie"]
    assert "Cookie" not in other.headers


def test_session_cookies_are_written_not_dropped(tmp_path):
    """
    The SSO flow issues session cookies (no expiry). The stdlib jar classes
    silently drop those on save, which would make persistence useless.
    """
    path = str(tmp_path / "cookies.txt")
    _jar_session().save_cookies(path)
    text = open(path).read()
    assert SP_COOKIE in text
    assert "\t0\t" + SP_COOKIE in text  # session cookie has expiry 0


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows ignores the POSIX mode: it reports 0666 whatever the ACL says",
)
def test_save_creates_file_mode_600(tmp_path):
    path = str(tmp_path / "cookies.txt")
    _jar_session().save_cookies(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]


def test_save_leaves_no_temp_file(tmp_path):
    # the mode assertion above cannot run on Windows; the atomic-rename part
    # of the same behaviour can
    path = str(tmp_path / "cookies.txt")
    _jar_session().save_cookies(path)
    assert not [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]


def test_expired_cookies_are_skipped_on_load_and_save(tmp_path):
    s = FermiSSOSession()
    s.cookies.set_cookie(
        rfs._make_cookie("old", "v", ".fnal.gov", "/", False, 1, False)
    )
    s.cookies.set_cookie(
        rfs._make_cookie("live", "v", ".fnal.gov", "/", False, None, False)
    )
    path = str(tmp_path / "jar.json")
    assert s.save_cookies(path) == 1

    stale = tmp_path / "stale.txt"
    stale.write_text(
        ".fnal.gov\tTRUE\t/\tFALSE\t1\told\tv\n.fnal.gov\tTRUE\t/\tFALSE\t0\tlive\tv\n"
    )
    t = FermiSSOSession()
    assert t.load_cookies(str(stale)) == 1
    assert list(_by_name(t)) == ["live"]


# --------------------------------------------------------------------------
# format detection and external formats
# --------------------------------------------------------------------------


def test_detect_format_by_extension():
    assert rfs.detect_cookie_format("a.json", None) == "json"
    assert rfs.detect_cookie_format("a.LWP", None) == "lwp"
    assert rfs.detect_cookie_format("cookies.txt", None) == "netscape"
    assert rfs.detect_cookie_format("noext", None) == "netscape"


def test_detect_format_by_content():
    assert rfs.detect_cookie_format("x", "#LWP-Cookies-2.0\n") == "lwp"
    assert rfs.detect_cookie_format("x", "[]") == "json"
    assert rfs.detect_cookie_format("x", '{"cookies": []}') == "json"
    assert rfs.detect_cookie_format("x", "# Netscape HTTP Cookie File\n") == "netscape"


def test_unknown_format_is_rejected(tmp_path):
    path = tmp_path / "jar"
    path.write_text("")
    with pytest.raises(ValueError, match="unknown cookie format"):
        FermiSSOSession().load_cookies(str(path), fmt="yaml")
    with pytest.raises(ValueError, match="unknown cookie format"):
        FermiSSOSession().save_cookies(str(path), fmt="yaml")


def test_browser_cookies_txt_with_httponly_prefix(tmp_path):
    """
    Chrome/Firefox exporters and curl write HttpOnly cookies with a
    '#HttpOnly_' domain prefix. Python < 3.10's MozillaCookieJar treats those
    lines as comments, which would drop exactly the cookies that matter.
    """
    path = tmp_path / "cookies.txt"
    path.write_text(
        "# Netscape HTTP Cookie File\n"
        "# http://curl.haxx.se/rfc/cookie_spec.html\n"
        "\n"
        f"#HttpOnly_mu2e-docdb.fnal.gov\tFALSE\t/\tTRUE\t0\t{SP_COOKIE}\tzzz\n"
        ".fnal.gov\tTRUE\t/\tFALSE\t2000000000\tsite\tv\n"
        "fnal.gov\tTRUE\t/\tFALSE\t2000000000\tnodot\tv\n"
    )
    s = FermiSSOSession(cookie_file=str(path))
    got = _by_name(s)
    assert s.cookies_loaded == 3
    assert got[SP_COOKIE].value == "zzz"
    assert got[SP_COOKIE].domain == "mu2e-docdb.fnal.gov"
    assert rfs._is_httponly(got[SP_COOKIE])
    # a TRUE include-subdomains flag implies a leading dot even if absent
    assert got["nodot"].domain == ".fnal.gov"


def test_browser_extension_json_export(tmp_path):
    """The Cookie-Editor / EditThisCookie shape: expirationDate, httpOnly, hostOnly."""
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps(
            [
                {
                    "domain": ".fnal.gov",
                    "expirationDate": time.time() + 100,
                    "hostOnly": False,
                    "httpOnly": True,
                    "name": "B",
                    "path": "/",
                    "secure": True,
                    "session": False,
                    "value": "v",
                },
                {
                    "domain": "mu2e-docdb.fnal.gov",
                    "hostOnly": True,
                    "httpOnly": True,
                    "name": SP_COOKIE,
                    "path": "/",
                    "secure": True,
                    "session": True,
                    "value": "q",
                },
            ]
        )
    )
    s = FermiSSOSession(cookie_file=str(path))
    got = _by_name(s)
    assert s.cookies_loaded == 2
    assert got["B"].domain == ".fnal.gov" and got["B"].expires
    assert got[SP_COOKIE].domain == "mu2e-docdb.fnal.gov"
    assert got[SP_COOKIE].expires is None


def test_json_output_shape(tmp_path):
    path = str(tmp_path / "jar.json")
    _jar_session().save_cookies(path)
    items = json.loads(open(path).read())
    assert {i["name"] for i in items} == {SP_COOKIE, "PF", "wide"}
    sp = next(i for i in items if i["name"] == SP_COOKIE)
    assert sp == {
        "name": SP_COOKIE,
        "value": "abc",
        "domain": "mu2e-docdb.fnal.gov",
        "path": "/",
        "secure": True,
        "httponly": True,
        "host_only": True,
        "expires": None,
    }


# --------------------------------------------------------------------------
# constructor behavior
# --------------------------------------------------------------------------


def test_missing_cookie_file_is_tolerated_by_constructor(tmp_path):
    s = FermiSSOSession(cookie_file=str(tmp_path / "absent.txt"))
    assert s.cookies_loaded == 0
    assert s.cookie_save is True


def test_missing_cookie_file_raises_from_explicit_load(tmp_path):
    with pytest.raises(FileNotFoundError):
        FermiSSOSession().load_cookies(str(tmp_path / "absent.txt"))


def test_cookie_file_expands_tilde(monkeypatch, tmp_path):
    # ntpath.expanduser reads USERPROFILE and ignores HOME; posixpath does the
    # opposite, so set whichever one this platform actually consults
    monkeypatch.setenv("USERPROFILE" if os.name == "nt" else "HOME", str(tmp_path))
    s = FermiSSOSession(cookie_file="~/jar.txt")
    # expanduser substitutes the "~" only, so the separator it was given
    # survives; normpath makes the comparison separator-agnostic
    assert os.path.normpath(s.cookie_file) == os.path.normpath(
        str(tmp_path / "jar.txt")
    )


def test_cookie_kwargs_are_not_passed_to_requests_session(tmp_path):
    # requests.Session.__init__ takes no arguments; leaking ours would raise
    FermiSSOSession(
        cookie_file=str(tmp_path / "x"), cookie_format="json", cookie_save=False
    )


# --------------------------------------------------------------------------
# end-to-end: log in once, reuse the jar without a password
# --------------------------------------------------------------------------


def test_login_saves_cookies_and_second_session_skips_login(tmp_path):
    path = str(tmp_path / "cookies.txt")

    first_adapter = ScriptedAdapter(sso_handler)
    first = FermiSSOSession(userpass="testuser:s3cret", cookie_file=path)
    first.mount("https://", first_adapter)
    resp = first.get(TARGET)
    assert resp.text == FINAL_PAGE
    assert first_adapter.methods == ["GET", "GET", "POST", "POST"]
    assert os.path.exists(path), "jar not written after the login completed"
    assert SP_COOKIE in open(path).read()

    # a brand-new process: no password, just the jar
    second_adapter = ScriptedAdapter(sso_handler)
    second = FermiSSOSession(cookie_file=path)
    second.mount("https://", second_adapter)
    resp = second.get(TARGET)
    assert resp.text == FINAL_PAGE
    assert second_adapter.methods == ["GET"], "cookie reuse should need one request"
    assert SP_COOKIE + "=sess-1" in second_adapter.calls[0].headers["Cookie"]


def test_stale_cookies_fall_through_to_password_login_and_refresh_file(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(f"mu2e-docdb.fnal.gov\tFALSE\t/\tTRUE\t0\t{SP_COOKIE}\tstale\n")

    def handler(request):
        # the SP rejects the stale cookie by starting SSO over
        if request.url.startswith(TARGET) and "stale" in request.headers.get(
            "Cookie", ""
        ):
            from conftest import CHOOSE_PAGE

            return CHOOSE_PAGE
        return sso_handler(request)

    adapter = ScriptedAdapter(handler)
    s = FermiSSOSession(userpass="testuser:s3cret", cookie_file=str(path))
    s.mount("https://", adapter)
    resp = s.get(TARGET)
    assert resp.text == FINAL_PAGE
    assert adapter.methods == ["GET", "GET", "POST", "POST"]
    # the jar now holds the fresh cookie, not the stale one
    text = path.read_text()
    assert "sess-1" in text and "stale" not in text


def test_cookie_save_false_leaves_the_file_alone(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text("# empty\n")
    before = path.read_text()
    s = FermiSSOSession(
        userpass="testuser:s3cret", cookie_file=str(path), cookie_save=False
    )
    s.mount("https://", ScriptedAdapter(sso_handler))
    assert s.get(TARGET).text == FINAL_PAGE
    assert path.read_text() == before


def test_no_login_means_no_save(tmp_path):
    """Reusing a browser export must not rewrite it when no login happened."""
    path = str(tmp_path / "cookies.txt")
    first = FermiSSOSession(userpass="testuser:s3cret", cookie_file=path)
    first.mount("https://", ScriptedAdapter(sso_handler))
    first.get(TARGET)
    mtime = os.stat(path).st_mtime_ns
    os.utime(path, ns=(mtime - 10**9, mtime - 10**9))
    mtime = os.stat(path).st_mtime_ns

    second = FermiSSOSession(cookie_file=path)
    second.mount("https://", ScriptedAdapter(sso_handler))
    second.get(TARGET)
    assert os.stat(path).st_mtime_ns == mtime


# --------------------------------------------------------------------------
# saving when the jar changes without a login sequence
# --------------------------------------------------------------------------


def test_cookies_gained_without_a_login_are_saved(tmp_path):
    """
    A second site behind the same IdP signs us in through a bare redirect
    chain when the IdP session cookie is still valid; no choose/login pages
    appear, yet the new application cookie must land in the jar. Seen live
    with mu2e-shifts -> mu2e-talks, 2026-09-02.
    """
    path = str(tmp_path / "cookies.txt")

    def handler(request):
        return FINAL_PAGE, ["talks_session=t-1; Path=/; Secure; HttpOnly"]

    s = FermiSSOSession(cookie_file=path)
    s.mount("https://", ScriptedAdapter(handler))
    s.get("https://mu2e-talks.fnal.gov/")
    assert s.login_count == 0
    assert os.path.exists(path)
    assert "talks_session" in open(path).read()


def test_unchanged_jar_is_not_rewritten(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(f"mu2e-docdb.fnal.gov\tFALSE\t/\tTRUE\t0\t{SP_COOKIE}\tsess-1\n")
    s = FermiSSOSession(cookie_file=str(path))
    s.mount("https://", ScriptedAdapter(sso_handler))
    assert s.get(TARGET).text == FINAL_PAGE
    # the handler serves the page without a Set-Cookie when the cookie is
    # presented, so the jar is unchanged and the file keeps its exact bytes
    assert (
        path.read_text()
        == f"mu2e-docdb.fnal.gov\tFALSE\t/\tTRUE\t0\t{SP_COOKIE}\tsess-1\n"
    )
