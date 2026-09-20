"""
Tests for auth_method="yubikey": adapter choice, the certificate hop that
replaces following the redirect to the mutual-TLS listener, cookie
absorption from the hop, the helper's HTTP plumbing, and probe wiring.
"""

import gc
import os
import subprocess

import pytest
import requests

import fermi_sso_probe as probe
import fermi_sso_yubikey as yk
from requests_fermi_sso import FermiSSOSession, HopResponse

from conftest import (
    CHOOSE_PAGE,
    FINAL_PAGE,
    MTLS_RESUME,
    OIDC_CALLBACK,
    OIDC_FINAL_PAGE,
    OIDC_TARGET,
    POSTBACK_PAGE,
    SP,
    FakeCertHop,
    ScriptedAdapter,
    make_response,
    yubikey_handler,
)

# --------------------------------------------------------------------------
# construction and adapter choice
# --------------------------------------------------------------------------


def test_yubikey_requires_a_cert_hop():
    with pytest.raises(ValueError, match="cert_hop"):
        FermiSSOSession(auth_method="yubikey")


def test_yubikey_prefers_the_production_adapter():
    s = FermiSSOSession(auth_method="yubikey", cert_hop=FakeCertHop())
    adapter = ScriptedAdapter(yubikey_handler)
    s.mount("https://", adapter)
    s.get(OIDC_TARGET)
    assert any("pfidpadapterid=ad..FNALYubikey" in u for u in adapter.urls)
    assert not any("YubikeyTest" in u for u in adapter.urls)


def test_yubikey_falls_back_to_password_adapter_when_not_offered():
    s = FermiSSOSession(auth_method="yubikey", cert_hop=FakeCertHop())
    req = requests.Request("GET", "https://pingprod.fnal.gov/idp/x").prepare()
    assert s.choose_adapter(make_response(req, CHOOSE_PAGE)) == "ad..FormBased"


# --------------------------------------------------------------------------
# the hop
# --------------------------------------------------------------------------


def test_redirect_to_mtls_port_goes_through_cert_hop(tmp_path):
    hop = FakeCertHop()
    adapter = ScriptedAdapter(yubikey_handler)
    jar = tmp_path / "jar.txt"
    s = FermiSSOSession(auth_method="yubikey", cert_hop=hop, cookie_file=str(jar))
    s.mount("https://", adapter)

    resp = s.get(OIDC_TARGET)

    assert resp.text == OIDC_FINAL_PAGE
    assert len(hop.calls) == 1
    url, headers = hop.calls[0]
    assert url == MTLS_RESUME
    assert "User-Agent" in headers
    assert adapter.urls[-1].startswith(OIDC_CALLBACK.split("?")[0])
    assert s.cert_hop_count == 1
    assert s.login_count == 1
    assert s.logging_in_already is False
    names = {c.name for c in s.cookies}
    assert {"PF", "session"} <= names
    assert jar.exists()


def test_hop_cookie_is_scoped_to_the_idp_host():
    hop = FakeCertHop()
    s = FermiSSOSession(auth_method="yubikey", cert_hop=hop)
    s.mount("https://", ScriptedAdapter(yubikey_handler))
    s.get(OIDC_TARGET)
    pf = next(c for c in s.cookies if c.name == "PF")
    assert pf.domain == "pingprod.fnal.gov"
    idp = s.prepare_request(requests.Request("GET", "https://pingprod.fnal.gov/as/x"))
    assert "PF=after-cert" in idp.headers["Cookie"]


def test_hop_response_is_in_the_history():
    s = FermiSSOSession(auth_method="yubikey", cert_hop=FakeCertHop())
    s.mount("https://", ScriptedAdapter(yubikey_handler))
    resp = s.get(OIDC_TARGET)
    assert any(h.url == MTLS_RESUME and h.status_code == 302 for h in resp.history)


def test_hop_denial_is_reported_not_hidden():
    denied = OIDC_CALLBACK.split("?")[0] + "?error=access_denied&state=xyz"
    hop = FakeCertHop(location=denied, set_cookies=())

    def handler(request):
        if request.url.startswith(denied.split("?")[0]):
            return "<html><title>Login — Mu2e Shift Scheduler</title>SSO login failed</html>"
        return yubikey_handler(request)

    s = FermiSSOSession(auth_method="yubikey", cert_hop=hop)
    s.mount("https://", ScriptedAdapter(handler))
    resp = s.get(OIDC_TARGET)
    assert s.login_count == 0
    ok, reasons = probe.classify(s, resp, "pingprod.fnal.gov")
    assert not ok
    assert any("access_denied" in r for r in reasons)


def test_non_mtls_redirects_are_still_followed_normally():
    def handler(request):
        if "pfidpadapterid=ad..FNALYubikey" in request.url:
            return "", [], 302, {"Location": OIDC_CALLBACK}
        return yubikey_handler(request)

    hop = FakeCertHop()
    s = FermiSSOSession(auth_method="yubikey", cert_hop=hop)
    s.mount("https://", ScriptedAdapter(handler))
    assert s.get(OIDC_TARGET).text == OIDC_FINAL_PAGE
    assert hop.calls == []


def test_hop_returning_a_page_is_handed_on_to_the_flow():
    hop = FakeCertHop(
        status=200, location=None, body=POSTBACK_PAGE.encode(), set_cookies=()
    )

    def handler(request):
        if request.url.startswith(SP + "/mellon/postResponse"):
            return FINAL_PAGE
        return yubikey_handler(request)

    s = FermiSSOSession(auth_method="yubikey", cert_hop=hop)
    s.mount("https://", ScriptedAdapter(handler))
    assert s.get(OIDC_TARGET).text == FINAL_PAGE
    assert s.login_count == 1


# --------------------------------------------------------------------------
# helper plumbing (no token, no openssl)
# --------------------------------------------------------------------------


def test_build_request_carries_cookies_and_closes():
    s = FermiSSOSession()
    s.cookies.set("PF", "tok", domain="pingprod.fnal.gov", path="/")
    prepared = s.prepare_request(requests.Request("GET", MTLS_RESUME))
    raw = yk.build_request(prepared, requests.utils.urlparse(MTLS_RESUME))
    text = raw.decode()
    assert text.startswith("GET /as/Krb1/resume/as/authorization.ping HTTP/1.1\r\n")
    assert "Host: pingprod.fnal.gov:9032\r\n" in text
    assert "Cookie: PF=tok" in text
    assert "Connection: close\r\n" in text
    assert "Accept-Encoding" not in text
    assert text.endswith("\r\n\r\n")


def test_parse_http_response_redirect_with_two_cookies():
    raw = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: https://mu2e-shifts.fnal.gov/oidc/callback?code=1&state=2\r\n"
        b"Set-Cookie: PF=abc; Path=/; Secure; HttpOnly\r\n"
        b"Set-Cookie: pfidpaid=def; Path=/; Secure\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n\r\n"
    )
    hop = yk.parse_http_response(raw)
    assert hop.status == 302
    assert hop.headers["location"].startswith(
        "https://mu2e-shifts.fnal.gov/oidc/callback"
    )
    assert hop.set_cookies == [
        "PF=abc; Path=/; Secure; HttpOnly",
        "pfidpaid=def; Path=/; Secure",
    ]
    assert hop.body == b""


def test_parse_http_response_chunked_body_and_noise_before_status():
    raw = (
        b"depth=0 CN=x\nverify return:1\n"
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\n<html\r\n8\r\n>hello</\r\n0\r\n\r\n"
    )
    hop = yk.parse_http_response(raw)
    assert hop.status == 200
    assert hop.body == b"<html>hello</"


def test_parse_http_response_content_length_truncates_trailing_noise():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyEXTRA"
    assert yk.parse_http_response(raw).body == b"body"


def test_parse_without_status_line_raises():
    with pytest.raises(ValueError):
        yk.parse_http_response(b"nothing here")


def test_command_and_environment(tmp_path):
    pem = tmp_path / "c.pem"
    pem.write_text("PEM")
    pin = tmp_path / "pin"
    pin.write_text("123456")
    hop = yk.YubiKeyCertHop(
        openssl_bin="/x/openssl",
        engines_dir="/x/engines-3",
        module_path="/x/libykcs11.dylib",
        cert_pem=str(pem),
        pin_source=str(pin),
        environ={},
    )
    cmd = hop.command("pingprod.fnal.gov", 9032)
    assert cmd[:3] == ["/x/openssl", "s_client", "-connect"]
    assert "pingprod.fnal.gov:9032" in cmd
    assert "-engine" in cmd and "pkcs11" in cmd
    key = cmd[cmd.index("-key") + 1]
    assert key.startswith("pkcs11:id=%01;type=private")
    assert f"pin-source=file:{pin}" in key
    assert cmd[cmd.index("-cert") + 1] == str(pem)
    env = hop.environment()
    assert env["OPENSSL_ENGINES"] == "/x/engines-3"
    assert env["PKCS11_MODULE_PATH"] == "/x/libykcs11.dylib"


def test_settings_come_from_environment_when_not_given():
    env = {
        yk.ENV_OPENSSL: "/e/openssl",
        yk.ENV_MODULE: "/e/mod.so",
        yk.ENV_KEY: "pkcs11:token=T;id=%01;type=private",
        yk.ENV_PIN_SOURCE: "/e/pin",
    }
    hop = yk.YubiKeyCertHop(
        environ=env, engines_dir="/e/eng", pkcs11_tool="/e/pkcs11-tool"
    )
    assert (hop.openssl_bin, hop.module_path, hop.key_uri, hop.pin_source) == (
        "/e/openssl",
        "/e/mod.so",
        "pkcs11:token=T;id=%01;type=private",
        "/e/pin",
    )


def test_call_uses_runner_and_parses(tmp_path):
    pem = tmp_path / "c.pem"
    pem.write_text("PEM")
    seen = {}

    def runner(cmd, request, env, timeout):
        seen["cmd"], seen["request"], seen["env"] = cmd, request, env
        return (
            b"HTTP/1.1 302 Found\r\nLocation: https://app/cb?code=1\r\nSet-Cookie: PF=z; Path=/\r\n\r\n",
            "",
            0,
        )

    hop = yk.YubiKeyCertHop(
        openssl_bin="/x/openssl",
        engines_dir="/x/e",
        module_path="/x/m",
        cert_pem=str(pem),
        pin_source=str(pem),
        environ={},
        runner=runner,
    )
    prepared = requests.Request(
        "GET", MTLS_RESUME, headers={"User-Agent": "t"}
    ).prepare()
    result = hop(MTLS_RESUME, prepared)
    assert isinstance(result, HopResponse)
    assert result.status == 302 and result.set_cookies == ["PF=z; Path=/"]
    assert b"GET /as/Krb1/resume/as/authorization.ping HTTP/1.1" in seen["request"]
    assert seen["env"]["PKCS11_MODULE_PATH"] == "/x/m"


def test_call_with_empty_output_raises_with_openssl_stderr(tmp_path):
    pem = tmp_path / "c.pem"
    pem.write_text("PEM")
    hop = yk.YubiKeyCertHop(
        openssl_bin="/x/openssl",
        engines_dir="/x/e",
        module_path="/x/m",
        cert_pem=str(pem),
        pin_source=str(pem),
        environ={},
        runner=lambda *a: (b"", "engine: PIN incorrect", 1),
    )
    prepared = requests.Request("GET", MTLS_RESUME).prepare()
    with pytest.raises(RuntimeError, match="PIN incorrect"):
        hop(MTLS_RESUME, prepared)


def test_check_reports_missing_pieces():
    hop = yk.YubiKeyCertHop(
        openssl_bin="/nope/openssl",
        engines_dir="/nope",
        module_path="/nope/m.so",
        pkcs11_tool="/nope/tool",
        environ={},
    )
    results = {what: ok for what, ok, _ in hop.check()}
    assert results["openssl"] is False
    assert results["pkcs11 engine"] is False
    assert results["PKCS#11 module"] is False


# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------


def test_probe_yubikey_option_parses():
    args = probe.build_parser().parse_args(["-a", "yubikey", "--pin-source", "/p"])
    assert args.auth == "yubikey" and args.pin_source == "/p"


def test_probe_yubikey_run_with_fake_hop(monkeypatch, capsys):
    import fermi_sso_yubikey

    class ReadyHop(FakeCertHop):
        def __init__(self, **kwargs):
            super().__init__()

        def check(self):
            return [("openssl", True, "/x")]

    monkeypatch.setattr(fermi_sso_yubikey, "YubiKeyCertHop", ReadyHop)
    real = probe.FermiSSOSession

    def factory(*args, **kwargs):
        session = real(*args, **kwargs)
        session.mount("https://", ScriptedAdapter(yubikey_handler))
        return session

    monkeypatch.setattr(probe, "FermiSSOSession", factory)
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    code = probe.main(
        ["--no-env-file", "-n", "-a", "yubikey", "-x", "Shifts", OIDC_TARGET]
    )
    err = capsys.readouterr().err
    assert code == 0, err
    assert "with the YubiKey certificate" in err
    assert "login     : performed" in err


def test_probe_yubikey_stops_when_prerequisites_are_missing(monkeypatch, capsys):
    import fermi_sso_yubikey

    class NotReady(FakeCertHop):
        def __init__(self, **kwargs):
            super().__init__()

        def check(self):
            return [("openssl", False, "not found")]

    monkeypatch.setattr(fermi_sso_yubikey, "YubiKeyCertHop", NotReady)
    assert probe.main(["--no-env-file", "-n", "-a", "yubikey", OIDC_TARGET]) == 2
    assert "prerequisite missing: openssl" in capsys.readouterr().err


# --------------------------------------------------------------------------
# temp directory lifetime
# --------------------------------------------------------------------------


def _hop_with_exported_cert(tmp_path):
    """
    A hop whose certificate export is faked, so ensure_cert_pem() creates
    its temp directory without a token being present.
    """
    hop = yk.YubiKeyCertHop(
        openssl_bin=str(tmp_path / "openssl"),
        pkcs11_tool=str(tmp_path / "pkcs11-tool"),
        module_path=str(tmp_path / "module.so"),
    )

    def fake_run(cmd, **kwargs):
        # write whatever output file the command asked for
        if "-o" in cmd:
            open(cmd[cmd.index("-o") + 1], "wb").close()
        if "-out" in cmd:
            open(cmd[cmd.index("-out") + 1], "wb").close()
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return hop, fake_run


def test_close_removes_the_exported_certificate(tmp_path, monkeypatch):

    hop, fake_run = _hop_with_exported_cert(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)

    pem = hop.ensure_cert_pem()
    tmpdir = os.path.dirname(pem)
    assert os.path.isdir(tmpdir)

    hop.close()
    assert not os.path.exists(tmpdir)


def test_close_is_idempotent(tmp_path, monkeypatch):

    hop, fake_run = _hop_with_exported_cert(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    hop.ensure_cert_pem()
    hop.close()
    hop.close()  # must not raise


def test_the_hop_works_as_a_context_manager(tmp_path, monkeypatch):

    hop, fake_run = _hop_with_exported_cert(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)

    with hop as entered:
        assert entered is hop
        tmpdir = os.path.dirname(hop.ensure_cert_pem())
        assert os.path.isdir(tmpdir)

    assert not os.path.exists(tmpdir)


def test_the_directory_goes_away_when_the_hop_is_collected(tmp_path, monkeypatch):
    """The case that leaked: the hop is passed to FermiSSOSession as a bare
    callable and the caller never keeps a reference to close."""
    hop, fake_run = _hop_with_exported_cert(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    tmpdir = os.path.dirname(hop.ensure_cert_pem())
    assert os.path.isdir(tmpdir)

    del hop
    gc.collect()

    assert not os.path.exists(tmpdir)


def test_a_caller_supplied_certificate_is_not_removed(tmp_path):
    """cert_pem given by the caller is theirs; close() must not delete it."""
    pem = tmp_path / "mine.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\n")
    hop = yk.YubiKeyCertHop(cert_pem=str(pem))

    assert hop.ensure_cert_pem() == str(pem)
    hop.close()
    assert pem.exists()
