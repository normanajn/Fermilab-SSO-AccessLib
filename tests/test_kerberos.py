"""
Tests for auth_method="kerberos": adapter selection on both IdP connections,
the SPNEGO handler hookup, login accounting, and the probe's reporting of
an unanswered Negotiate challenge.
"""

import pytest
import requests

import fermi_sso_probe as probe
from requests_fermi_sso import KERBEROS_ADAPTER_RE, PASSWORD_ADAPTER, FermiSSOSession

from conftest import (
    CHOOSE_PAGE,
    FINAL_PAGE,
    OIDC_CHOOSE_PAGE,
    TARGET,
    FakeSPNEGOAuth,
    ScriptedAdapter,
    kerberos_handler,
    make_response,
)


def _fake(text, url="https://pingprod.fnal.gov/idp/SSO.saml2"):
    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


# --------------------------------------------------------------------------
# construction
# --------------------------------------------------------------------------


def test_default_auth_method_is_password_and_sets_no_handler():
    s = FermiSSOSession()
    assert s.auth_method == "password"
    assert s.auth is None


def test_unknown_auth_method_is_rejected():
    with pytest.raises(ValueError, match="auth_method"):
        FermiSSOSession(auth_method="passkey")


def test_kerberos_attaches_the_given_spnego_handler():
    fake = FakeSPNEGOAuth()
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=fake)
    assert s.auth is fake


def test_kerberos_default_handler_is_requests_gssapi_or_a_clear_error():
    try:
        import requests_gssapi  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError, match="requests-gssapi"):
            FermiSSOSession(auth_method="kerberos")
    else:
        s = FermiSSOSession(auth_method="kerberos")
        assert type(s.auth).__name__ == "HTTPSPNEGOAuth"


# --------------------------------------------------------------------------
# adapter selection
# --------------------------------------------------------------------------


def test_password_session_keeps_the_formbased_adapter():
    s = FermiSSOSession()
    assert s.choose_adapter(_fake(CHOOSE_PAGE)) == PASSWORD_ADAPTER
    assert "pfidpadapterid=ad..FormBased" in s.extract_chose_url(_fake(CHOOSE_PAGE))


def test_kerberos_picks_krborform_on_the_saml_connection():
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=FakeSPNEGOAuth())
    assert s.choose_adapter(_fake(CHOOSE_PAGE)) == "ad..KrbOrForm"
    assert "pfidpadapterid=ad..KrbOrForm" in s.extract_chose_url(_fake(CHOOSE_PAGE))


def test_kerberos_picks_kerbform_on_the_oidc_connection():
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=FakeSPNEGOAuth())
    assert s.choose_adapter(_fake(OIDC_CHOOSE_PAGE)) == "ad..kerbForm"


def test_kerberos_avoids_the_windows_only_adapter():
    """ad..KrbOrFormForWin is listed before ad..KrbOrForm and must be skipped."""
    assert CHOOSE_PAGE.index("KrbOrFormForWin") < CHOOSE_PAGE.index('"ad..KrbOrForm"')
    assert not KERBEROS_ADAPTER_RE.search("ad..KrbOrFormForWin")
    assert KERBEROS_ADAPTER_RE.search("ad..KrbOrForm")
    assert KERBEROS_ADAPTER_RE.search("ad..kerbForm")
    assert not KERBEROS_ADAPTER_RE.search("ad..FormBased")
    assert not KERBEROS_ADAPTER_RE.search("ad..CILogonCert")


def test_kerberos_falls_back_to_password_adapter_when_none_offered():
    page = CHOOSE_PAGE.replace(
        '<option value="ad..KrbOrFormForWin">b. On-site Fermi Windows System</option>',
        "",
    ).replace('<option value="ad..KrbOrForm">c. Kerberos (FERMI or FNAL)</option>', "")
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=FakeSPNEGOAuth())
    assert s.choose_adapter(_fake(page)) == PASSWORD_ADAPTER


# --------------------------------------------------------------------------
# end-to-end
# --------------------------------------------------------------------------


def test_kerberos_login_walk(tmp_path):
    fake = FakeSPNEGOAuth()
    adapter = ScriptedAdapter(kerberos_handler)
    jar = tmp_path / "jar.txt"
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=fake, cookie_file=str(jar))
    s.mount("https://", adapter)

    resp = s.get(TARGET)

    assert resp.text == FINAL_PAGE
    # target GET, adapter-selection GET (answered with the ticket), postback POST
    assert adapter.methods == ["GET", "GET", "POST"]
    assert "pfidpadapterid=ad..KrbOrForm" in adapter.urls[1]
    assert adapter.calls[1].headers["Authorization"].startswith("Negotiate ")
    assert s.login_count == 1
    assert s.logging_in_already is False
    assert jar.exists()
    # no password was ever involved
    assert s.login_form_data is None
    assert not any("pf.pass" in (c.body or "") for c in adapter.calls)


def test_unanswered_challenge_is_returned_and_not_counted():
    """No handler (or a handler without a ticket): the 401 comes back as is."""
    adapter = ScriptedAdapter(kerberos_handler)
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=lambda r: r)
    s.mount("https://", adapter)

    resp = s.get(TARGET)

    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Negotiate"
    assert adapter.methods == ["GET", "GET"]
    assert s.login_count == 0
    ok, reasons = probe.classify(s, resp, "pingprod.fnal.gov")
    assert not ok
    assert any("Kerberos" in r and "klist" in r for r in reasons)
    assert not any("stranded" in r for r in reasons)


def test_kerberos_with_password_fallback_uses_kerberos_first():
    fake = FakeSPNEGOAuth()
    adapter = ScriptedAdapter(kerberos_handler)
    s = FermiSSOSession(auth_method="kerberos", spnego_auth=fake, userpass="u:p")
    s.mount("https://", adapter)
    assert s.get(TARGET).text == FINAL_PAGE
    assert "pfidpadapterid=ad..KrbOrForm" in adapter.urls[1]
    assert not any("pf.pass" in (c.body or "") for c in adapter.calls)


# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------


def test_probe_auth_option_and_env():
    args = probe.build_parser().parse_args(["-a", "kerberos"])
    assert args.auth == "kerberos"
    assert (
        probe.resolve(
            None, probe.ENV_AUTH, {probe.ENV_AUTH: "kerberos"}, {}, "password"
        )
        == "kerberos"
    )


def test_probe_kerberos_needs_no_password(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv(probe.ENV_PASSWORD, raising=False)
    monkeypatch.delenv(probe.ENV_USER, raising=False)
    monkeypatch.delenv("USER", raising=False)
    real = probe.FermiSSOSession

    def factory(*args, **kwargs):
        kwargs["spnego_auth"] = FakeSPNEGOAuth()
        session = real(*args, **kwargs)
        session.mount("https://", ScriptedAdapter(kerberos_handler))
        return session

    monkeypatch.setattr(probe, "FermiSSOSession", factory)
    code = probe.main(
        ["--no-env-file", "-n", "-a", "kerberos", "-x", "DocDB Home", TARGET]
    )
    err = capsys.readouterr().err
    assert code == 0, err
    assert "with Kerberos" in err
    assert "login     : performed" in err


def test_probe_rejects_bad_auth_env(monkeypatch, capsys):
    monkeypatch.setenv(probe.ENV_AUTH, "carrier-pigeon")
    assert probe.main(["--no-env-file", "-n", "-u", "u", "-p", "p", TARGET]) == 2
    assert "must be password or kerberos" in capsys.readouterr().err
