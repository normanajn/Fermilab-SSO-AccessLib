"""
Tests for the SP-to-IdP SAML AuthnRequest step: recognition of the
auto-submitting form, extraction, the walk through to the protected page,
and the probe's naming of a second-factor stop.
"""

import pytest
import requests

import fermi_sso_probe as probe
from requests_fermi_sso import FermiSSOSession

from conftest import (
    AUTHN_IDP_URL,
    AUTHN_REQUEST_PAGE,
    AUTHN_START,
    CHOOSE_PAGE,
    FINAL_PAGE,
    LOGIN_PAGE,
    POSTBACK_PAGE,
    RESUME,
    SECURID_PAGE,
    SP,
    ScriptedAdapter,
    authn_request_handler,
    authn_request_mfa_handler,
    make_response,
)


def _fake(text, url):
    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


@pytest.fixture
def session():
    return FermiSSOSession()


# --------------------------------------------------------------------------
# recognition and extraction
# --------------------------------------------------------------------------


def test_authn_request_form_is_recognized(session):
    assert session.is_saml_request_page(_fake(AUTHN_REQUEST_PAGE, AUTHN_START))


def test_postback_form_is_not_mistaken_for_an_authn_request(session):
    """SAMLResponse forms are the IdP -> SP direction and have their own path."""
    assert not session.is_saml_request_page(
        _fake(POSTBACK_PAGE, "https://pingprod.fnal.gov/idp/x")
    )


def test_idp_pages_are_not_authn_requests(session):
    for page in (CHOOSE_PAGE, LOGIN_PAGE, FINAL_PAGE, SECURID_PAGE):
        assert not session.is_saml_request_page(
            _fake(page, "https://pingprod.fnal.gov/idp/x")
        )


def test_get_form_with_samlrequest_is_ignored(session):
    page = AUTHN_REQUEST_PAGE.replace('method="post"', 'method="get"')
    assert not session.is_saml_request_page(_fake(page, AUTHN_START))


def test_extract_gives_absolute_idp_url_and_all_fields(session):
    url, fields = session.extract_saml_request_form(
        _fake(AUTHN_REQUEST_PAGE, AUTHN_START)
    )
    assert url == AUTHN_IDP_URL
    assert set(fields) == {"SAMLRequest"}
    assert fields["SAMLRequest"].startswith("PD94bWwg")


def test_extract_carries_relaystate_and_resolves_relative_action(session):
    page = AUTHN_REQUEST_PAGE.replace(
        f'action="{AUTHN_IDP_URL}"', 'action="/idp/SSO.saml2"'
    ).replace(
        "<noscript>",
        '<input type="hidden" name="RelayState" value="https://sp/target"/><noscript>',
    )
    url, fields = session.extract_saml_request_form(
        _fake(page, "https://pingprod.fnal.gov:9031/x/y")
    )
    assert url == "https://pingprod.fnal.gov:9031/idp/SSO.saml2"
    assert fields["RelayState"] == "https://sp/target"


def test_extract_without_a_form_raises(session):
    with pytest.raises(ValueError):
        session.extract_saml_request_form(_fake(FINAL_PAGE, SP))


# --------------------------------------------------------------------------
# end-to-end
# --------------------------------------------------------------------------


def test_authn_request_then_login_then_postback(tmp_path):
    adapter = ScriptedAdapter(authn_request_handler)
    jar = tmp_path / "jar.txt"
    s = FermiSSOSession(userpass="testuser:s3cret", cookie_file=str(jar))
    s.mount("https://", adapter)

    resp = s.get(AUTHN_START)

    assert resp.text == FINAL_PAGE
    # authorize GET, AuthnRequest POST, login POST, postback POST
    assert adapter.methods == ["GET", "POST", "POST", "POST"]
    assert adapter.urls[1] == AUTHN_IDP_URL
    assert "SAMLRequest=PD94bWwg" in adapter.calls[1].body
    assert adapter.urls[2] == "https://pingprod.fnal.gov" + RESUME
    assert "pf.username=testuser" in adapter.calls[2].body
    assert s.authn_request_count == 1
    assert s.login_count == 1
    assert s.logging_in_already is False
    assert jar.exists()


def test_authn_request_without_credentials_stops_at_the_login_form():
    adapter = ScriptedAdapter(authn_request_handler)
    s = FermiSSOSession()
    s.mount("https://", adapter)
    resp = s.get(AUTHN_START)
    assert s.login_page_re.search(resp.text)
    assert adapter.methods == ["GET", "POST"]
    assert s.authn_request_count == 1 and s.login_count == 0


def test_second_factor_stop_is_named_by_the_probe():
    """
    Workday's connection: password accepted, then an RSA SecurID form. The
    library cannot continue; the probe must say why rather than "stranded".
    """
    adapter = ScriptedAdapter(authn_request_mfa_handler)
    s = FermiSSOSession(userpass="testuser:s3cret")
    s.mount("https://", adapter)
    resp = s.get(AUTHN_START)

    assert "SecurID" in resp.text
    assert adapter.methods == ["GET", "POST", "POST"]
    # the password was accepted (login form not re-served), so it counts
    assert s.login_count == 1
    ok, reasons = probe.classify(s, resp, "pingprod.fnal.gov")
    assert not ok
    assert any("second factor" in r and "SecurID" in r for r in reasons)
    assert not any("stranded" in r for r in reasons)
