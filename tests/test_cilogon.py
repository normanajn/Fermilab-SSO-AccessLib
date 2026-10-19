"""
Tests for the CILogon device-flow approval: CILogon's user-code and
identity-provider pages, the Shibboleth IdP's client-storage forms, the
attribute-order-independent SAMLResponse postback, and the probe's handling
of a CILogon target.
"""

import pytest
import requests

import fermi_sso_probe as probe
from requests_fermi_sso import (
    CILOGON_DEVICE_URL,
    FERMILAB_CILOGON_IDP,
    FermiSSOSession,
    cilogon_error,
)

from conftest import (
    CHOOSE_PAGE,
    CILOGON,
    CILOGON_CODE,
    CILOGON_CODE_NOT_FOUND,
    CILOGON_CSRF,
    CILOGON_SUCCESS_PAGE,
    CILOGON_USER_CODE_PAGE,
    CILOGON_VERIFY,
    CILOGON_WAYF_PAGE,
    CIL_PING_POSTBACK,
    FNAL_ENTITY,
    IDPEXT_ACS,
    IDPEXT_SSO,
    LOGIN_PAGE,
    POSTBACK_PAGE,
    SHIB_POSTBACK_PAGE,
    SHIB_STORAGE_READ_PAGE,
    SHIB_STORAGE_WRITE_PAGE,
    _CILOGON_JS_NOTICE,
    ScriptedAdapter,
    cilogon_handler,
    make_response,
)


def _fake(text, url):
    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


def _wayf():
    return CILOGON_WAYF_PAGE.format(
        notice=_CILOGON_JS_NOTICE, csrf=CILOGON_CSRF, code=CILOGON_CODE, entity=FNAL_ENTITY
    )


def _user_code_page(alert=""):
    return CILOGON_USER_CODE_PAGE.replace("{alert}", alert).format(
        notice=_CILOGON_JS_NOTICE, csrf=CILOGON_CSRF
    )


def _session(**kwargs):
    adapter = ScriptedAdapter(cilogon_handler)
    kwargs.setdefault("userpass", "testuser:s3cret")
    session = FermiSSOSession(**kwargs)
    session.mount("https://", adapter)
    return session, adapter


def _body(call):
    body = call.body or ""
    return body.decode() if isinstance(body, bytes) else body


# --------------------------------------------------------------------------
# recognition and extraction
# --------------------------------------------------------------------------


def test_fermilab_entity_id_is_the_default():
    assert FermiSSOSession().cilogon_idp == FERMILAB_CILOGON_IDP == FNAL_ENTITY


def test_wayf_page_is_recognized_and_user_code_page_is_not():
    s = FermiSSOSession()
    wayf = _fake(_wayf(), CILOGON_VERIFY)
    code = _fake(_user_code_page(), CILOGON + "/device/")
    assert s.is_cilogon_wayf_page(wayf)
    assert not s.is_cilogon_user_code_page(wayf)
    assert s.is_cilogon_user_code_page(code)
    assert not s.is_cilogon_wayf_page(code)


def test_cilogon_forms_are_ignored_off_cilogon():
    """The same markup on another host is not answered."""
    s = FermiSSOSession()
    assert not s.is_cilogon_wayf_page(_fake(_wayf(), "https://example.org/device/"))
    assert not s.is_cilogon_user_code_page(
        _fake(_user_code_page(), "https://example.org/device/")
    )


def test_wayf_extract_selects_idp_logs_on_and_drops_checkbox():
    s = FermiSSOSession(cilogon_idp="https://other.example/idp")
    url, fields = s.extract_cilogon_wayf_form(_fake(_wayf(), CILOGON_VERIFY))
    assert url == CILOGON + "/device/"
    assert fields["providerId"] == "https://other.example/idp"
    assert fields["submit"] == "Log On"
    assert fields["CSRF"] == CILOGON_CSRF
    assert fields["previouspage"] == "WAYF"
    assert fields["skinname"] == "fnalonly"
    assert "keepidp" not in fields


def test_user_code_extract_fills_code_and_requires_one():
    page = _fake(_user_code_page(), CILOGON + "/device/")
    with pytest.raises(ValueError):
        FermiSSOSession().extract_cilogon_user_code_form(page)
    url, fields = FermiSSOSession(
        cilogon_user_code="ABC-DEF"
    ).extract_cilogon_user_code_form(page)
    assert url == CILOGON + "/device/"
    assert fields == {"CSRF": CILOGON_CSRF, "user_code": "ABC-DEF", "submit": "Enter User Code"}


def test_shib_storage_pages_are_recognized():
    s = FermiSSOSession()
    assert s.is_shib_storage_page(_fake(SHIB_STORAGE_READ_PAGE, IDPEXT_SSO + "?execution=e1s1"))
    assert s.is_shib_storage_page(_fake(SHIB_STORAGE_WRITE_PAGE, IDPEXT_SSO + "?execution=e1s3"))
    for page in (CHOOSE_PAGE, LOGIN_PAGE, POSTBACK_PAGE, SHIB_POSTBACK_PAGE, _wayf()):
        assert not s.is_shib_storage_page(_fake(page, IDPEXT_SSO))


def test_shibboleth_postback_is_recognized_despite_attribute_order():
    s = FermiSSOSession()
    resp = _fake(SHIB_POSTBACK_PAGE, IDPEXT_SSO + "?execution=e1s3")
    assert not s.postback_form_re.search(resp.text)
    assert s.is_postback_page(resp)
    url, fields = s.extract_post_back_data(resp)
    assert url == CILOGON + "/Shibboleth.sso/SAML2/POST"
    assert fields == {"RelayState": "ss:mem:4c1d", "SAMLResponse": "PD94bWwgdmVyc2lvbj0iMS4wIj8+"}


def test_pingprod_postback_still_goes_through_the_regex():
    s = FermiSSOSession()
    url, fields = s.extract_post_back_data(_fake(CIL_PING_POSTBACK, "https://pingprod.fnal.gov:9031/x"))
    assert url == IDPEXT_ACS
    assert fields["RelayState"] == "e1s2"


def test_cilogon_error_reads_alert_and_skips_javascript_notice():
    assert cilogon_error(_wayf()) is None
    assert cilogon_error(_user_code_page(CILOGON_CODE_NOT_FOUND)) == "Error: User code not found."


# --------------------------------------------------------------------------
# the walk
# --------------------------------------------------------------------------


def test_device_approval_walks_to_cilogon_success():
    s, adapter = _session()
    result = s.approve_cilogon_device(CILOGON_VERIFY)
    assert result.ok, result.reasons
    assert result.response.url == CILOGON + "/secure/getuser/"
    assert "successfully approved" in result.response.text
    assert s.cilogon_count == 1
    assert s.shib_storage_count == 2
    assert s.login_count == 1

    wayf_post = [c for c in adapter.calls if c.method == "POST" and c.url == CILOGON + "/device/"]
    assert len(wayf_post) == 1
    body = _body(wayf_post[0])
    assert "submit=Log+On" in body
    assert "providerId=https%3A%2F%2Fidp.fnal.gov%2Fidp%2Fshibboleth" in body
    assert "keepidp" not in body
    # the CILogon postback came from the parsed Shibboleth form
    acs = [c for c in adapter.calls if c.url.startswith(CILOGON + "/Shibboleth.sso/")]
    assert len(acs) == 1 and "SAMLResponse=" in _body(acs[0])
    # the IdP session cookie and the CILogon session cookie were both kept
    names = {c.name for c in s.cookies}
    assert {"PHPSESSID", "CSRF", "JSESSIONID", "_shibsession_cil"} <= names


def test_bare_user_code_builds_the_verification_url():
    s, adapter = _session()
    result = s.approve_cilogon_device(CILOGON_CODE)
    assert result.ok, result.reasons
    assert adapter.urls[0] == CILOGON_DEVICE_URL + "?user_code=" + CILOGON_CODE


def test_user_code_page_is_answered_when_code_is_known():
    s, adapter = _session(cilogon_user_code=CILOGON_CODE)
    resp = s.get(CILOGON + "/device/")
    assert s.cilogon_problems(resp) == []
    assert s.cilogon_count == 2
    code_post = [c for c in adapter.calls if "user_code=" in _body(c)]
    assert "submit=Enter+User+Code" in _body(code_post[0])


def test_user_code_page_is_left_alone_without_a_code():
    s, adapter = _session()
    resp = s.get(CILOGON + "/device/")
    assert adapter.methods == ["GET"]
    assert any("user-code page" in r for r in s.cilogon_problems(resp))


def test_bad_user_code_reports_cilogon_error():
    s, _ = _session(cilogon_user_code="BAD-COD-E00")
    resp = s.get(CILOGON + "/device/")
    reasons = s.cilogon_problems(resp)
    assert "CILogon reported: Error: User code not found." in reasons


def test_stopping_at_the_idp_is_not_success():
    """No credentials: the walk stops on pingprod's login form."""
    adapter = ScriptedAdapter(cilogon_handler)
    s = FermiSSOSession()
    s.mount("https://", adapter)
    result = s.approve_cilogon_device(CILOGON_VERIFY)
    assert not result.ok
    assert result.reasons == ["the login did not return to CILogon (stopped on pingprod.fnal.gov)"]
    assert s.login_page_re.search(result.response.text)


# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------


def test_probe_classify_reports_cilogon_error():
    s = FermiSSOSession()
    ok, reasons = probe.classify(
        s, _fake(_user_code_page(CILOGON_CODE_NOT_FOUND), CILOGON + "/device/"), "pingprod.fnal.gov"
    )
    assert not ok
    assert "CILogon reported: Error: User code not found." in reasons


def test_probe_classify_accepts_cilogon_success():
    s = FermiSSOSession()
    ok, reasons = probe.classify(
        s,
        _fake(CILOGON_SUCCESS_PAGE.format(notice=_CILOGON_JS_NOTICE), CILOGON + "/secure/getuser/"),
        "pingprod.fnal.gov",
    )
    assert ok, reasons


def test_probe_classify_names_a_pending_shibboleth_form():
    s = FermiSSOSession()
    ok, reasons = probe.classify(
        s, _fake(SHIB_STORAGE_READ_PAGE, IDPEXT_SSO + "?execution=e1s1"), "pingprod.fnal.gov"
    )
    assert not ok
    assert any("Shibboleth" in r for r in reasons)


def test_probe_user_code_option_builds_url(monkeypatch, capsys):
    captured = {}

    def fake_get(self, url, **kwargs):
        captured["url"] = url
        captured["code"] = self.cilogon_user_code
        captured["idp"] = self.cilogon_idp
        return _fake(CILOGON_SUCCESS_PAGE.format(notice=_CILOGON_JS_NOTICE), CILOGON + "/secure/getuser/")

    monkeypatch.setattr(FermiSSOSession, "get", fake_get)
    rc = probe.main(
        ["--no-env-file", "-u", "x", "-p", "y", "--user-code", CILOGON_CODE,
         "--cilogon-idp", "https://other.example/idp", "-q"]
    )
    assert rc == 0
    assert captured["url"] == CILOGON_DEVICE_URL + "?user_code=" + CILOGON_CODE
    assert captured["code"] == CILOGON_CODE
    assert captured["idp"] == "https://other.example/idp"


def test_probe_user_code_from_environment(monkeypatch):
    captured = {}

    def fake_get(self, url, **kwargs):
        captured["url"] = url
        return _fake(CILOGON_SUCCESS_PAGE.format(notice=_CILOGON_JS_NOTICE), CILOGON + "/secure/getuser/")

    monkeypatch.setattr(FermiSSOSession, "get", fake_get)
    monkeypatch.setenv("FERMI_SSO_USER_CODE", "ENV-COD-E11")
    rc = probe.main(["--no-env-file", "-u", "x", "-p", "y", "-q"])
    assert rc == 0
    assert captured["url"].endswith("user_code=ENV-COD-E11")
