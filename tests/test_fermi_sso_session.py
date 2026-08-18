"""
Tests for FermiSSOSession: page recognition, URL construction, and the
end-to-end login walk driven through a scripted transport adapter.
"""

import pytest

from requests_fermi_sso import FermiSSOSession

from conftest import (
    CHOOSE_PAGE,
    FINAL_PAGE,
    LOGIN_PAGE,
    POSTBACK_PAGE,
    RESUME,
    SP,
    TARGET,
    ScriptedAdapter,
    make_response,
    sso_handler,
)


@pytest.fixture
def session():
    return FermiSSOSession()


# --------------------------------------------------------------------------
# page recognition
# --------------------------------------------------------------------------


def test_choose_page_is_recognized(session):
    match = session.choose_page_re.search(CHOOSE_PAGE)
    assert match
    assert match.group(1) == RESUME


def test_login_page_is_recognized(session):
    match = session.login_page_re.search(LOGIN_PAGE)
    assert match
    assert match.group(1) == RESUME


def test_page_patterns_do_not_cross_match(session):
    """
    The choose and login pages are told apart only by the case of the form's
    method attribute, so verify each pattern rejects the other page.
    """
    assert not session.login_page_re.search(CHOOSE_PAGE)
    assert not session.choose_page_re.search(LOGIN_PAGE)
    # the postback form uses lowercase method="post" and an absolute action
    assert not session.login_page_re.search(POSTBACK_PAGE)
    assert not session.choose_page_re.search(POSTBACK_PAGE)


def test_final_page_matches_nothing(session):
    assert not session.choose_page_re.search(FINAL_PAGE)
    assert not session.login_page_re.search(FINAL_PAGE)
    assert not session.postback_form_re.search(FINAL_PAGE)


# --------------------------------------------------------------------------
# URL and form-data extraction
# --------------------------------------------------------------------------


def test_extract_post_back_data(session):
    resp = _fake(POSTBACK_PAGE, SP + "/anything")
    url, formdata = session.extract_post_back_data(resp)
    assert url == SP + "/mellon/postResponse"
    assert formdata["RelayState"] == TARGET
    assert formdata["SAMLResponse"].startswith("PHNhbWxwOl")


def test_extract_login_url_prefers_base_href(session):
    """The <base> tag wins over the host the page was fetched from."""
    resp = _fake(LOGIN_PAGE, "https://elsewhere.example.org/whatever")
    assert session.extract_login_url(resp) == "https://pingprod.fnal.gov" + RESUME


def test_extract_login_url_falls_back_to_response_host(session):
    page = LOGIN_PAGE.replace('<base href="https://pingprod.fnal.gov/"/>', "")
    resp = _fake(page, "https://pingprod.fnal.gov/idp/startSSO.ping?x=1")
    assert session.extract_login_url(resp) == "https://pingprod.fnal.gov" + RESUME


def test_extract_chose_url_selects_password_adapter(session):
    resp = _fake(CHOOSE_PAGE, "https://pingprod.fnal.gov/idp/SSO.saml2")
    url = session.extract_chose_url(resp)
    assert url.startswith("https://pingprod.fnal.gov" + RESUME + "?")
    # ad..FormBased is "a. Services Username and Password" at the live IdP
    assert "pfidpadapterid=ad..FormBased" in url
    assert "rememberChoice=true" in url


def _fake(text, url):
    import requests

    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


# --------------------------------------------------------------------------
# end-to-end flow
# --------------------------------------------------------------------------


def test_full_login_flow_reaches_protected_page(sso_session, sso_adapter):
    resp = sso_session.get(TARGET)

    assert resp.text == FINAL_PAGE
    assert "DocDB Home" in resp.text

    # four requests: target, choose-resume, login POST, postback POST
    assert sso_adapter.methods == ["GET", "GET", "POST", "POST"]
    assert sso_adapter.urls[0] == TARGET
    assert "pfidpadapterid=ad..FormBased" in sso_adapter.urls[1]
    assert sso_adapter.urls[2] == "https://pingprod.fnal.gov" + RESUME
    assert sso_adapter.urls[3] == SP + "/mellon/postResponse"


def test_login_post_carries_the_credentials(sso_session, sso_adapter):
    sso_session.get(TARGET)
    body = sso_adapter.calls[2].body
    assert "pf.username=testuser" in body
    assert "pf.pass=s3cret" in body
    assert "pf.adapterId=FormBased" in body
    assert "pf.ok=clicked" in body


def test_postback_carries_the_saml_response(sso_session, sso_adapter):
    sso_session.get(TARGET)
    body = sso_adapter.calls[3].body
    assert "SAMLResponse=PHNhbWxwOl" in body
    assert "RelayState=" in body


def test_flow_flag_is_cleared_so_a_second_fetch_works(sso_session, sso_adapter):
    """
    logging_in_already guards against recursion; if it were left set, every
    later request would skip SSO handling entirely.
    """
    sso_session.get(TARGET)
    assert sso_session.logging_in_already is False
    resp = sso_session.get(TARGET)
    assert resp.text == FINAL_PAGE


def test_without_credentials_the_walk_stops_at_the_login_form(
    anon_session, sso_adapter
):
    """
    With no userpass the session still picks an auth method, but must not
    submit the login form -- it has nothing to submit.
    """
    resp = anon_session.get(TARGET)
    assert anon_session.login_page_re.search(resp.text)
    assert sso_adapter.methods == ["GET", "GET"]


def test_non_sso_page_passes_through_untouched(sso_session, sso_adapter):
    resp = sso_session.get(SP + "/")
    assert "Landing" in resp.text
    assert len(sso_adapter.calls) == 1


# --------------------------------------------------------------------------
# credential parsing
# --------------------------------------------------------------------------


def test_userpass_is_split_into_form_data():
    session = FermiSSOSession(userpass="alice:hunter2")
    assert session.login_form_data["pf.username"] == "alice"
    assert session.login_form_data["pf.pass"] == "hunter2"
    assert session.login_form_data["pf.adapterId"] == "FormBased"


def test_no_userpass_leaves_form_data_unset():
    assert FermiSSOSession().login_form_data is None


def test_password_containing_a_colon_is_rejected():
    """
    Known limitation: __init__ does userpass.split(":") and unpacks into two
    names, so any colon in the password raises. fermi_sso_probe checks for
    this up front to turn it into a clear error message.
    """
    with pytest.raises(ValueError):
        FermiSSOSession(userpass="alice:hunter:2")


def test_session_is_a_requests_session():
    assert isinstance(FermiSSOSession(), __import__("requests").Session)
