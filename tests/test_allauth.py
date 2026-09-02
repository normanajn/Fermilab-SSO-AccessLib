"""
Tests for the django-allauth confirmation step: recognition, form extraction,
and the walk from the allauth page through the IdP to the application.
"""

import pytest
import requests

from requests_fermi_sso import FermiSSOSession, _find_forms

from conftest import (
    ALLAUTH_FINAL_PAGE,
    ALLAUTH_MENU_PAGE,
    ALLAUTH_PAGE,
    ALLAUTH_SIGNED_IN_PAGE,
    ALLAUTH_SP,
    ALLAUTH_START,
    ALLAUTH_TOKEN,
    OIDC_RESUME,
    ScriptedAdapter,
    allauth_handler,
    allauth_sso_session_handler,
    make_response,
)


def _fake(text, url):
    request = requests.Request(method="GET", url=url).prepare()
    return make_response(request, text)


@pytest.fixture
def session():
    return FermiSSOSession()


# --------------------------------------------------------------------------
# recognition
# --------------------------------------------------------------------------


def test_confirmation_page_is_recognized(session):
    assert session.is_allauth_sso_page(_fake(ALLAUTH_PAGE, ALLAUTH_START))


def test_provider_login_url_variants(session):
    for path in (
        "/accounts/oidc/keycloak/login/",
        "/accounts/google/login/?next=%2Fx",
        "/accounts/openid_connect/login",
    ):
        assert session.is_allauth_sso_page(_fake(ALLAUTH_PAGE, ALLAUTH_SP + path)), path


def test_local_signin_menu_is_not_submitted(session):
    """/accounts/login/ has a passkey form with a credential field: leave it."""
    resp = _fake(ALLAUTH_MENU_PAGE, ALLAUTH_SP + "/accounts/login/?next=/")
    assert not session.is_allauth_sso_page(resp)


def test_csrf_form_outside_accounts_is_not_submitted(session):
    """A bare CSRF form elsewhere on a site (a logout button, say) is not ours."""
    resp = _fake(ALLAUTH_PAGE, ALLAUTH_SP + "/logout/")
    assert not session.is_allauth_sso_page(resp)


def test_form_with_extra_fields_is_not_submitted(session):
    page = ALLAUTH_PAGE.replace(
        '<button type="submit"',
        '<input type="text" name="username"><button type="submit"',
    )
    assert not session.is_allauth_sso_page(_fake(page, ALLAUTH_START))


def test_get_form_is_not_submitted(session):
    page = ALLAUTH_PAGE.replace('<form method="post">', '<form method="get">')
    assert not session.is_allauth_sso_page(_fake(page, ALLAUTH_START))


def test_logout_form_is_never_the_one_submitted(session):
    """
    Signed-in variant: nav-bar logout form first, SSO form second. The SSO
    form must be chosen; the logout form posts elsewhere and is skipped.
    """
    resp = _fake(ALLAUTH_SIGNED_IN_PAGE, ALLAUTH_START)
    assert session.is_allauth_sso_page(resp)
    url, data = session.extract_allauth_form(resp)
    assert url == ALLAUTH_START
    assert "logout" not in url


def test_page_with_only_a_logout_form_is_not_submitted(session):
    page = ALLAUTH_SIGNED_IN_PAGE.replace(
        '<form method="post">', '<form method="post" action="/x/">'
    )
    # the SSO form now posts elsewhere too, so nothing on the page qualifies
    assert not session.is_allauth_sso_page(_fake(page, ALLAUTH_START))


def test_action_to_a_different_path_is_rejected(session):
    for action in (
        "/accounts/logout/",
        "/accounts/google/login/",
        "https://evil.example/",
        "logout/",
    ):
        page = ALLAUTH_PAGE.replace(
            '<form method="post">', f'<form method="post" action="{action}">'
        )
        assert not session.is_allauth_sso_page(_fake(page, ALLAUTH_START)), action


def test_action_equal_to_own_path_is_accepted(session):
    for action in (
        "",
        "?next=%2F",
        "/accounts/oidc/keycloak/login/",
        "/accounts/oidc/keycloak/login",
    ):
        page = ALLAUTH_PAGE.replace(
            '<form method="post">', f'<form method="post" action="{action}">'
        )
        assert session.is_allauth_sso_page(_fake(page, ALLAUTH_START)), repr(action)


def test_idp_pages_are_not_mistaken_for_allauth(session):
    from conftest import CHOOSE_PAGE, LOGIN_PAGE, POSTBACK_PAGE

    for page in (CHOOSE_PAGE, LOGIN_PAGE, POSTBACK_PAGE):
        assert not session.is_allauth_sso_page(
            _fake(page, "https://pingprod.fnal.gov/accounts/x/login/")
        )


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------


def test_extract_posts_back_to_the_same_url_with_the_token(session):
    url, data = session.extract_allauth_form(_fake(ALLAUTH_PAGE, ALLAUTH_START))
    assert url == ALLAUTH_START  # query string, and so ?next=, preserved
    assert data == {"csrfmiddlewaretoken": ALLAUTH_TOKEN}


def test_extract_honours_a_relative_action_and_next_field(session):
    page = ALLAUTH_PAGE.replace(
        '<form method="post">',
        '<form method="POST" action="/accounts/oidc/keycloak/login/">'
        '<input type="hidden" name="next" value="/reports/">',
    )
    url, data = session.extract_allauth_form(_fake(page, ALLAUTH_START))
    assert url == ALLAUTH_SP + "/accounts/oidc/keycloak/login/"
    assert data == {"csrfmiddlewaretoken": ALLAUTH_TOKEN, "next": "/reports/"}


def test_form_scanner_ignores_submit_controls_and_survives_junk():
    forms = _find_forms(ALLAUTH_MENU_PAGE)
    assert len(forms) == 1
    attrs, fields = forms[0]
    assert attrs["action"] == "/accounts/2fa/webauthn/login/"
    assert set(fields) == {"csrfmiddlewaretoken", "next", "credential"}
    assert _find_forms("") == []
    assert isinstance(_find_forms("<form><input name=<<<"), list)


# --------------------------------------------------------------------------
# end-to-end
# --------------------------------------------------------------------------


def test_allauth_then_idp_login_walk():
    adapter = ScriptedAdapter(allauth_handler)
    s = FermiSSOSession(userpass="testuser:s3cret")
    s.mount("https://", adapter)

    resp = s.get(ALLAUTH_START)

    assert resp.text == ALLAUTH_FINAL_PAGE
    # confirmation GET, confirmation POST, choose-resume GET, login POST
    assert adapter.methods == ["GET", "POST", "GET", "POST"]
    post = adapter.calls[1]
    assert post.url == ALLAUTH_START
    assert f"csrfmiddlewaretoken={ALLAUTH_TOKEN}" in post.body
    assert post.headers["Referer"] == ALLAUTH_START
    assert "pfidpadapterid=ad..FormBased" in adapter.urls[2]
    assert adapter.urls[3] == "https://pingprod.fnal.gov" + OIDC_RESUME
    assert s.allauth_count == 1
    assert s.login_count == 1
    assert s.logging_in_already is False


def test_allauth_with_live_idp_session_needs_no_credentials(tmp_path):
    """The cross-site case: jar holds the IdP session, no login pages appear."""
    jar = tmp_path / "jar.txt"
    jar.write_text("pingprod.fnal.gov\tFALSE\t/\tTRUE\t0\tPF\tlive\n")
    adapter = ScriptedAdapter(allauth_sso_session_handler)
    s = FermiSSOSession(cookie_file=str(jar))
    s.mount("https://", adapter)

    resp = s.get(ALLAUTH_START)

    assert resp.text == ALLAUTH_FINAL_PAGE
    assert adapter.methods == ["GET", "POST"]
    assert s.allauth_count == 1 and s.login_count == 0
    # the new application cookie changed the jar, so it was saved
    assert "sessionid" in jar.read_text()


def test_site_signin_menu_passes_through_untouched():
    adapter = ScriptedAdapter(allauth_handler)
    s = FermiSSOSession(userpass="testuser:s3cret")
    s.mount("https://", adapter)
    resp = s.get(ALLAUTH_SP + "/accounts/login/?next=/")
    assert resp.text == ALLAUTH_MENU_PAGE
    assert adapter.methods == ["GET"]
    assert s.allauth_count == 0


def test_signed_in_variant_end_to_end_does_not_log_out():
    """With a live site session the nav has a logout form; we must still land."""
    calls = []

    def handler(request):
        calls.append((request.method, request.url))
        if request.url.startswith(ALLAUTH_START):
            if request.method == "POST":
                return ALLAUTH_FINAL_PAGE
            return ALLAUTH_SIGNED_IN_PAGE
        if "logout" in request.url:
            raise AssertionError("the logout form was submitted")
        return ALLAUTH_MENU_PAGE

    s = FermiSSOSession()
    s.mount("https://", ScriptedAdapter(handler))
    assert s.get(ALLAUTH_START).text == ALLAUTH_FINAL_PAGE
    assert [m for m, _ in calls] == ["GET", "POST"]
    assert all("logout" not in u for _, u in calls)
