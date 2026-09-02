"""
Shared fixtures for the requests_fermi_sso test suite.

The HTML fixtures below are trimmed copies of what pingprod.fnal.gov and
mu2e-docdb.fnal.gov actually served (captured 2026-08-18). The tag shapes --
attribute order, quoting, and the upper/lowercase of the form ``method`` --
are reproduced exactly, because requests_fermi_sso matches these pages with
regular expressions and is sensitive to all three.
"""

import os
import sys

import pytest
import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

IDP = "https://pingprod.fnal.gov"
SP = "https://mu2e-docdb.fnal.gov"
TARGET = SP + "/cgi-bin/sso/DocumentDatabase"
RESUME = "/idp/ZAPBqJRObr/resumeSAML20/idp/SSO.ping"

CHOOSE_PAGE = """<html>
<head><base href="https://pingprod.fnal.gov/"/></head>
<body>
<form method="GET" action="{resume}">
<select name="pfidpadapterid">
<option value="ad..FormBased">a. Services Username and Password</option>
<option value="ad..KrbOrFormForWin">b. On-site Fermi Windows System</option>
<option value="ad..KrbOrForm">c. Kerberos (FERMI or FNAL)</option>
</select>
<input type="submit" value="Login"/>
</form>
</body></html>
""".format(resume=RESUME)

LOGIN_PAGE = """<html>
<head><base href="https://pingprod.fnal.gov/"/></head>
<body>
<form method="POST" action="{resume}" autocomplete="off">
<input id="username" type="text" size="36" name="pf.username" value="" autocorrect="off" autocapitalize="off"  />
<input id="password" type="password" size="36" name="pf.pass" />
<input type="hidden" name="pf.ok" value="" />
<input type="hidden" name="pf.cancel" value="" />
<input type="hidden" name="pf.adapterId" id="pf.adapterId" value="FormBased" />
</form>
</body></html>
""".format(resume=RESUME)

#: The IdP's auto-submitting SAML response form. Note lowercase method="post",
#: which is why it does not collide with the login-page pattern.
POSTBACK_PAGE = """<html>
<body onload="document.forms[0].submit()">
<form method="post" action="{sp}/mellon/postResponse">
<input type="hidden" name="RelayState" value="{target}"/>
<input type="hidden" name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNlPjwvc2FtbHA6UmVzcG9uc2U+"/>
<noscript><input type="submit" value="Continue"/></noscript>
</form>
</body></html>
""".format(sp=SP, target=TARGET)

#: The OIDC variant of the same two pages, as served for the Mu2e shift
#: scheduler (captured 2026-09-02). Only the form action prefix differs:
#: /as/.../resume/as/authorization.ping instead of /idp/.../resumeSAML20/...
OIDC_SP = "https://mu2e-shifts.fnal.gov"
OIDC_TARGET = OIDC_SP + "/login/oidc?next=/"
OIDC_RESUME = "/as/lJsCVlRD92/resume/as/authorization.ping"
OIDC_CHOOSE_PAGE = CHOOSE_PAGE.replace(RESUME, OIDC_RESUME).replace(
    '<option value="ad..KrbOrForm">c. Kerberos (FERMI or FNAL)</option>',
    '<option value="ad..CILogonCert">CILogonCert Only</option>\n'
    '<option value="ad..kerbForm">Kerberos (FNAL or FERMI)</option>',
)
OIDC_LOGIN_PAGE = LOGIN_PAGE.replace(RESUME, OIDC_RESUME)
OIDC_FINAL_PAGE = """<html><head><title>Mu2e Shift Scheduler</title></head>
<body><h1>Shifts</h1><p>Signed in as testuser.</p></body></html>
"""

FINAL_PAGE = """<html><head><title>Mu2e Document Database</title></head>
<body><h1>DocDB Home</h1><p>Welcome, testuser.</p></body></html>
"""

PLAIN_PAGE = """<html><head><title>Landing</title></head>
<body><a href="/cgi-bin/sso/DocumentDatabase">Single Sign-On</a></body></html>
"""


#: Cookie the service provider sets once the SAML postback is accepted.
SP_COOKIE = "mellon-cookie"


class _FakeRaw:
    """
    Just enough of urllib3's HTTPResponse for requests to harvest cookies.

    Session.send() calls extract_cookies_to_jar(jar, request, resp.raw), which
    reads Set-Cookie headers from raw._original_response.msg. Giving the
    fake response that attribute lets the scripted transport set cookies on
    the real session jar without any sockets.
    """

    def __init__(self, set_cookies):
        import http.client

        msg = http.client.HTTPMessage()
        for header in set_cookies:
            msg["Set-Cookie"] = header
        self._original_response = type("orig", (), {"msg": msg})()

    def close(self):
        pass

    def release_conn(self):
        pass


def make_response(request, text, status=200, set_cookies=()):
    """Build a requests.Response the way an adapter would."""
    resp = requests.Response()
    resp.status_code = status
    resp.url = request.url
    resp.request = request
    resp.encoding = "utf-8"
    resp._content = text.encode("utf-8")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if set_cookies:
        resp.raw = _FakeRaw(set_cookies)
    return resp


class ScriptedAdapter(HTTPAdapter):
    """
    Transport adapter that answers from a handler instead of the network.

    Mounting this lets the real FermiSSOSession.send() logic run end to end
    with no sockets involved. Every PreparedRequest is recorded in .calls.
    """

    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        super(ScriptedAdapter, self).__init__()

    def send(self, request, **kwargs):
        self.calls.append(request)
        result = self.handler(request)
        if isinstance(result, tuple):
            text, set_cookies = result
        else:
            text, set_cookies = result, ()
        return make_response(request, text, set_cookies=set_cookies)

    @property
    def urls(self):
        return [call.url for call in self.calls]

    @property
    def methods(self):
        return [call.method for call in self.calls]


def sso_handler(request):
    """
    Serve the four-step Fermilab SSO sequence.

    target URL          -> choose-authentication page
                           (or the protected page if the SP cookie is sent)
    resume URL + query  -> login form
    POST to resume URL  -> SAML postback form
    POST to mellon      -> the protected page, and Set-Cookie of the SP cookie
    """
    url, method = request.url, request.method
    if url.startswith(SP + "/mellon/postResponse"):
        return FINAL_PAGE, [f"{SP_COOKIE}=sess-1; Path=/; Secure; HttpOnly"]
    if RESUME in url:
        if method == "POST":
            return POSTBACK_PAGE
        return LOGIN_PAGE
    if url.startswith(TARGET):
        if SP_COOKIE + "=" in request.headers.get("Cookie", ""):
            return FINAL_PAGE
        return CHOOSE_PAGE
    return PLAIN_PAGE


@pytest.fixture
def sso_adapter():
    """A ScriptedAdapter wired to the full SSO sequence."""
    return ScriptedAdapter(sso_handler)


@pytest.fixture
def sso_session(sso_adapter):
    """A logged-in-capable FermiSSOSession talking to the scripted adapter."""
    from requests_fermi_sso import FermiSSOSession

    session = FermiSSOSession(userpass="testuser:s3cret")
    session.mount("https://", sso_adapter)
    return session


@pytest.fixture
def anon_session(sso_adapter):
    """A FermiSSOSession with no credentials, to test the partial walk."""
    from requests_fermi_sso import FermiSSOSession

    session = FermiSSOSession()
    session.mount("https://", sso_adapter)
    return session


def oidc_handler(request):
    """
    Serve the OIDC flavour of the sequence, with no SAML postback.

    login/oidc          -> choose-authentication page (in reality a 302 to
                           the IdP that requests follows; the scripted adapter
                           serves the IdP page directly)
    resume URL + query  -> login form
    POST to resume URL  -> the protected page (standing in for the 302 chain
                           back through /oidc/callback that requests follows)
    """
    url, method = request.url, request.method
    if OIDC_RESUME in url:
        if method == "POST":
            return OIDC_FINAL_PAGE
        return OIDC_LOGIN_PAGE
    if url.startswith(OIDC_TARGET):
        return OIDC_CHOOSE_PAGE
    return PLAIN_PAGE
