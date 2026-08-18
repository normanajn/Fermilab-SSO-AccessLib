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
""".format(
    resume=RESUME
)

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
""".format(
    resume=RESUME
)

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
""".format(
    sp=SP, target=TARGET
)

FINAL_PAGE = """<html><head><title>Mu2e Document Database</title></head>
<body><h1>DocDB Home</h1><p>Welcome, testuser.</p></body></html>
"""

PLAIN_PAGE = """<html><head><title>Landing</title></head>
<body><a href="/cgi-bin/sso/DocumentDatabase">Single Sign-On</a></body></html>
"""


def make_response(request, text, status=200):
    """Build a requests.Response the way an adapter would."""
    resp = requests.Response()
    resp.status_code = status
    resp.url = request.url
    resp.request = request
    resp.encoding = "utf-8"
    resp._content = text.encode("utf-8")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
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
        return make_response(request, self.handler(request))

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
    resume URL + query  -> login form
    POST to resume URL  -> SAML postback form
    POST to mellon      -> the protected page
    """
    url, method = request.url, request.method
    if url.startswith(SP + "/mellon/postResponse"):
        return FINAL_PAGE
    if RESUME in url:
        if method == "POST":
            return POSTBACK_PAGE
        return LOGIN_PAGE
    if url.startswith(TARGET):
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
