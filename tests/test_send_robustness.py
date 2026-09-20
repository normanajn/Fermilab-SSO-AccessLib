"""
Tests for send()'s re-entrancy guard and for the body-scanning guard.

Both concern what send() does around the login walk rather than the walk
itself: that the guard is cleared however send() leaves, and that bodies
which cannot be a stage of the login sequence are never decoded.
"""

import io

import pytest
import requests
import urllib3
from requests.adapters import BaseAdapter

from requests_fermi_sso import MAX_POSTBACK_HOPS, FermiSSOSession

LOGIN_FORM = '<html><form method="POST" action="/idp/login">x</form></html>'


def html(request, body, status=200):
    resp = requests.Response()
    resp.status_code = status
    resp.url = request.url
    resp.request = request
    resp.encoding = "utf-8"
    resp._content = body.encode("utf-8")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


def postback(action):
    return (
        f'<html><form method="post" action="{action}">'
        '<input type="hidden" name="RelayState" value="rs"/>'
        '<input type="hidden" name="SAMLResponse" value="cmVzcA=="/>'
        "</form></html>"
    )


# --------------------------------------------------------------------------
# the re-entrancy guard
# --------------------------------------------------------------------------


class ExplodingAdapter(BaseAdapter):
    """Serves the login form, then fails the POST the way a dropped
    connection would."""

    def __init__(self, exc):
        self.exc = exc

    def send(self, request, **kwargs):
        if request.method == "POST":
            raise self.exc
        return html(request, LOGIN_FORM)

    def close(self):
        pass


@pytest.mark.parametrize(
    "exc",
    [
        requests.ConnectionError("connection dropped mid-login"),
        requests.Timeout("idp timed out"),
    ],
)
def test_the_guard_is_cleared_when_a_nested_request_raises(exc):
    # Left set, the session silently stops logging in for good: every later
    # request takes the early return in send() and behaves as a plain
    # Session.
    session = FermiSSOSession(userpass="u:p")
    session.mount("https://", ExplodingAdapter(exc))

    with pytest.raises(type(exc)):
        session.get("https://site/page")

    assert session.logging_in_already is False


def test_the_session_still_logs_in_after_a_failed_attempt(sso_adapter):
    """The point of clearing the guard: a retry must still work."""
    session = FermiSSOSession(userpass="testuser:s3cret")
    session.mount("https://", ExplodingAdapter(requests.ConnectionError("boom")))
    with pytest.raises(requests.ConnectionError):
        session.get("https://site/page")

    # same session, a working transport: the login must still be driven
    session.mount("https://", sso_adapter)
    from conftest import FINAL_PAGE, TARGET

    resp = session.get(TARGET)
    assert resp.text == FINAL_PAGE
    assert session.login_count == 1


def test_the_guard_is_cleared_on_the_delay_page(sso_adapter):
    from conftest import DELAY_PAGE, ScriptedAdapter

    session = FermiSSOSession(userpass="u:p")
    session.mount("https://", ScriptedAdapter(lambda request: DELAY_PAGE))
    session.get("https://pingprod.fnal.gov/as/authorization.oauth2")
    assert session.logging_in_already is False


# --------------------------------------------------------------------------
# chained postbacks
# --------------------------------------------------------------------------


class ChainedPostbackAdapter(BaseAdapter):
    """First hop answers with another postback form, as an intermediate
    assertion consumer does."""

    def __init__(self):
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append((request.method, request.url))
        if request.method == "GET":
            return html(request, postback("https://sp/acs1"))
        if request.url.endswith("acs1"):
            return html(request, postback("https://sp/acs2"))
        return html(request, "<html><body>done</body></html>")

    def close(self):
        pass


def test_a_chained_postback_is_followed_to_the_end():
    session = FermiSSOSession()
    adapter = ChainedPostbackAdapter()
    session.mount("https://", adapter)

    resp = session.get("https://sp/protected")

    assert [m for m, _ in adapter.calls] == ["GET", "POST", "POST"]
    assert "done" in resp.text


def test_a_chained_postback_counts_as_one_login():
    # Before the guard was added here the nested send() walked the sequence
    # again, so one sign-on incremented login_count twice.
    session = FermiSSOSession()
    session.mount("https://", ChainedPostbackAdapter())
    session.get("https://sp/protected")
    assert session.login_count == 1


def test_a_postback_loop_is_bounded():
    class Loop(BaseAdapter):
        def __init__(self):
            self.n = 0

        def send(self, request, **kwargs):
            self.n += 1
            return html(request, postback("https://sp/acs"))

        def close(self):
            pass

    session = FermiSSOSession()
    loop = Loop()
    session.mount("https://", loop)
    session.get("https://sp/x")

    assert loop.n == 1 + MAX_POSTBACK_HOPS


# --------------------------------------------------------------------------
# the body-scanning guard
# --------------------------------------------------------------------------


class StreamingAdapter(BaseAdapter):
    """Serves a real streamable body, so _content_consumed means what it
    means in production."""

    def __init__(self, body, content_type):
        self.body = body
        self.content_type = content_type

    def send(self, request, stream=False, **kwargs):
        raw = urllib3.HTTPResponse(
            body=io.BytesIO(self.body),
            status=200,
            headers={
                "Content-Type": self.content_type,
                "Content-Length": str(len(self.body)),
            },
            preload_content=False,
        )
        resp = requests.Response()
        resp.status_code = 200
        resp.raw = raw
        resp.url = request.url
        resp.request = request
        resp.headers.update(raw.headers)
        return resp

    def close(self):
        pass


def test_a_binary_body_is_never_decoded():
    # Touching .text here would buffer the whole attachment and defeat
    # stream=True, which is how a DocDB download used to pull the file into
    # memory whether the caller asked for it or not.
    body = b"%PDF-1.4" + bytes(range(256)) * 4000
    session = FermiSSOSession()
    session.mount("https://", StreamingAdapter(body, "application/pdf"))

    resp = session.get("https://docdb/doc.pdf", stream=True)

    assert resp._content_consumed is False
    assert b"".join(resp.iter_content(65536)) == body


def test_an_oversized_html_body_is_not_scanned():
    body = b"<html>" + b"x" * (3 * 1024 * 1024) + b"</html>"
    session = FermiSSOSession()
    session.mount("https://", StreamingAdapter(body, "text/html"))

    resp = session.get("https://site/huge", stream=True)

    assert resp._content_consumed is False


def test_an_html_body_is_still_scanned_and_logged_in(sso_adapter):
    from conftest import FINAL_PAGE, TARGET

    session = FermiSSOSession(userpass="testuser:s3cret")
    session.mount("https://", sso_adapter)
    assert session.get(TARGET).text == FINAL_PAGE


def test_a_response_without_a_content_type_is_still_scanned():
    class NoType(BaseAdapter):
        def send(self, request, **kwargs):
            resp = requests.Response()
            resp.status_code = 200
            resp.url = request.url
            resp.request = request
            resp.encoding = "utf-8"
            resp._content = LOGIN_FORM.encode()
            return resp

        def close(self):
            pass

    session = FermiSSOSession()
    session.mount("https://", NoType())
    resp = session.get("https://site/page")
    # no credentials, so the walk stops at the login form -- but it was seen
    assert session.login_page_re.search(resp.text)
