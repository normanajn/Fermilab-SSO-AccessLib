import requests
from requests.cookies import create_cookie

import json
import os
import re
import sys
import time
import logging
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

__version__ = "0.2.0"

logger = logging.getLogger(__name__)

#: Cookie file formats understood by load_cookies()/save_cookies().
COOKIE_FORMATS = ("netscape", "lwp", "json")

#: Authentication methods FermiSSOSession can drive at the identity provider.
AUTH_METHODS = ("password", "kerberos", "yubikey")

#: The IdP's password adapter, the same on every connection seen so far.
PASSWORD_ADAPTER = "ad..FormBased"

#: Kerberos adapter ids differ per connection: the SAML connection offers
#: ad..KrbOrForm (and ad..KrbOrFormForWin), the OAuth/OIDC one ad..kerbForm.
#: Matched against the choose page's <option value="..."> list, so the right
#: one is picked wherever the session lands. The "ForWin" variant is avoided
#: because it expects a domain-joined Windows client.
KERBEROS_ADAPTER_RE = re.compile(
    r"^ad\.\.(?!KrbOrFormForWin$)[^\"]*(krb|kerb)[^\"]*$", re.I
)

#: The hardware-token adapters (FNAL Yubikey, HSPD-12 badge) authenticate by
#: client certificate on the IdP's mutual-TLS listener. Prefer the production
#: Yubikey adapter over the test one; HSPD12 last.
YUBIKEY_ADAPTER_ORDER = (
    re.compile(r"^ad\.\.FNALYubikey$", re.I),
    re.compile(r"^ad\.\..*yubikey.*$", re.I),
    re.compile(r"^ad\.\.FNALHSPD12$", re.I),
)

#: Redirect targets handed to the certificate hop instead of being followed:
#: the IdP's mutual-TLS listener, which lives on its own port.
MTLS_LOCATION_RE = re.compile(r"^https://[^/]+:9032/", re.I)

#: Content types the identity provider serves its forms as. A response of
#: any other type cannot be a stage of the login sequence, so its body is
#: never decoded or scanned.
HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")

#: Bodies larger than this are not scanned for login forms. Every page in the
#: sequence is a few tens of kB; anything this large is a payload, and
#: decoding it to text just to run six regexes over it is what made
#: stream=True useless for document downloads.
MAX_SCAN_BYTES = 2 * 1024 * 1024

#: Most flows post back once. A few chain a second time through an
#: intermediate assertion consumer; anything beyond that is a loop.
MAX_POSTBACK_HOPS = 4

_NETSCAPE_HEADER = "# Netscape HTTP Cookie File"
_LWP_HEADER = "#LWP-Cookies-2.0"
_HTTPONLY_PREFIX = "#HttpOnly_"


class FermiSSOSession(requests.Session):
    """
    Subclass of requests.Session that logs into Fermi SSO
    as needed.
    >>> import requests
    >>> from requests_fermi_sso import FermiSSOSession
    >>> s = FermiSSOSession(userpass=f"{username}:{password}")
    >>> resp = s.get("https://cdcvs.fnal.gov/index.html")

    Cookies from an earlier login -- this library's own, or a browser
    export -- can be reused so no password is needed at all:
    >>> s = FermiSSOSession(cookie_file="~/.fermi_sso.cookies")
    >>> resp = s.get("https://cdcvs.fnal.gov/index.html")
    """

    def __init__(self, *args, **kwargs):
        """
        set login form data, various page recognition regexps,
        initialize logging_in_already flag to prevent halls of mirrors
        and do superclass init

        Keyword arguments consumed here (everything else goes to
        requests.Session):

        userpass       "user:password" for the IdP's password adapter
        auth_method    "password" (default), "kerberos", or "yubikey".
                       Kerberos selects the IdP's Kerberos adapter on the
                       choose page and answers its SPNEGO (Negotiate)
                       challenge from the local ticket cache via
                       requests-gssapi. Yubikey selects the hardware-token
                       adapter and performs the mutual-TLS request it
                       redirects to through cert_hop
        spnego_auth    a requests auth handler to use for the Negotiate
                       challenge instead of requests_gssapi.HTTPSPNEGOAuth
        cert_hop       callable(url, prepared_request) -> HopResponse that
                       performs one GET with a client certificate Python's
                       TLS stack cannot present (a smart-card key). Required
                       for auth_method="yubikey"; see fermi_sso_yubikey
        cookie_file    path of a cookie jar to load before the first request;
                       missing files are ignored so a first run can create it
        cookie_format  "netscape", "lwp", "json", or None to auto-detect
        cookie_save    when true (the default if cookie_file is given), the
                       jar is rewritten to cookie_file each time this session
                       completes a login sequence
        """

        if "userpass" in kwargs:
            # split once: a colon is legal in a password, and splitting on
            # every one of them used to raise ValueError out of __init__
            username, _, passwd = kwargs["userpass"].partition(":")
            self.login_form_data = {
                "pf.username": username,
                "pf.pass": passwd,
                "pf.ok": "clicked",
                "pf.cancel": "",
                "pf.adapterId": "FormBased",
            }
            del kwargs["userpass"]
        else:
            self.login_form_data = None

        # PingFederate serves the same choose/login pages for SAML (paths under
        # /idp/) and for OIDC / OAuth2 (paths under /as/). Accept both.
        self.choose_page_re = re.compile(
            '<form.*method="GET".*action="(/(?:idp|as)/[^"]*)".*>'
        )
        self.login_page_re = re.compile(
            '<form.*method="POST".*action="(/(?:idp|as)/[^"]*)".*>'
        )
        self.base_re = re.compile('<base href="(.*)/"/>')
        # PingFederate throttles repeated sign-ons with a "Multiple Sign-On
        # Delay" page. It carries a GET form with pfidpadapterid, so it would
        # otherwise pass for the choose page and each automatic re-selection
        # would count as another attempt.
        self.delay_page_re = re.compile(
            r"<title>\s*Multiple Sign-On Delay\s*</title>", re.I
        )
        self.postback_form_re = re.compile(
            '<form.*method="post".*action="([^"]*)".*>.*<input.*name="RelayState" *value="([^"]*)".*<input.*name="SAMLResponse" *value="([^"]*)"',
            flags=re.S,
        )
        self.auth_method = kwargs.pop("auth_method", "password")
        if self.auth_method not in AUTH_METHODS:
            raise ValueError(
                f"auth_method must be one of {AUTH_METHODS}, not {self.auth_method!r}"
            )
        spnego_auth = kwargs.pop("spnego_auth", None)
        self.cert_hop = kwargs.pop("cert_hop", None)
        if self.auth_method == "yubikey" and self.cert_hop is None:
            raise ValueError(
                "auth_method='yubikey' needs cert_hop, e.g. "
                "fermi_sso_yubikey.YubiKeyCertHop()"
            )
        #: Redirects matching this are performed by cert_hop, not followed.
        self.mtls_location_re = MTLS_LOCATION_RE
        self.cert_hop_count = 0
        #: Adapter selected on the choose page for password authentication.
        self.adapterid = PASSWORD_ADAPTER
        #: Pattern picking the Kerberos adapter out of the choose page's options.
        self.kerberos_adapter_re = KERBEROS_ADAPTER_RE
        self.logging_in_already = False

        # django-allauth puts a confirmation page in front of the IdP: the
        # provider login URL (/accounts/<provider>/login/ or
        # /accounts/oidc/<id>/login/) serves a form that must be POSTed with
        # its CSRF token before the redirect to pingprod happens. Recognized
        # by URL path plus a post form whose only fields are the CSRF token
        # and optionally "next"; see is_allauth_sso_page().
        self.allauth_url_re = re.compile(r"^/accounts/.+/login/?$")
        self.allauth_count = 0

        # Service providers that use the SAML HTTP-POST binding towards the
        # IdP (Workday, for one) hand the browser an auto-submitting form
        # carrying SAMLRequest. Count of those submitted here.
        self.authn_request_count = 0

        self.cookie_file = kwargs.pop("cookie_file", None)
        if self.cookie_file:
            self.cookie_file = os.path.expanduser(self.cookie_file)
        self.cookie_format = kwargs.pop("cookie_format", None)
        self.cookie_save = kwargs.pop("cookie_save", bool(self.cookie_file))
        self.cookies_loaded = 0
        self.login_count = 0

        requests.Session.__init__(self, *args, **kwargs)

        if self.auth_method == "kerberos":
            # The handler only acts on a 401 carrying WWW-Authenticate:
            # Negotiate, so attaching it session-wide is harmless elsewhere.
            self.auth = (
                spnego_auth if spnego_auth is not None else _default_spnego_auth()
            )

        if self.cookie_file:
            self.cookies_loaded = self.load_cookies(
                self.cookie_file, self.cookie_format, missing_ok=True
            )

    def send(self, req, **send_kwargs):
        """
        This is what is actually different from plain Session;
        we do the Session send(), but before returning the data
        check for various pages in the SSO login sequence, and
        send them appropriate responses
        """
        if self.logging_in_already:
            # recursively called from a get() or post(), below...
            return requests.Session.send(self, req, **send_kwargs)

        jar_before = self._jar_signature()
        res = requests.Session.send(self, req, **send_kwargs)
        logger.debug(f"returning {res=}")
        # Everything below may set logging_in_already and may raise -- a
        # transport error on a nested request, a malformed form, a failed
        # certificate hop. The flag has to be cleared on the way out either
        # way; leaving it set turns this session into a plain Session that
        # never logs in again, silently.
        try:
            return self._run_login_sequence(res, jar_before)
        finally:
            self.logging_in_already = False

    def _run_login_sequence(self, res, jar_before):
        """
        Walk whatever stage of the SSO sequence res represents.

        Called by send() with the re-entrancy flag clear, and always under
        the try/finally there that clears it again.
        """
        performed_login = False

        if not self._is_scannable(res):
            # Not a page that could carry an SSO form. Skip the body
            # entirely -- see _is_scannable -- but still persist any cookies
            # the redirect chain picked up.
            self._save_jar_if_changed(jar_before, performed_login)
            return res

        if self.is_allauth_sso_page(res):
            self.logging_in_already = True
            url, formdata = self.extract_allauth_form(res)
            logger.debug(f"got allauth SSO confirmation page; posting to {url}")
            # Django's CSRF check on HTTPS requires a same-origin Referer
            res = requests.Session.post(
                self, url, data=formdata, headers={"Referer": res.url}
            )
            self.allauth_count += 1

        if self.is_saml_request_page(res):
            # SP -> IdP AuthnRequest by HTTP-POST binding: submit it and carry
            # on with whatever the IdP answers (choose page, login form, or a
            # SAMLResponse postback straight back if the IdP session is live)
            self.logging_in_already = True
            url, formdata = self.extract_saml_request_form(res)
            logger.debug(f"got SAML AuthnRequest form; posting to {url}")
            res = requests.Session.post(self, url, data=formdata)
            self.authn_request_count += 1

        if self.delay_page_re.search(res.text):
            logger.warning(
                "identity provider is throttling sign-ons (Multiple Sign-On "
                "Delay); returning that page unanswered"
            )
            return res

        m = self.choose_page_re.search(res.text)
        if m:
            self.logging_in_already = True
            logger.debug("got Choose page...")
            url = self.extract_chose_url(res)
            logger.debug(f"trying to choose by calling {url} ")
            if self.auth_method == "yubikey":
                res = self._select_with_cert_hop(url)
                # a denied hop comes back as the application's error page,
                # which is a 200; the OAuth error lives in the redirect URL
                denied = any("error=" in h.url for h in list(res.history) + [res])
                if not (
                    denied
                    or res.status_code >= 400
                    or self.choose_page_re.search(res.text)
                    or self.login_page_re.search(res.text)
                ):
                    performed_login = True
            else:
                res = requests.Session.get(self, url)
            for resp in res.history:
                logger.debug(f"history_item:{resp.status_code}: {resp.text}")
            if self.auth_method == "kerberos":
                # The Kerberos adapter answers the adapter selection with a
                # 401 Negotiate challenge that the auth handler satisfies
                # underneath us. Anything other than a lingering 401 or an
                # IdP page means the ticket was accepted.
                if res.status_code == 401:
                    logger.warning(
                        "Kerberos (Negotiate) challenge from the identity "
                        "provider was not satisfied; is there a valid ticket?"
                    )
                elif not (
                    self.choose_page_re.search(res.text)
                    or self.login_page_re.search(res.text)
                ):
                    performed_login = True

        m = self.login_page_re.search(res.text)
        if m and self.login_form_data:
            logger.debug("got Login page...")
            # guard the nested post like the other branches; without it the
            # nested send() handled the postback itself and this login was
            # counted (and the jar saved) twice
            self.logging_in_already = True
            url = self.extract_login_url(res)
            res = requests.Session.post(self, url, data=self.login_form_data)
            # Being served the login form again means the password was
            # rejected. Anything else -- a SAML postback form, or for OIDC the
            # already-followed redirect back to the application -- means the
            # IdP accepted the credentials.
            performed_login = not self.login_page_re.search(res.text)

        # SAML flows end with an auto-submitting postback form. OIDC flows end
        # with a 302 to the client's redirect_uri, which requests has already
        # followed by this point, so there is nothing more to do for them.
        #
        # Guarded like the other branches, so the nested send() does not walk
        # the sequence a second time and count the sign-on twice. That makes
        # a chained postback -- where the assertion consumer answers with
        # another one -- this frame's job, hence the loop rather than a
        # single if.
        hops = 0
        while (
            hops < MAX_POSTBACK_HOPS
            and self._is_scannable(res)
            and self.postback_form_re.search(res.text)
        ):
            logger.debug("saw Postback form...")
            logger.debug(f"cookies: {repr(self.cookies)}")
            logger.debug(res.text)
            logger.debug("=-=-=-=-=-=-=-=")
            self.logging_in_already = True
            url, formdata = self.extract_post_back_data(res)
            res = requests.Session.post(self, url, data=formdata)
            hops += 1
            performed_login = True
        if hops >= MAX_POSTBACK_HOPS:
            logger.warning(
                f"stopped after {MAX_POSTBACK_HOPS} SAML postbacks; the "
                "identity provider and the service provider may be looping"
            )

        if performed_login:
            self.login_count += 1

        self._save_jar_if_changed(jar_before, performed_login)
        return res

    def _save_jar_if_changed(self, jar_before, performed_login):
        """
        Persist the jar whenever this request changed it: after a login, but
        also when the IdP's own session cookie let a second site sign us in
        via a plain redirect chain with no login sequence at all. An
        unchanged jar -- typically a reused browser export -- is left alone.
        """
        if not (self.cookie_file and self.cookie_save):
            return
        if not (performed_login or self._jar_signature() != jar_before):
            return
        try:
            self.save_cookies(self.cookie_file, self.cookie_format)
        except OSError as exc:
            logger.warning(f"could not save cookies to {self.cookie_file}: {exc}")

    def _is_scannable(self, res):
        """
        True when res could be a stage of the login sequence.

        Reading res.text forces the whole body into memory and marks the
        response consumed, which defeats stream=True and, on a DocDB
        attachment, can mean gigabytes. The identity provider only ever
        serves HTML, and only small HTML, so a response that is neither is
        passed straight through untouched.

        A response with no Content-Type is scanned, as before: absent the
        header there is nothing to rule it out on.
        """
        ctype = res.headers.get("Content-Type", "")
        if ctype:
            main = ctype.split(";")[0].strip().lower()
            if main and main not in HTML_CONTENT_TYPES:
                logger.debug(f"not scanning a {main} response for login forms")
                return False
        length = res.headers.get("Content-Length")
        if length:
            try:
                if int(length) > MAX_SCAN_BYTES:
                    logger.debug(
                        f"not scanning a {length}-byte response for login forms"
                    )
                    return False
            except ValueError:
                pass
        return True

    def _jar_signature(self):
        """Hashable snapshot of the jar, for change detection."""
        return frozenset(
            (c.domain, c.path, c.name, c.value, c.expires) for c in self.cookies
        )

    def extract_post_back_data(self, resp):
        """utiltity to regex match the data for the postback form"""

        m = self.postback_form_re.search(resp.text)
        return m.group(1), {"RelayState": m.group(2), "SAMLResponse": m.group(3)}

    def extract_login_url(self, resp):
        """utility to regex match and expand the login form url"""
        base = resp.url[0 : resp.url.find("/", 9)]
        mb = self.base_re.search(resp.text)
        if mb:
            base = mb.group(1)
        m = self.login_page_re.search(resp.text)
        return base + m.group(1)

    def choose_adapter(self, resp) -> str:
        """
        Adapter id to select on the choose page.

        Password: self.adapterid (ad..FormBased). Kerberos: the first
        <option> whose value matches kerberos_adapter_re, since the id
        differs between the IdP's SAML and OIDC connections. Yubikey: the
        best hardware-token option per YUBIKEY_ADAPTER_ORDER. If the page
        offers no option for the method, the password adapter is used
        instead, with a warning, so a site without it still logs in when a
        password was also supplied.
        """
        if self.auth_method == "password":
            return self.adapterid
        options = re.findall(r'<option[^>]*value="([^"]*)"', resp.text)
        if self.auth_method == "kerberos":
            for value in options:
                if self.kerberos_adapter_re.search(value):
                    return value
        elif self.auth_method == "yubikey":
            for pattern in YUBIKEY_ADAPTER_ORDER:
                for value in options:
                    if pattern.search(value):
                        return value
        logger.warning(
            f"no {self.auth_method} adapter among {options}; "
            f"falling back to {self.adapterid}"
        )
        return self.adapterid

    # ------------------------------------------------------------------
    # certificate hop (hardware token on the IdP's mutual-TLS listener)
    # ------------------------------------------------------------------

    def _select_with_cert_hop(self, url):
        """
        Select the adapter without following redirects; if the IdP answers
        with a redirect to its mutual-TLS listener, perform that one request
        through cert_hop, absorb its cookies, and continue from its
        redirect. Anything else is returned as requests would have.
        """
        res = requests.Session.get(self, url, allow_redirects=False)
        location = res.headers.get("Location", "")
        if not (res.is_redirect and self.mtls_location_re.search(location)):
            if res.is_redirect:
                return requests.Session.get(self, urljoin(url, location))
            return res
        hop_url = urljoin(url, location)
        prepared = self.prepare_request(requests.Request("GET", hop_url))
        logger.debug(f"certificate hop to {hop_url.split('?')[0]}")
        hop = self.cert_hop(hop_url, prepared)
        self.cert_hop_count += 1
        self._absorb_hop_cookies(hop, prepared)
        hop_res = _hop_to_response(hop, hop_url, prepared)
        if hop.status in (301, 302, 303, 307, 308) and hop.headers.get("location"):
            next_url = urljoin(hop_url, hop.headers["location"])
            logger.debug(f"certificate hop redirects to {next_url.split('?')[0]}")
            res = requests.Session.get(self, next_url)
            res.history.insert(0, hop_res)
            return res
        return hop_res

    def _absorb_hop_cookies(self, hop, prepared):
        """Feed the hop's Set-Cookie headers into the session jar."""
        import http.client
        from requests.cookies import MockRequest, MockResponse

        msg = http.client.HTTPMessage()
        for value in hop.set_cookies:
            msg["Set-Cookie"] = value
        self.cookies.extract_cookies(MockResponse(msg), MockRequest(prepared))

    def extract_chose_url(self, resp):
        """return form data to send to the Pick Authentication Method form"""

        formdata = {
            "pfidpadapterid": self.choose_adapter(resp),
            "rememberChoice": "true",  # don't re-ask
        }
        base = resp.url[0 : resp.url.find("/", 9)]
        mb = self.base_re.search(resp.text)
        if mb:
            base = mb.group(1)

        # urlencode, not a hand-rolled join: for kerberos and yubikey the
        # adapter id is read straight out of the page's <option> list
        packed_form_data = urlencode(formdata)
        # use a regexp to find the <form> tag in the page
        m = self.choose_page_re.search(resp.text)
        if not m:
            # only reachable if a caller invokes this on a page send() never
            # matched; an assert here vanished under python -O
            raise ValueError("no choose-authentication form in response")
        return base + m.group(1) + "?" + packed_form_data

    # ------------------------------------------------------------------
    # django-allauth confirmation page
    # ------------------------------------------------------------------

    def is_allauth_sso_page(self, resp) -> bool:
        """
        True when resp is django-allauth's "continue to <provider>" page.

        Requires an allauth provider-login URL path and a post form that
        posts back to that same path (no action, or an action resolving to
        it) whose only fields are csrfmiddlewaretoken (required) and next
        (optional). The local /accounts/login/ page fails the form test: its
        password or passkey form carries other fields. A site's "Sign out"
        button -- also a CSRF-only post form, but to /accounts/logout/ -- is
        excluded by the action test; submitting it would end the session.
        """
        if not self.allauth_url_re.search(urlsplit(resp.url).path):
            return False
        return self._allauth_form(resp) is not None

    def extract_allauth_form(self, resp) -> Tuple[str, Dict[str, str]]:
        """Return (absolute post URL, hidden field data) for the allauth form."""
        form = self._allauth_form(resp)
        if form is None:
            raise ValueError("no allauth SSO form in response")
        url, fields = form
        return url, fields

    @staticmethod
    def _allauth_form(resp):
        """(post URL, fields) of the self-posting CSRF-only form, or None."""
        page_path = urlsplit(resp.url).path.rstrip("/")
        for attrs, fields in _find_forms(resp.text):
            if (attrs.get("method") or "").lower() != "post":
                continue
            names = set(fields)
            if "csrfmiddlewaretoken" not in names or not names <= {
                "csrfmiddlewaretoken",
                "next",
            }:
                continue
            action = attrs.get("action") or ""
            url = urljoin(resp.url, action) if action else resp.url
            if urlsplit(url).path.rstrip("/") != page_path:
                logger.debug(f"ignoring CSRF-only form posting elsewhere: {action!r}")
                continue
            return url, fields
        return None

    # ------------------------------------------------------------------
    # SAML AuthnRequest (SP -> IdP, HTTP-POST binding)
    # ------------------------------------------------------------------

    def is_saml_request_page(self, resp) -> bool:
        """
        True when resp is a service provider's auto-submitting AuthnRequest
        form: a post form with a SAMLRequest field and no SAMLResponse.
        """
        return self._saml_request_form(resp) is not None

    def extract_saml_request_form(self, resp) -> Tuple[str, Dict[str, str]]:
        """Return (absolute IdP URL, all hidden fields) for the AuthnRequest form."""
        form = self._saml_request_form(resp)
        if form is None:
            raise ValueError("no SAML AuthnRequest form in response")
        return form

    @staticmethod
    def _saml_request_form(resp):
        for attrs, fields in _find_forms(resp.text):
            if (attrs.get("method") or "").lower() != "post":
                continue
            if "SAMLRequest" in fields and "SAMLResponse" not in fields:
                action = attrs.get("action") or ""
                url = urljoin(resp.url, action) if action else resp.url
                return url, fields
        return None

    # ------------------------------------------------------------------
    # cookie persistence
    # ------------------------------------------------------------------

    def load_cookies(self, path, fmt=None, missing_ok=False):
        """
        Merge cookies from a file into this session's jar.

        fmt is one of COOKIE_FORMATS, or None to detect from the file's
        extension and first line. Expired cookies are skipped. Returns the
        number of cookies loaded. A missing file raises FileNotFoundError
        unless missing_ok is set, in which case 0 is returned.
        """
        path = os.path.expanduser(path)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            if missing_ok:
                logger.debug(f"cookie file {path} does not exist yet")
                return 0
            raise

        fmt = fmt or detect_cookie_format(path, text)
        if fmt == "netscape":
            cookies = parse_netscape_cookies(text)
        elif fmt == "lwp":
            cookies = parse_lwp_cookies(text)
        elif fmt == "json":
            cookies = parse_json_cookies(text)
        else:
            raise ValueError(
                f"unknown cookie format {fmt!r}; expected one of {COOKIE_FORMATS}"
            )

        now = time.time()
        loaded = 0
        for cookie in cookies:
            if cookie.is_expired(now):
                logger.debug(
                    f"skipping expired cookie {cookie.name} for {cookie.domain}"
                )
                continue
            self.cookies.set_cookie(cookie)
            loaded += 1
        logger.debug(f"loaded {loaded} cookies from {path} ({fmt})")
        return loaded

    def save_cookies(self, path, fmt=None):
        """
        Write this session's cookie jar to path.

        fmt defaults to the format implied by the path's extension
        (".json", ".lwp"), else Netscape cookies.txt. Session cookies --
        the kind the SSO flow actually issues -- are written too, unlike
        the stdlib jar classes, which drop them by default. The file is
        created mode 0600 because these cookies are bearer credentials.
        Returns the number of cookies written.
        """
        path = os.path.expanduser(path)
        fmt = fmt or detect_cookie_format(path, None)
        now = time.time()
        cookies = [c for c in self.cookies if not c.is_expired(now)]

        if fmt == "netscape":
            text = format_netscape_cookies(cookies)
        elif fmt == "lwp":
            text = format_lwp_cookies(cookies)
        elif fmt == "json":
            text = format_json_cookies(cookies)
        else:
            raise ValueError(
                f"unknown cookie format {fmt!r}; expected one of {COOKIE_FORMATS}"
            )

        # write to a sibling temp file and rename so a reader never sees a
        # half-written jar, and so the mode is right before any data lands
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        logger.debug(f"saved {len(cookies)} cookies to {path} ({fmt})")
        return len(cookies)


# ----------------------------------------------------------------------
# certificate hop result
# ----------------------------------------------------------------------


class HopResponse:
    """
    What a cert_hop callable returns: the raw result of one HTTPS request
    made outside requests. headers has lower-cased names and keeps the last
    value of a repeated header; set_cookies keeps every Set-Cookie value.
    """

    def __init__(
        self, status: int, headers: Dict[str, str], body: bytes, set_cookies=()
    ):
        self.status = int(status)
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body or b""
        self.set_cookies = list(set_cookies)

    def __repr__(self):
        return f"HopResponse({self.status}, location={self.headers.get('location')!r})"


def _hop_to_response(hop: HopResponse, url: str, prepared) -> requests.Response:
    """Wrap a HopResponse as a requests.Response so callers see one shape."""
    resp = requests.Response()
    resp.status_code = hop.status
    resp.url = url
    resp.request = prepared
    resp.headers.update(hop.headers)
    resp._content = hop.body
    resp.encoding = "utf-8"
    return resp


# ----------------------------------------------------------------------
# Kerberos / SPNEGO
# ----------------------------------------------------------------------


def _default_spnego_auth():
    """
    requests_gssapi.HTTPSPNEGOAuth configured for the IdP.

    Mutual authentication is OPTIONAL because PingFederate does not return a
    final Negotiate token on the redirect that follows a successful
    exchange; REQUIRED would reject that response. opportunistic_auth stays
    off so tokens are only produced in answer to a challenge.
    """
    try:
        from requests_gssapi import OPTIONAL, HTTPSPNEGOAuth
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "auth_method='kerberos' needs the requests-gssapi package: "
            "pip install 'requests-fermi_sso[kerberos]'"
        ) from exc
    return HTTPSPNEGOAuth(mutual_authentication=OPTIONAL, opportunistic_auth=False)


# ----------------------------------------------------------------------
# minimal form scanner
# ----------------------------------------------------------------------


class _FormScanner(HTMLParser):
    """Collect every <form> with its attributes and named input fields."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: List[Tuple[Dict[str, str], Dict[str, str]]] = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "form":
            self._current = (attrs, {})
            self.forms.append(self._current)
        elif tag in ("input", "select", "textarea") and self._current is not None:
            name = attrs.get("name")
            if name and (attrs.get("type") or "").lower() not in (
                "submit",
                "button",
                "image",
            ):
                self._current[1][name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def _find_forms(text: str):
    """Return [(form attrs, {field name: value}), ...] for the page."""
    scanner = _FormScanner()
    try:
        scanner.feed(text)
        scanner.close()
    except Exception as exc:  # malformed markup: treat as no forms
        logger.debug(f"form scan failed: {exc}")
        return []
    return scanner.forms


# ----------------------------------------------------------------------
# cookie file formats
#
# Three formats are supported:
#
#   netscape  the tab-separated cookies.txt written by curl -c, wget, and
#             the common browser "export cookies" extensions. HttpOnly
#             cookies appear with a "#HttpOnly_" domain prefix; Python < 3.10
#             drops those as comments, which is why this is hand-rolled
#             rather than using http.cookiejar.MozillaCookieJar.
#   lwp       the libwww-perl Set-Cookie3 format of http.cookiejar.LWPCookieJar
#   json      a list of objects. Written with this module's own keys, read
#             with either those or the keys used by the Cookie-Editor /
#             EditThisCookie browser extensions (expirationDate, httpOnly,
#             hostOnly).
# ----------------------------------------------------------------------


def detect_cookie_format(path: str, text: Optional[str]) -> str:
    """
    Pick a format from the path's extension, then from the content.

    With text None (as when saving) only the extension is consulted and the
    fallback is netscape.
    """
    lower = path.lower()
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".lwp"):
        return "lwp"
    if text is not None:
        head = text.lstrip()
        if head.startswith(_LWP_HEADER):
            return "lwp"
        if head.startswith("[") or head.startswith("{"):
            return "json"
    return "netscape"


def _make_cookie(
    name: str,
    value: str,
    domain: str,
    path: str,
    secure: bool,
    expires: Optional[int],
    httponly: bool,
    host_only: bool = False,
):
    """
    Build an http.cookiejar.Cookie the way a Set-Cookie header would have.

    In Netscape files a leading dot on the domain (equivalently, the
    include-subdomains flag) marks a domain cookie; without it the cookie is
    host-only. requests.cookies.create_cookie derives domain_specified and
    domain_initial_dot from the domain string, so normalize that here.
    """
    if domain and not host_only and not domain.startswith("."):
        domain = "." + domain
    if host_only and domain.startswith("."):
        domain = domain[1:]
    rest = {"HttpOnly": None} if httponly else {}
    return create_cookie(
        name,
        value,
        domain=domain or "",
        path=path or "/",
        secure=bool(secure),
        expires=int(expires) if expires else None,
        discard=not expires,
        rest=rest,
    )


def _is_httponly(cookie) -> bool:
    rest = cookie._rest or {}
    return any(k.lower() == "httponly" for k in rest)


def parse_netscape_cookies(text: str) -> List:
    """Parse cookies.txt lines into Cookie objects."""
    cookies = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r\n")
        httponly = False
        if line.startswith(_HTTPONLY_PREFIX):
            httponly = True
            line = line[len(_HTTPONLY_PREFIX) :]
        elif not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) == 6:
            # a cookie with an empty value loses its trailing tab in some
            # exporters
            fields.append("")
        if len(fields) != 7:
            logger.debug(
                f"cookies.txt line {lineno}: expected 7 fields, got {len(fields)}"
            )
            continue
        domain, flag, path, secure, expires, name, value = fields
        subdomains = flag.strip().upper() == "TRUE"
        try:
            expires_at = int(float(expires)) if expires.strip() else 0
        except ValueError:
            logger.debug(f"cookies.txt line {lineno}: bad expiry {expires!r}")
            continue
        cookies.append(
            _make_cookie(
                name,
                value,
                domain,
                path,
                secure.strip().upper() == "TRUE",
                expires_at or None,
                httponly,
                host_only=not subdomains and not domain.startswith("."),
            )
        )
    return cookies


def format_netscape_cookies(cookies: Iterable) -> str:
    """Render cookies as a cookies.txt file, session cookies included."""
    lines = [
        _NETSCAPE_HEADER,
        "# Written by requests_fermi_sso. Session cookies have expiry 0.",
        "",
    ]
    for c in cookies:
        domain = c.domain or ""
        subdomains = domain.startswith(".")
        prefix = _HTTPONLY_PREFIX if _is_httponly(c) else ""
        lines.append(
            "\t".join(
                [
                    prefix + domain,
                    "TRUE" if subdomains else "FALSE",
                    c.path or "/",
                    "TRUE" if c.secure else "FALSE",
                    str(int(c.expires) if c.expires else 0),
                    c.name,
                    c.value if c.value is not None else "",
                ]
            )
        )
    return "\n".join(lines) + "\n"


def parse_lwp_cookies(text: str) -> List:
    """Parse the LWP Set-Cookie3 format via the stdlib jar."""
    import http.cookiejar
    import tempfile

    jar = http.cookiejar.LWPCookieJar()
    # LWPCookieJar only loads from a filename
    with tempfile.NamedTemporaryFile(
        "w", suffix=".lwp", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(text)
        name = tmp.name
    try:
        jar.load(name, ignore_discard=True, ignore_expires=True)
    finally:
        os.unlink(name)
    return list(jar)


def format_lwp_cookies(cookies: Iterable) -> str:
    import http.cookiejar

    jar = http.cookiejar.LWPCookieJar()
    for c in cookies:
        jar.set_cookie(c)
    return f"{_LWP_HEADER}\n" + jar.as_lwp_str(ignore_discard=True, ignore_expires=True)


def parse_json_cookies(text: str) -> List:
    """
    Parse a JSON cookie list.

    Accepts this module's own output and the shape exported by the
    Cookie-Editor and EditThisCookie browser extensions. A top-level object
    with a "cookies" key is unwrapped.
    """
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("cookies", [])
    cookies = []
    for item in data:
        if not isinstance(item, dict) or "name" not in item:
            continue
        expires = item.get("expires", item.get("expirationDate"))
        if expires in ("", None, 0, False) or item.get("session"):
            expires = None
        httponly = bool(item.get("httponly", item.get("httpOnly", False)))
        host_only = bool(item.get("host_only", item.get("hostOnly", False)))
        cookies.append(
            _make_cookie(
                item["name"],
                item.get("value", ""),
                item.get("domain", ""),
                item.get("path", "/"),
                bool(item.get("secure", False)),
                expires,
                httponly,
                host_only=host_only,
            )
        )
    return cookies


def format_json_cookies(cookies: Iterable) -> str:
    items = []
    for c in cookies:
        items.append(
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain or "",
                "path": c.path or "/",
                "secure": bool(c.secure),
                "httponly": _is_httponly(c),
                "host_only": not (c.domain or "").startswith("."),
                "expires": int(c.expires) if c.expires else None,
            }
        )
    return json.dumps(items, indent=2, sort_keys=True) + "\n"
