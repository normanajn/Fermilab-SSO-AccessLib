import requests
from requests.cookies import create_cookie

import json
import os
import re
import sys
import time
import logging
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)

#: Cookie file formats understood by load_cookies()/save_cookies().
COOKIE_FORMATS = ("netscape", "lwp", "json")

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
        cookie_file    path of a cookie jar to load before the first request;
                       missing files are ignored so a first run can create it
        cookie_format  "netscape", "lwp", "json", or None to auto-detect
        cookie_save    when true (the default if cookie_file is given), the
                       jar is rewritten to cookie_file each time this session
                       completes a login sequence
        """

        if "userpass" in kwargs:
            username, passwd = kwargs["userpass"].split(":")
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
        self.postback_form_re = re.compile(
            '<form.*method="post".*action="([^"]*)".*>.*<input.*name="RelayState" *value="([^"]*)".*<input.*name="SAMLResponse" *value="([^"]*)"',
            flags=re.S,
        )
        self.adapterid = "ad..FormBased"
        self.logging_in_already = False

        self.cookie_file = kwargs.pop("cookie_file", None)
        if self.cookie_file:
            self.cookie_file = os.path.expanduser(self.cookie_file)
        self.cookie_format = kwargs.pop("cookie_format", None)
        self.cookie_save = kwargs.pop("cookie_save", bool(self.cookie_file))
        self.cookies_loaded = 0
        self.login_count = 0

        requests.Session.__init__(self, *args, **kwargs)

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
        performed_login = False

        m = self.choose_page_re.search(res.text)
        if m:
            self.logging_in_already = True
            ("got Choose page...")
            # got choose_auth page...
            url = self.extract_chose_url(res)
            logger.debug(f"trying to choose by calling {url} ")
            res = requests.Session.get(self, url)
            for resp in res.history:
                logger.debug(f"history_item:{resp.status_code}: {resp.text}")

        m = self.login_page_re.search(res.text)
        if m and self.login_form_data:
            logger.debug("got Login page...")
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
        m = self.postback_form_re.search(res.text)
        if m:
            logger.debug("saw Postback form...")
            logger.debug(f"cookies: {repr(self.cookies)}")
            logger.debug(res.text)
            logger.debug("=-=-=-=-=-=-=-=")
            url, formdata = self.extract_post_back_data(res)
            res = requests.Session.post(self, url, data=formdata)
            performed_login = True

        if performed_login:
            self.login_count += 1

        # Persist the jar whenever this request changed it: after a login,
        # but also when the IdP's own session cookie let a second site sign
        # us in via a plain redirect chain with no login sequence at all.
        # An unchanged jar -- typically a reused browser export -- is left
        # alone.
        if (
            self.cookie_file
            and self.cookie_save
            and (performed_login or self._jar_signature() != jar_before)
        ):
            try:
                self.save_cookies(self.cookie_file, self.cookie_format)
            except OSError as exc:
                logger.warning(f"could not save cookies to {self.cookie_file}: {exc}")

        self.logging_in_already = False
        return res

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

    def extract_chose_url(self, resp):
        """return form data to send to the Pick Authentication Method form"""

        formdata = {
            "pfidpadapterid": self.adapterid,  # we want password
            "rememberChoice": "true",  # don't re-ask
        }
        base = resp.url[0 : resp.url.find("/", 9)]
        mb = self.base_re.search(resp.text)
        if mb:
            base = mb.group(1)

        packed_form_data = "&".join([f"{k}={v}" for k, v in formdata.items()])
        # use a regexp to find the <form> tag in the page
        m = self.choose_page_re.search(resp.text)
        assert m
        return base + m.group(1) + "?" + packed_form_data

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
