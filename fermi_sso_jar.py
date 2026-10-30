#!/usr/bin/env python3
"""
fermi_sso_jar -- maintain a cookie jar that holds live sessions for the
Fermilab SSO sites in the catalog, so scripts can reach them without
logging in.

The idea is to pre-prime one jar: log in to each site once, with whatever
credential works for it, and let every later process load the jar and go
straight through. This module is the engine behind three front ends with
identical capabilities:

    fermi-sso-jar        command line (this file)
    fermi-sso-jar-tui    curses terminal viewer
    fermi-sso-jar-gui    Qt viewer

and it is importable: ``open_session("mu2e-talks")`` returns a ready
FermiSSOSession for a site, priming the jar first if it has to.

Per site the jar is in one of these states, judged offline from the cookie
expiries alone:

    live      the site's cookies are present and good for a while
    soon      present but within the refresh margin of expiring
    session   present, but only session cookies, whose lifetime the file
              does not record (the SSO flow issues mostly these); verify
              with a network request to be sure
    expired   present but past expiry
    absent    the jar holds nothing for the site

Settings resolve in this order, highest priority first:

    1. commandline options
    2. environment variables
    3. a .env file
    4. the ``settings`` block of the site catalog files
    5. built-in defaults

See fermi_sso_jar(1), fermi_sso_sites(5), and docs/HOWTO.md.
"""

import argparse
import getpass
import html
import os
import platform
import shlex
import stat
import sys
import time
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional
from urllib.parse import urljoin, urlsplit

import fermi_sso_probe as probe
from fermi_sso_cookies import (
    cookie_record,
    domain_matches,
    file_mode_warning,
    format_duration,
    format_timestamp,
    read_jar,
)
from fermi_sso_sites import (
    DEFAULT_IDP_HOST,
    ENV_SITES_FILE,
    JS_LOCATION_RE,
    USER_SITES_FILE,
    Catalog,
    SiteError,
    add_user_site,
    describe,
    load_catalog,
    remove_user_site,
    user_entry,
)
from requests_fermi_sso import (
    AUTH_METHODS,
    COOKIE_FORMATS,
    FermiSSOSession,
    detect_cookie_format,
    format_json_cookies,
    format_lwp_cookies,
    format_netscape_cookies,
)
from requests_fermi_sso import __version__ as _lib_version

#: single source of truth lives in the library module
__version__ = _lib_version

#: Where the jar lives when nothing names one. Matches the convention the
#: rest of the documentation uses.
DEFAULT_JAR = "~/.fermi_sso.cookies"

#: Default env file written by ``setup``; the probe's second search path.
DEFAULT_ENV_FILE = "~/.fermi_sso.env"

#: Cookies expiring within this many seconds count as "soon" and are
#: refreshed by ``refresh``.
DEFAULT_MARGIN = 30 * 60

ENV_MARGIN = "FERMI_SSO_REFRESH_MARGIN"

SITE_STATES = ("live", "soon", "session", "expired", "absent")

#: Pseudo-site key for the identity provider's own cookies.
IDP_KEY = "idp"


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------


class Credential(NamedTuple):
    """
    What a login needs. password None with auth 'password' means cookies
    only; the prompt callable, when given, is asked for it on demand.
    """

    auth_method: str = "password"
    user: Optional[str] = None
    password: Optional[str] = None
    pin_source: Optional[str] = None
    prompt: Optional[Callable[[], Optional[str]]] = None

    def can_login(self) -> bool:
        if self.auth_method in ("kerberos", "yubikey"):
            return True
        return bool(self.user) and (bool(self.password) or self.prompt is not None)

    def with_password_prompted(self) -> "Credential":
        """
        Ask the prompt once, now, so a run over several sites does not ask
        once per site. Returns self unchanged when no prompt is needed.
        """
        if self.auth_method == "password" and not self.password and self.prompt:
            return self._replace(password=self.prompt() or None, prompt=None)
        return self

    def describe(self) -> str:
        if self.auth_method == "kerberos":
            return "Kerberos ticket"
        if self.auth_method == "yubikey":
            return "YubiKey certificate"
        if self.user and (self.password or self.prompt):
            return f"password for {self.user}"
        return "cookies only"


def resolve_credential(
    environ: Dict[str, str],
    dotenv: Dict[str, str],
    catalog_settings: Optional[Dict] = None,
    auth: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    password_env: Optional[str] = None,
    pin_source: Optional[str] = None,
    prompt: Optional[Callable[[], Optional[str]]] = None,
) -> Credential:
    """
    Apply the usual precedence to the credential settings. The catalog's
    ``settings`` block sits between the .env file and the defaults.
    """
    settings = dict(catalog_settings or {})

    def pick(cli, env_key, setting_key, default=None):
        value = probe.resolve(cli, env_key, environ, dotenv)
        if value is None:
            value = settings.get(setting_key)
        return default if value is None else value

    auth_method = pick(auth, probe.ENV_AUTH, "auth", "password")
    if auth_method not in AUTH_METHODS:
        raise ValueError(
            f"auth method must be one of {AUTH_METHODS}, not {auth_method!r}"
        )
    user = pick(user, probe.ENV_USER, "user", environ.get("USER"))
    if password is None and password_env:
        password = environ.get(password_env)
        if not password:
            raise ValueError(f"${password_env} is unset or empty")
    if password is None:
        password = environ.get(probe.ENV_PASSWORD) or dotenv.get(probe.ENV_PASSWORD)
    pin = pick(pin_source, probe.ENV_PIN_SOURCE, "pin_source")
    if pin:
        pin = os.path.expanduser(pin)
    if auth_method != "password":
        prompt = None
    return Credential(auth_method, user, password or None, pin, prompt)


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------


class SiteStatus(NamedTuple):
    key: str
    name: str
    state: str
    cookies: int
    remaining: Optional[float]  # seconds to the earliest expiry, or None
    expires: Optional[int]  # epoch of that expiry
    domains: List[str]
    connection: Optional[str]
    url: Optional[str]
    names: List[str]  # cookie names, for the detail views

    @property
    def expiry_text(self) -> str:
        if self.state == "absent":
            return "no cookies"
        if self.state == "session":
            return "session cookies only"
        if self.state == "expired":
            return f"expired {format_duration(-self.remaining)} ago"
        return f"in {format_duration(self.remaining)}"


def site_status(site: Dict, records: Iterable[Dict], margin: float = DEFAULT_MARGIN) -> SiteStatus:
    """Judge one site from the jar's cookie records."""
    mine = [
        r for r in records if any(domain_matches(r["domain"], d) for d in site["domains"])
    ]
    return _status_from_records(
        site["key"], site["name"], site["domains"], site.get("connection"),
        site.get("url"), mine, margin,
    )


def idp_status(records: Iterable[Dict], idp_host: str = DEFAULT_IDP_HOST, margin: float = DEFAULT_MARGIN) -> SiteStatus:
    """The identity provider's own cookies, as a pseudo-site."""
    mine = [r for r in records if domain_matches(r["domain"], idp_host)]
    return _status_from_records(
        IDP_KEY, f"identity provider ({idp_host})", [idp_host], None, None, mine, margin
    )


def _status_from_records(key, name, domains, connection, url, mine, margin) -> SiteStatus:
    names = sorted({r["name"] for r in mine})
    if not mine:
        return SiteStatus(key, name, "absent", 0, None, None, domains, connection, url, names)
    unexpired = [r for r in mine if r["state"] != "expired"]
    if not unexpired:
        latest = max(mine, key=lambda r: r["expires"])
        return SiteStatus(
            key, name, "expired", len(mine), latest["remaining"], latest["expires"],
            domains, connection, url, names,
        )
    dated = [r for r in unexpired if r["expires"] is not None]
    if not dated:
        return SiteStatus(key, name, "session", len(mine), None, None, domains, connection, url, names)
    earliest = min(dated, key=lambda r: r["expires"])
    state = "soon" if earliest["remaining"] <= margin else "live"
    return SiteStatus(
        key, name, state, len(mine), earliest["remaining"], earliest["expires"],
        domains, connection, url, names,
    )


# --------------------------------------------------------------------------
# priming
# --------------------------------------------------------------------------


class PrimeResult(NamedTuple):
    key: str
    ok: bool
    reasons: List[str]
    final_url: str
    status_code: Optional[int]
    logged_in: bool  # a login sequence was performed
    saved: bool  # the jar file was (re)written
    cookies_loaded: int
    error: Optional[str] = None  # transport or setup failure, no response

    def summary(self) -> str:
        if self.error:
            return f"ERROR {self.error}"
        if self.ok:
            how = "logged in" if self.logged_in else "cookies accepted"
            return f"ok ({how}{', jar saved' if self.saved else ''})"
        return "FAILED " + "; ".join(self.reasons)


def build_session(
    credential: Credential,
    jar: Optional[str],
    cookie_format: Optional[str] = None,
    save: bool = True,
    cilogon_idp: Optional[str] = None,
) -> FermiSSOSession:
    """
    A FermiSSOSession for the credential, loaded from the jar. Raises
    ImportError (missing optional dependency), ValueError (bad jar or
    credential), OSError (unreadable jar), or RuntimeError (YubiKey
    prerequisites missing).
    """
    kwargs: Dict = {"auth_method": credential.auth_method}
    if cilogon_idp:
        kwargs["cilogon_idp"] = cilogon_idp
    if credential.auth_method == "yubikey":
        from fermi_sso_yubikey import YubiKeyCertHop

        hop = YubiKeyCertHop(pin_source=credential.pin_source)
        failed = [(w, d) for w, ok, d in hop.check() if not ok]
        if failed:
            raise RuntimeError(
                "yubikey prerequisites missing: "
                + "; ".join(f"{w}: {d}" for w, d in failed)
                + " (run fermi-sso-yubikey)"
            )
        kwargs["cert_hop"] = hop
    password = credential.password
    if credential.auth_method == "password" and not password and credential.prompt:
        password = credential.prompt()
    if password:
        if not credential.user:
            raise ValueError("a password needs a username")
        kwargs["userpass"] = f"{credential.user}:{password}"
    if jar:
        kwargs["cookie_file"] = jar
        kwargs["cookie_format"] = cookie_format
        kwargs["cookie_save"] = save
    return FermiSSOSession(**kwargs)


def _follow_js_redirect(session: FermiSSOSession, resp):
    """
    ServiceNow and friends answer a protected URL with a tiny page whose
    only content is a JavaScript location assignment. Follow it once.
    """
    if len(resp.content) > 64 * 1024:
        return resp
    match = JS_LOCATION_RE.search(resp.text)
    if not match:
        return resp
    target = urljoin(resp.url, html.unescape(match.group(1)))
    if urlsplit(target).scheme not in ("http", "https"):
        return resp
    return session.get(target)


def prime_site(
    site: Dict,
    credential: Credential,
    jar: str,
    cookie_format: Optional[str] = None,
    save: bool = True,
    idp_host: str = DEFAULT_IDP_HOST,
    adapter=None,
    session_factory=build_session,
    timeout: float = 60,
) -> PrimeResult:
    """
    Fetch the site's SSO entry URL through a session loaded from the jar,
    logging in with the credential if the cookies do not carry it, and
    report whether the login completed. The session saves the jar itself
    whenever a request changed it. ``adapter`` is mounted on https:// for
    offline tests.
    """
    key = site["key"]
    jar = os.path.expanduser(jar)
    existed = os.path.isfile(jar)
    mtime = os.stat(jar).st_mtime_ns if existed else None
    try:
        session = session_factory(credential, jar, cookie_format, save)
    except (ImportError, ValueError, OSError, RuntimeError) as exc:
        return PrimeResult(key, False, [], site["url"], None, False, False, 0, str(exc))
    if adapter is not None:
        session.mount("https://", adapter)
    try:
        resp = session.get(site["url"], timeout=timeout)
        if site.get("js_redirect"):
            resp = _follow_js_redirect(session, resp)
    except Exception as exc:  # requests raises many; the user needs the text
        return PrimeResult(
            key, False, [], site["url"], None, bool(session.login_count), False,
            session.cookies_loaded, f"{type(exc).__name__}: {exc}",
        )
    finally:
        hop = getattr(session, "cert_hop", None)
        if hop is not None and hasattr(hop, "close"):
            hop.close()
    ok, reasons = probe.classify(session, resp, idp_host, site.get("expect"))
    now_exists = os.path.isfile(jar)
    saved = now_exists and (not existed or os.stat(jar).st_mtime_ns != mtime)
    return PrimeResult(
        key, ok, reasons, resp.url, resp.status_code, bool(session.login_count),
        saved, session.cookies_loaded,
    )


def verify_site(site: Dict, jar: str, **kwargs) -> PrimeResult:
    """Cookies-only probe: does the jar still sign in to this site?"""
    return prime_site(site, Credential(), jar, **kwargs)


# --------------------------------------------------------------------------
# the manager: jar + catalog
# --------------------------------------------------------------------------


class JarManager:
    """
    One jar, one catalog. Reads the jar fresh on every status() so the
    viewers can poll it while another process rewrites it.
    """

    def __init__(
        self,
        jar: str = DEFAULT_JAR,
        catalog: Optional[Catalog] = None,
        cookie_format: Optional[str] = None,
        margin: float = DEFAULT_MARGIN,
        idp_host: str = DEFAULT_IDP_HOST,
    ):
        self.jar = os.path.expanduser(jar)
        self.catalog = catalog if catalog is not None else load_catalog()
        self.cookie_format = cookie_format
        self.margin = margin
        self.idp_host = idp_host

    # -- reading ---------------------------------------------------------

    def records(self, now: Optional[float] = None) -> List[Dict]:
        """Every cookie in the jar, expired ones included; [] if no jar."""
        if not os.path.isfile(self.jar):
            return []
        _, cookies = read_jar(self.jar, self.cookie_format)
        now = time.time() if now is None else now
        recs = [cookie_record(c, now) for c in cookies]
        recs.sort(key=lambda r: (r["domain"].lstrip(".").lower(), r["path"], r["name"]))
        return recs

    def status(self, keys: Iterable[str] = (), now: Optional[float] = None) -> List[SiteStatus]:
        """IdP pseudo-site first, then the catalog sites in key order."""
        recs = self.records(now)
        keys = list(keys)
        sites = [self.catalog.get(k) for k in keys] if keys else self.catalog.ordered()
        out = [idp_status(recs, self.idp_host, self.margin)]
        out += [site_status(s, recs, self.margin) for s in sites]
        return out

    def unclaimed(self, now: Optional[float] = None) -> List[Dict]:
        """Cookies belonging to neither the IdP nor any catalog site."""
        return [
            r
            for r in self.records(now)
            if not domain_matches(r["domain"], self.idp_host)
            and self.catalog.for_domain(r["domain"]) is None
        ]

    def stale_keys(self, now: Optional[float] = None, include_session: bool = False) -> List[str]:
        """Sites ``refresh`` should prime: absent, expired, soon (and session)."""
        want = {"absent", "expired", "soon"}
        if include_session:
            want.add("session")
        return [s.key for s in self.status(now=now) if s.key != IDP_KEY and s.state in want]

    # -- network ---------------------------------------------------------

    def prime(self, key: str, credential: Credential, save: bool = True, **kwargs) -> PrimeResult:
        site = self.catalog.get(key)
        return prime_site(
            site, credential, self.jar, self.cookie_format, save,
            idp_host=self.idp_host, **kwargs,
        )

    def verify(self, key: str, **kwargs) -> PrimeResult:
        return self.prime(key, Credential(), save=True, **kwargs)

    def prime_many(
        self,
        keys: Iterable[str],
        credential: Credential,
        save: bool = True,
        progress: Optional[Callable[[str, Optional[PrimeResult]], None]] = None,
        stop_on_throttle: bool = True,
        **kwargs,
    ) -> List[PrimeResult]:
        """
        Prime several sites in sequence through one jar, so the IdP session
        the first login creates signs the rest in without a login form.
        Stops when the IdP starts throttling: more attempts only lengthen
        the delay.
        """
        results = []
        for key in keys:
            if progress:
                progress(key, None)
            if credential.auth_method == "password" and not credential.password and credential.prompt:
                # Do not ask for a password the jar may make unnecessary:
                # try the cookies alone first, and prompt only on failure.
                # Whatever is typed then serves every later site in the run.
                result = self.verify(key, **kwargs)
                if result.ok:
                    results.append(result)
                    if progress:
                        progress(key, result)
                    continue
                credential = credential.with_password_prompted()
                if not credential.can_login():
                    results.append(result)
                    if progress:
                        progress(key, result)
                    continue
            result = self.prime(key, credential, save, **kwargs)
            results.append(result)
            if progress:
                progress(key, result)
            if stop_on_throttle and any("throttling" in r for r in result.reasons):
                break
        return results

    # -- editing the jar -------------------------------------------------

    def clear(self, keys: Iterable[str], idp: bool = False) -> int:
        """
        Drop the cookies of the named sites (and the IdP's, with idp) from
        the jar file. Returns how many were removed. The file keeps its
        format and mode 600.
        """
        if not os.path.isfile(self.jar):
            return 0
        fmt, cookies = read_jar(self.jar, self.cookie_format)
        domains: List[str] = []
        for key in keys:
            domains += self.catalog.get(key)["domains"]
        if idp:
            domains.append(self.idp_host)
        keep = [c for c in cookies if not any(domain_matches(c.domain or "", d) for d in domains)]
        removed = len(cookies) - len(keep)
        if removed:
            _write_jar(self.jar, fmt, keep)
        return removed

    def purge_expired(self) -> int:
        if not os.path.isfile(self.jar):
            return 0
        fmt, cookies = read_jar(self.jar, self.cookie_format)
        now = time.time()
        keep = [c for c in cookies if not c.is_expired(now)]
        removed = len(cookies) - len(keep)
        if removed:
            _write_jar(self.jar, fmt, keep)
        return removed


def _write_jar(path: str, fmt: str, cookies: List):
    """Rewrite a jar in place: temp file, mode 600, atomic rename."""
    fmt = fmt or detect_cookie_format(path, None)
    text = {
        "netscape": format_netscape_cookies,
        "lwp": format_lwp_cookies,
        "json": format_json_cookies,
    }[fmt](cookies)
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


# --------------------------------------------------------------------------
# programmatic access
# --------------------------------------------------------------------------


def open_session(
    site: Optional[str] = None,
    jar: Optional[str] = None,
    credential: Optional[Credential] = None,
    ensure: bool = True,
    catalog: Optional[Catalog] = None,
    env_file: Optional[str] = None,
) -> FermiSSOSession:
    """
    A FermiSSOSession loaded from the jar, for scripts.

    With ``site`` and ``ensure`` the site's entry URL is fetched first; if
    the jar does not sign in and the credential (default: resolved from the
    environment and env file exactly as the tools do) can log in, the login
    is performed and the jar saved. Raises RuntimeError when the site cannot
    be reached signed-in. Without ``site`` the jar is simply loaded.
    """
    environ = dict(os.environ)
    dotenv = probe.load_env_file(probe.find_env_file(env_file, environ))
    catalog = catalog if catalog is not None else load_catalog(environ=environ)
    jar = os.path.expanduser(
        jar or probe.resolve(None, probe.ENV_COOKIE_FILE, environ, dotenv)
        or catalog.settings.get("cookie_file") or DEFAULT_JAR
    )
    if credential is None:
        credential = resolve_credential(environ, dotenv, catalog.settings)
    if site and ensure:
        mgr = JarManager(jar, catalog)
        result = mgr.prime(site, credential)
        if not result.ok:
            raise RuntimeError(
                f"cannot sign in to {site}: " + (result.error or "; ".join(result.reasons))
            )
    return build_session(Credential(credential.auth_method, credential.user, None, credential.pin_source), jar)


# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------


def render_env_file(values: Dict[str, str]) -> str:
    lines = [
        "# Written by fermi-sso-jar setup. Settings for the fermi-sso tools;",
        "# commandline options and environment variables override these.",
        "# See env.example in the source tree for every key.",
    ]
    for key, value in values.items():
        if value is None or value == "":
            continue
        if any(ch in value for ch in " #'\""):
            value = '"' + value.replace('"', '\\"') + '"'
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def write_env_file(path: str, values: Dict[str, str], merge: bool = True) -> str:
    """
    Write (or update, with merge) a mode-600 env file. Existing keys not
    in values are kept; a password already in the file is kept too.
    """
    path = os.path.expanduser(path)
    current: Dict[str, str] = {}
    if merge and os.path.isfile(path):
        current = probe.load_env_file(path)
    current.update({k: v for k, v in values.items() if v})
    text = render_env_file(current)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def shell_snippet(env_file: str, jar: str, shell: str = "sh") -> str:
    """Lines for a shell rc so every tool and script finds the same files."""
    env_file = os.path.expanduser(env_file)
    jar = os.path.expanduser(jar)
    if shell == "powershell":
        return (
            f'$env:FERMI_SSO_ENV_FILE = "{env_file}"\n'
            f'$env:FERMI_SSO_COOKIE_FILE = "{jar}"\n'
        )
    if shell in ("csh", "tcsh"):
        return (
            f"setenv FERMI_SSO_ENV_FILE {shlex.quote(env_file)}\n"
            f"setenv FERMI_SSO_COOKIE_FILE {shlex.quote(jar)}\n"
        )
    return (
        f"export FERMI_SSO_ENV_FILE={shlex.quote(env_file)}\n"
        f"export FERMI_SSO_COOKIE_FILE={shlex.quote(jar)}\n"
    )


def scheduler_snippet(env_file: str, jar: str, system: Optional[str] = None, interval_minutes: int = 30) -> str:
    """
    A recipe for running ``fermi-sso-jar refresh`` unattended on this
    platform: crontab (Linux), launchd (macOS) or schtasks (Windows).
    Refresh only logs in when something is stale, so a frequent timer is
    cheap and never trips the sign-on throttle.
    """
    system = system or platform.system()
    exe = _tool_path("fermi-sso-jar")
    cmd = f"{exe} refresh -n -q --env-file {os.path.expanduser(env_file)} -c {os.path.expanduser(jar)}"
    if system == "Darwin":
        label = "gov.fnal.fermi-sso-jar.refresh"
        plist = os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")
        args = "\n".join(f"        <string>{a}</string>" for a in shlex.split(cmd))
        return (
            f"# macOS launchd agent. Write this to {plist}\n"
            f"# then: launchctl load {plist}\n"
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            f"    <key>Label</key><string>{label}</string>\n"
            f"    <key>ProgramArguments</key>\n    <array>\n{args}\n    </array>\n"
            f"    <key>StartInterval</key><integer>{interval_minutes * 60}</integer>\n"
            "    <key>StandardOutPath</key><string>/tmp/fermi-sso-jar.log</string>\n"
            "    <key>StandardErrorPath</key><string>/tmp/fermi-sso-jar.log</string>\n"
            "</dict>\n</plist>\n"
        )
    if system == "Windows":
        return (
            "# Windows Task Scheduler, run from PowerShell:\n"
            f'schtasks /Create /SC MINUTE /MO {interval_minutes} /TN "fermi-sso-jar refresh" '
            f'/TR "{cmd}"\n'
        )
    return (
        "# crontab entry (crontab -e). Refresh exits quietly when nothing is stale.\n"
        f"*/{interval_minutes} * * * * {cmd} >> /tmp/fermi-sso-jar.log 2>&1\n"
    )


def _tool_path(name: str) -> str:
    """The console script next to this interpreter, else the bare name."""
    bindir = os.path.dirname(sys.executable)
    for candidate in (name, name + ".exe"):
        path = os.path.join(bindir, candidate)
        if os.path.isfile(path):
            return path
    return name


# --------------------------------------------------------------------------
# text output
# --------------------------------------------------------------------------


def format_status_table(statuses: List[SiteStatus], utc: bool = False) -> str:
    header = ("SITE", "STATE", "COOKIES", "EXPIRES", "CONNECTION", "NAME")
    rows = []
    for s in statuses:
        exp = s.expiry_text
        if s.expires is not None and s.state != "expired":
            exp += f" ({format_timestamp(s.expires, utc)})"
        rows.append((s.key, s.state, str(s.cookies), exp, s.connection or "-", s.name))
    widths = [max(len(r[i]) for r in rows + [header]) for i in range(len(header) - 1)]
    lines = []
    for row in [header] + rows:
        cells = [row[i].ljust(widths[i]) for i in range(len(widths))] + [row[-1]]
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines) + "\n"


def status_json(mgr: JarManager, statuses: List[SiteStatus], now: float) -> Dict:
    return {
        "jar": mgr.jar,
        "exists": os.path.isfile(mgr.jar),
        "generated": int(now),
        "margin": mgr.margin,
        "sites": [
            dict(
                s._asdict(),
                remaining=None if s.remaining is None else int(s.remaining),
                stale=s.state in ("absent", "expired", "soon"),
            )
            for s in statuses
        ],
        "unclaimed": [
            {"domain": r["domain"], "name": r["name"], "state": r["state"]}
            for r in mgr.unclaimed(now)
        ],
    }


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def add_common_options(parser: argparse.ArgumentParser):
    g = parser.add_argument_group("files")
    g.add_argument(
        "-c", "--cookie-file", metavar="FILE", default=None,
        help=f"the jar (${probe.ENV_COOKIE_FILE}; default {DEFAULT_JAR})",
    )
    g.add_argument(
        "--cookie-format", choices=COOKIE_FORMATS, default=None,
        help=f"jar format (${probe.ENV_COOKIE_FORMAT}; default: detect)",
    )
    g.add_argument(
        "-e", "--env-file", metavar="FILE", default=None,
        help=f"settings file (default: ./.env, then {DEFAULT_ENV_FILE})",
    )
    g.add_argument("--no-env-file", action="store_true", help="ignore env files")
    g.add_argument(
        "-S", "--sites-file", metavar="FILE", action="append", default=[],
        help=f"extra site catalog, merged after {USER_SITES_FILE} and "
        f"${ENV_SITES_FILE}; repeatable",
    )
    g.add_argument(
        "--no-builtin-sites", action="store_true",
        help="start from an empty catalog instead of the built-in sites",
    )
    g.add_argument(
        "--margin", metavar="SECONDS", type=int, default=None,
        help=f"cookies expiring within SECONDS count as stale "
        f"(${ENV_MARGIN}; default {DEFAULT_MARGIN})",
    )
    g.add_argument(
        "--idp-host", default=None,
        help=f"identity provider host (${probe.ENV_IDP_HOST}; default {DEFAULT_IDP_HOST})",
    )


def add_credential_options(parser: argparse.ArgumentParser):
    g = parser.add_argument_group("credentials")
    g.add_argument("-u", "--user", default=None, help=f"account (${probe.ENV_USER}, then $USER)")
    g.add_argument(
        "-p", "--password", default=None,
        help="password. WARNING: visible in ps(1); prefer --password-env, "
        "the env file, or the prompt",
    )
    g.add_argument(
        "--password-env", metavar="NAME", default=None,
        help=f"read the password from $NAME (default ${probe.ENV_PASSWORD})",
    )
    g.add_argument(
        "-a", "--auth", choices=AUTH_METHODS, default=None,
        help=f"password (default), kerberos, or yubikey (${probe.ENV_AUTH})",
    )
    g.add_argument(
        "--pin-source", metavar="FILE", default=None,
        help=f"YubiKey PIV PIN file, mode 600 (${probe.ENV_PIN_SOURCE})",
    )
    g.add_argument(
        "-n", "--no-prompt", action="store_true",
        help="never prompt for a password (cron, CI)",
    )
    g.add_argument(
        "--no-save-cookies", action="store_true", help="load the jar but never rewrite it"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fermi_sso_jar",
        description="Pre-prime and maintain a cookie jar holding live sessions "
        "for the Fermilab SSO sites in the catalog.",
        epilog="Settings resolve as: commandline > environment > .env file > "
        "catalog settings > defaults. See fermi_sso_jar(1).",
    )
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument(
        "-d", "--debug", action="store_true", default=None,
        help=f"wire-level debug logging (${probe.ENV_DEBUG}=1)",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("status", help="show what the jar holds per site (default)")
    add_common_options(p)
    p.add_argument("sites", nargs="*", metavar="SITE", help="limit to these site keys")
    p.add_argument("-j", "--json", action="store_true", help="JSON on stdout")
    p.add_argument("--utc", action="store_true", help="UTC timestamps")
    p.add_argument("-q", "--quiet", action="store_true", help="only the table")
    p.add_argument(
        "--cookies", action="store_true",
        help="also list the individual cookies, grouped by site",
    )
    p.add_argument(
        "--stale", action="store_true",
        help="exit 1 if any site is absent, expired or expiring soon",
    )

    p = sub.add_parser("prime", help="log in to sites and save their cookies to the jar")
    add_common_options(p)
    add_credential_options(p)
    p.add_argument("sites", nargs="*", metavar="SITE", help="site keys; none means --all")
    p.add_argument("--all", action="store_true", help="every enabled site in the catalog")
    p.add_argument("-q", "--quiet", action="store_true", help="one line per site")

    p = sub.add_parser(
        "refresh",
        help="prime only the sites whose cookies are absent, expired or expiring",
    )
    add_common_options(p)
    add_credential_options(p)
    p.add_argument("sites", nargs="*", metavar="SITE", help="consider only these sites")
    p.add_argument(
        "--verify", action="store_true",
        help="also network-check sites holding only session cookies, and "
        "re-login to those that no longer sign in",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing when nothing was stale")

    p = sub.add_parser("verify", help="network-check, cookies only, that the jar signs in")
    add_common_options(p)
    p.add_argument("sites", nargs="*", metavar="SITE", help="site keys; none means all")
    p.add_argument("-q", "--quiet", action="store_true", help="one line per site")

    p = sub.add_parser("clear", help="remove sites' cookies from the jar")
    add_common_options(p)
    p.add_argument("sites", nargs="*", metavar="SITE")
    p.add_argument("--idp", action="store_true", help="also drop the identity provider's cookies")
    p.add_argument("--expired", action="store_true", help="drop every expired cookie")
    p.add_argument("--all", action="store_true", help="every catalog site (keeps unknown cookies)")

    p = sub.add_parser("sites", help="list, show, add, or remove catalog entries")
    add_common_options(p)
    ssub = p.add_subparsers(dest="sites_command", metavar="ACTION")
    sp = ssub.add_parser("list", help="one line per site")
    sp.add_argument("-j", "--json", action="store_true")
    sp = ssub.add_parser("show", help="every field of the named sites")
    sp.add_argument("sites", nargs="+", metavar="SITE")
    sp = ssub.add_parser("add", help=f"add or replace an entry in {USER_SITES_FILE}")
    sp.add_argument("key", help="short key: lowercase, digits, '.', '_', '-'")
    sp.add_argument("url", help="the site's SSO entry URL (https)")
    sp.add_argument("--name", default=None, help="human label")
    sp.add_argument("-x", "--expect", default=None, help="text required on the final page")
    sp.add_argument(
        "-D", "--domain", action="append", default=[],
        help="cookie domain of the site session (default: the URL's host); repeatable",
    )
    sp.add_argument("--connection", choices=("saml", "oidc"), default=None)
    sp.add_argument(
        "--auth", action="append", default=[], choices=AUTH_METHODS,
        help="auth methods known to work; repeatable",
    )
    sp.add_argument("--js-redirect", action="store_true", help="follow a JavaScript location= stub")
    sp.add_argument("--notes", default="")
    sp.add_argument("--file", default=None, help=f"catalog file to write (default {USER_SITES_FILE})")
    sp.add_argument(
        "--test", action="store_true",
        help="after writing, run verify on the new entry",
    )
    sp = ssub.add_parser("remove", help="remove a user entry, or hide a built-in one")
    sp.add_argument("key")
    sp.add_argument("--file", default=None)

    p = sub.add_parser("setup", help="write the env file and show how to wire the shell and a timer")
    add_common_options(p)
    p.add_argument("-u", "--user", default=None, help="account to record")
    p.add_argument("-a", "--auth", choices=AUTH_METHODS, default=None, help="method to record")
    p.add_argument("--pin-source", default=None, help="PIN file to record (yubikey)")
    p.add_argument(
        "--store-password", action="store_true",
        help="prompt for the password and store it in the env file (mode 600)",
    )
    p.add_argument(
        "--write-env", metavar="FILE", default=None,
        help=f"env file to write (default {DEFAULT_ENV_FILE})",
    )
    p.add_argument(
        "--shell", choices=("sh", "csh", "tcsh", "powershell"), default=None,
        help="print rc lines for this shell (default: detect)",
    )
    p.add_argument(
        "--scheduler", action="store_true",
        help="print a cron/launchd/schtasks recipe for periodic refresh",
    )
    p.add_argument("--interval", type=int, default=30, help="scheduler interval, minutes")
    p.add_argument(
        "--non-interactive", action="store_true",
        help="do not ask; write what the options and environment supply",
    )
    p.add_argument("-n", "--dry-run", action="store_true", help="print the env file, write nothing")

    return parser


class _Context(NamedTuple):
    environ: Dict[str, str]
    dotenv: Dict[str, str]
    mgr: JarManager
    debug: bool


def _context(args, warn) -> _Context:
    environ = dict(os.environ)
    if getattr(args, "no_env_file", False):
        dotenv: Dict[str, str] = {}
    else:
        env_file = getattr(args, "env_file", None)
        if env_file and not os.path.isfile(os.path.expanduser(env_file)):
            raise SystemExit(f"error: env file not found: {env_file}")
        dotenv = probe.load_env_file(probe.find_env_file(env_file, environ), warn=warn)
    catalog = load_catalog(
        getattr(args, "sites_file", []), environ,
        builtin=not getattr(args, "no_builtin_sites", False),
    )
    settings = catalog.settings
    jar = probe.resolve(getattr(args, "cookie_file", None), probe.ENV_COOKIE_FILE, environ, dotenv)
    jar = jar or settings.get("cookie_file") or DEFAULT_JAR
    fmt = probe.resolve(getattr(args, "cookie_format", None), probe.ENV_COOKIE_FORMAT, environ, dotenv)
    if fmt and fmt not in COOKIE_FORMATS:
        raise SystemExit(f"error: ${probe.ENV_COOKIE_FORMAT} must be one of {COOKIE_FORMATS}")
    margin_s = probe.resolve(
        None if getattr(args, "margin", None) is None else str(args.margin),
        ENV_MARGIN, environ, dotenv,
    )
    try:
        margin = int(margin_s) if margin_s is not None else int(settings.get("margin", DEFAULT_MARGIN))
    except (TypeError, ValueError):
        raise SystemExit(f"error: ${ENV_MARGIN} must be an integer number of seconds")
    idp_host = probe.resolve(getattr(args, "idp_host", None), probe.ENV_IDP_HOST, environ, dotenv)
    idp_host = idp_host or settings.get("idp_host") or DEFAULT_IDP_HOST
    debug = args.debug if args.debug is not None else probe.resolve(None, probe.ENV_DEBUG, environ, dotenv, "") == "1"
    if debug:
        probe.enable_debug()
    mgr = JarManager(jar, catalog, fmt, margin, idp_host)
    return _Context(environ, dotenv, mgr, debug)


def _credential(args, ctx: _Context) -> Credential:
    prompt = None
    if not args.no_prompt and sys.stdin.isatty():
        def prompt():
            user = cred.user or ""
            return getpass.getpass(f"Fermilab password for {user}: ")

    cred = resolve_credential(
        ctx.environ, ctx.dotenv, ctx.mgr.catalog.settings,
        auth=args.auth, user=args.user, password=args.password,
        password_env=args.password_env, pin_source=args.pin_source, prompt=prompt,
    )
    return cred


def _print_results(results: List[PrimeResult], out, quiet: bool):
    for r in results:
        out(f"{r.key:<16} {r.summary()}")
        if not quiet and not r.error:
            out(f"{'':<16} -> {r.final_url}")


def cmd_status(args, ctx, out, warn) -> int:
    mgr = ctx.mgr
    now = time.time()
    try:
        statuses = mgr.status(args.sites, now)
    except SiteError as exc:
        warn(f"error: {exc}")
        return 2
    if args.json:
        import json

        out(json.dumps(status_json(mgr, statuses, now), indent=2))
    else:
        if not args.quiet:
            out(f"jar     : {mgr.jar}" + ("" if os.path.isfile(mgr.jar) else "  (does not exist yet)"))
            out(f"catalog : builtin" + "".join(f", {f}" for f in mgr.catalog.files))
            out(f"margin  : {format_duration(mgr.margin)}")
            out("")
        out(format_status_table(statuses, args.utc).rstrip("\n"))
        if args.cookies:
            recs = mgr.records(now)
            for s in statuses:
                mine = [r for r in recs if any(domain_matches(r["domain"], d) for d in s.domains)]
                if not mine:
                    continue
                out("")
                out(f"[{s.key}]")
                for r in mine:
                    exp = "session" if r["expires"] is None else (
                        f"expired {format_duration(-r['remaining'])} ago" if r["state"] == "expired"
                        else f"in {format_duration(r['remaining'])}"
                    )
                    out(f"  {r['domain']:<32} {r['name']:<28} {exp}")
            unclaimed = mgr.unclaimed(now)
            if unclaimed:
                out("")
                out("[not in the catalog]")
                for r in unclaimed:
                    out(f"  {r['domain']:<32} {r['name']:<28} {r['state']}")
        if not args.quiet:
            mode_warning = file_mode_warning(mgr.jar)
            if mode_warning:
                warn(mode_warning)
    if args.stale:
        return 1 if mgr.stale_keys(now) else 0
    return 0


def cmd_prime(args, ctx, out, warn) -> int:
    mgr = ctx.mgr
    keys = args.sites or [s["key"] for s in mgr.catalog.ordered()]
    if not keys:
        warn("error: the catalog is empty")
        return 2
    try:
        for k in keys:
            mgr.catalog.get(k)
        cred = _credential(args, ctx)
    except (SiteError, ValueError) as exc:
        warn(f"error: {exc}")
        return 2
    if not cred.can_login():
        warn(
            "error: nothing to log in with; give --user and a password source "
            "(--password-env, the env file, or a terminal to prompt on), or "
            "--auth kerberos|yubikey. To test the jar alone use 'verify'."
        )
        return 2
    if not args.quiet:
        warn(f"priming {len(keys)} site(s) into {mgr.jar} with {cred.describe()}")
    results = mgr.prime_many(keys, cred, save=not args.no_save_cookies)
    _print_results(results, out, args.quiet)
    return 0 if all(r.ok for r in results) and len(results) == len(keys) else 1


def cmd_refresh(args, ctx, out, warn) -> int:
    mgr = ctx.mgr
    try:
        for k in args.sites:
            mgr.catalog.get(k)
        cred = _credential(args, ctx)
    except (SiteError, ValueError) as exc:
        warn(f"error: {exc}")
        return 2
    now = time.time()
    stale = mgr.stale_keys(now)
    if args.sites:
        stale = [k for k in stale if k in args.sites]
    to_prime = list(stale)
    if args.verify:
        session_only = [
            s.key for s in mgr.status(args.sites, now)
            if s.key != IDP_KEY and s.state == "session"
        ]
        for key in session_only:
            result = mgr.verify(key)
            if not args.quiet:
                out(f"{key:<16} verify: {result.summary()}")
            if not result.ok:
                to_prime.append(key)
    if not to_prime:
        if not args.quiet:
            out("nothing to refresh: every site is live")
        return 0
    if not cred.can_login():
        warn(f"stale: {', '.join(to_prime)}; nothing to log in with (see 'prime')")
        return 1
    if not args.quiet:
        warn(f"refreshing {', '.join(to_prime)} with {cred.describe()}")
    results = mgr.prime_many(to_prime, cred, save=not args.no_save_cookies)
    _print_results(results, out, True)
    return 0 if all(r.ok for r in results) and len(results) == len(to_prime) else 1


def cmd_verify(args, ctx, out, warn) -> int:
    mgr = ctx.mgr
    keys = args.sites or [s["key"] for s in mgr.catalog.ordered()]
    try:
        results = [mgr.verify(k) for k in keys]
    except SiteError as exc:
        warn(f"error: {exc}")
        return 2
    _print_results(results, out, args.quiet)
    return 0 if all(r.ok for r in results) else 1


def cmd_clear(args, ctx, out, warn) -> int:
    mgr = ctx.mgr
    removed = 0
    keys = list(args.sites)
    if args.all:
        keys = [s["key"] for s in mgr.catalog.ordered()]
    if not keys and not args.idp and not args.expired:
        warn("error: name sites, or give --all, --idp, or --expired")
        return 2
    try:
        if keys or args.idp:
            removed += mgr.clear(keys, idp=args.idp)
        if args.expired:
            removed += mgr.purge_expired()
    except SiteError as exc:
        warn(f"error: {exc}")
        return 2
    out(f"removed {removed} cookie(s) from {mgr.jar}")
    return 0


def cmd_sites(args, ctx, out, warn) -> int:
    cat = ctx.mgr.catalog
    action = args.sites_command or "list"
    if action == "list":
        if getattr(args, "json", False):
            import json

            out(json.dumps({k: cat.sites[k] for k in sorted(cat.sites)}, indent=2))
            return 0
        for s in cat.ordered():
            out(f"{s['key']:<16} {s['connection'] or '-':<5} {s['url']}")
        return 0
    if action == "show":
        try:
            for k in args.sites:
                out(describe(cat.get(k)))
                out("")
        except SiteError as exc:
            warn(f"error: {exc}")
            return 2
        return 0
    if action == "add":
        try:
            entry = user_entry(
                args.key, args.url, name=args.name, expect=args.expect,
                domains=args.domain or None, connection=args.connection,
                auth=args.auth or None, js_redirect=args.js_redirect, notes=args.notes,
            )
            path = add_user_site(args.key, entry, args.file or USER_SITES_FILE)
        except SiteError as exc:
            warn(f"error: {exc}")
            return 2
        out(f"wrote {args.key} to {path}")
        if args.test:
            cat.merge({args.key: entry}, path)
            result = ctx.mgr.verify(args.key)
            out(f"{args.key:<16} {result.summary()}")
            return 0 if result.ok else 1
        return 0
    if action == "remove":
        try:
            path = remove_user_site(args.key, args.file or USER_SITES_FILE)
        except SiteError as exc:
            warn(f"error: {exc}")
            return 2
        out(f"updated {path}")
        return 0
    warn(f"error: unknown sites action {action!r}")
    return 2


def _detect_shell() -> str:
    if os.name == "nt":
        return "powershell"
    shell = os.path.basename(os.environ.get("SHELL", "sh"))
    return "csh" if shell in ("csh", "tcsh") else "sh"


def cmd_setup(args, ctx, out, warn, ask=None) -> int:
    """
    Record the account, method and jar path in the env file, and print the
    shell and scheduler wiring. ``ask`` is input() unless replaced (tests).
    """
    mgr = ctx.mgr
    ask = ask or (lambda prompt, default: (input(f"{prompt} [{default}]: ").strip() or default))
    interactive = not args.non_interactive and sys.stdin.isatty()
    env_path = os.path.expanduser(args.write_env or DEFAULT_ENV_FILE)

    user = probe.resolve(args.user, probe.ENV_USER, ctx.environ, ctx.dotenv, ctx.environ.get("USER", ""))
    auth = probe.resolve(args.auth, probe.ENV_AUTH, ctx.environ, ctx.dotenv, "password")
    pin = probe.resolve(args.pin_source, probe.ENV_PIN_SOURCE, ctx.environ, ctx.dotenv, "")
    jar = mgr.jar
    if interactive:
        user = ask("Fermilab services account", user)
        auth = ask(f"authentication method ({'/'.join(AUTH_METHODS)})", auth)
        if auth == "yubikey":
            pin = ask("PIV PIN file (blank: openssl prompts)", pin)
        jar = os.path.expanduser(ask("cookie jar", jar))
        env_path = os.path.expanduser(ask("env file to write", env_path))
    if auth not in AUTH_METHODS:
        warn(f"error: auth must be one of {AUTH_METHODS}")
        return 2
    values = {
        probe.ENV_USER: user,
        probe.ENV_AUTH: auth,
        probe.ENV_COOKIE_FILE: jar,
        probe.ENV_PIN_SOURCE: pin,
    }
    if args.store_password and auth == "password":
        if not sys.stdin.isatty():
            warn("error: --store-password needs a terminal to prompt on")
            return 2
        values[probe.ENV_PASSWORD] = getpass.getpass(f"Fermilab password for {user}: ")

    if args.dry_run:
        out(f"# would write {env_path}:")
        out(render_env_file({k: v for k, v in values.items() if v}).rstrip("\n"))
    else:
        write_env_file(env_path, values)
        out(f"wrote {env_path} (mode 600)")
        jar_dir = os.path.dirname(jar)
        if jar_dir and not os.path.isdir(jar_dir):
            os.makedirs(jar_dir, mode=0o700, exist_ok=True)
            out(f"created {jar_dir}")
        sites_path = os.path.expanduser(USER_SITES_FILE)
        if not os.path.isfile(sites_path):
            from fermi_sso_sites import write_sites_file

            write_sites_file(sites_path, {}, {})
            out(f"created empty site catalog {sites_path} (add sites with: fermi-sso-jar sites add KEY URL)")
    out("")
    out("# add to your shell rc so every tool and script finds the same files:")
    out(shell_snippet(env_path, jar, args.shell or _detect_shell()).rstrip("\n"))
    if args.scheduler:
        out("")
        out(scheduler_snippet(env_path, jar, interval_minutes=args.interval).rstrip("\n"))
    out("")
    out("# then prime the jar once (prompts for the password unless the env file holds it):")
    out(f"fermi-sso-jar prime --all")
    return 0


COMMANDS = {
    "status": cmd_status,
    "prime": cmd_prime,
    "refresh": cmd_refresh,
    "verify": cmd_verify,
    "clear": cmd_clear,
    "sites": cmd_sites,
    "setup": cmd_setup,
}


def main(argv=None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # "status" is the default command, and the command word may come after
    # the common options ("fermi-sso-jar -c JAR prime docdb"): argparse wants
    # it first, so hoist it.
    if not any(a in ("-h", "--help", "-V", "--version") for a in argv):
        position = next((i for i, a in enumerate(argv) if a in COMMANDS), None)
        if position is None:
            argv = ["status"] + argv
        else:
            argv = [argv[position]] + argv[:position] + argv[position + 1 :]
    args = parser.parse_args(argv)

    def warn(message):
        print(message, file=sys.stderr)

    def out(message):
        print(message)

    try:
        ctx = _context(args, warn)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            warn(exc.code)
            return 2
        raise
    except SiteError as exc:
        warn(f"error: {exc}")
        return 2
    return COMMANDS[args.command](args, ctx, out, warn)


if __name__ == "__main__":
    sys.exit(main())
