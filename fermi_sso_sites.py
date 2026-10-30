#!/usr/bin/env python3
"""
fermi_sso_sites -- the catalog of SSO-protected sites the jar tools know.

A "site" is the handful of facts needed to sign in to one service provider
and to tell afterwards whether the jar still carries its session: the SSO
entry URL (not the site root, which is usually an unprotected landing page
or a local login menu), a text expected on the page behind it, the cookie
domains that make up the site's own session, and which identity-provider
connection it uses.

The catalog is extensible. The built-in entries below are merged with, in
order, ~/.fermi_sso/sites.yaml, the files named in $FERMI_SSO_SITES_FILE
(colon separated; semicolon on Windows), and any --sites-file options. A
later file overrides an earlier entry with the same key, and an entry with
``enabled: false`` hides one. ``fermi-sso-jar sites add`` writes the user
file. The shipped config/sites.yaml is the same catalog in file form and
doubles as the schema reference; see fermi_sso_sites(5).
"""

import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from requests_fermi_sso import AUTH_METHODS
from requests_fermi_sso import __version__ as _lib_version

#: single source of truth lives in the library module
__version__ = _lib_version

ENV_SITES_FILE = "FERMI_SSO_SITES_FILE"

#: Per-user catalog, written by ``fermi-sso-jar sites add``.
USER_SITES_FILE = "~/.fermi_sso/sites.yaml"

#: Identity-provider host the built-in sites all sit behind.
DEFAULT_IDP_HOST = "pingprod.fnal.gov"

#: The two PingFederate connections. Sites on the same connection share one
#: IdP session in the jar; a login to one signs the others in silently.
CONNECTIONS = ("saml", "oidc")

#: Keys a site entry may carry, with their defaults.
SITE_FIELDS = {
    "name": None,  # human label; defaults to the key
    "url": None,  # SSO entry URL; required
    "expect": None,  # text that must appear on the final page
    "domains": None,  # cookie domains of the site session; default: URL host
    "connection": None,  # saml | oidc | None (unknown)
    "auth": None,  # auth methods known to work; default: all
    "js_redirect": False,  # follow a JavaScript location= stub (ServiceNow)
    "notes": "",
    "enabled": True,
}

#: Every site this package has been run against, with the URL that works.
#: Mirrored in config/sites.yaml; tests/test_sites.py keeps them in step.
BUILTIN_SITES: Dict[str, Dict] = {
    "docdb": {
        "name": "Mu2e DocDB",
        "url": "https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase",
        "expect": "Document",
        "domains": ["mu2e-docdb.fnal.gov"],
        "connection": "saml",
        "auth": ["password", "kerberos"],
        "notes": "The site root is unprotected; only the /cgi-bin/sso/ entry "
        "point exercises the login. The SAML connection does not offer the "
        "YubiKey adapter.",
    },
    "mu2e-shifts": {
        "name": "Mu2e shift scheduler",
        "url": "https://mu2e-shifts.fnal.gov/login/oidc?next=/",
        "expect": "Calendar",
        "domains": ["mu2e-shifts.fnal.gov"],
        "connection": "oidc",
        "notes": "The root is a local login menu; use the /login/oidc entry.",
    },
    "mu2e-talks": {
        "name": "Mu2eTalks",
        "url": "https://mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/?next=%2F",
        "expect": "Dashboard",
        "domains": ["mu2e-talks.fnal.gov"],
        "connection": "oidc",
        "notes": "django-allauth confirmation page in front of the IdP; the "
        "library submits it.",
    },
    "scd-reporting": {
        "name": "SCD Reporting",
        "url": "https://scd-reporting.fnal.gov/accounts/oidc/keycloak/login/?next=%2F",
        "expect": "Dashboard",
        "domains": ["scd-reporting.fnal.gov"],
        "connection": "oidc",
        "notes": "django-allauth, as Mu2eTalks.",
    },
    "servicenow": {
        "name": "Fermilab ServiceNow",
        "url": "https://fermi.servicenowservices.com/navpage.do",
        "expect": None,
        "domains": ["fermi.servicenowservices.com"],
        "connection": "saml",
        "auth": ["password", "kerberos"],
        "js_redirect": True,
        "notes": "Protected pages redirect to auth_redirect.do, a JavaScript "
        "jump to the IdP; js_redirect makes the jar tools follow it.",
    },
}

#: Pattern of the ``location = '...'`` assignment in a JavaScript redirect
#: stub such as ServiceNow's auth_redirect.do.
JS_LOCATION_RE = re.compile(r"location(?:\.href)?\s*=\s*['\"]([^'\"]+)", re.I)

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class SiteError(ValueError):
    """A catalog file or entry is malformed."""


# --------------------------------------------------------------------------
# normalizing entries
# --------------------------------------------------------------------------


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def normalize_site(key: str, raw: Dict, source: str = "builtin") -> Dict:
    """
    Fill in defaults and validate one entry. Returns a new dict with every
    SITE_FIELDS key present plus 'key' and 'source'.
    """
    if not isinstance(raw, dict):
        raise SiteError(f"{source}: site {key!r} must be a mapping")
    if not _KEY_RE.match(key):
        raise SiteError(
            f"{source}: site key {key!r} must be lowercase letters, digits, "
            f"'.', '_' or '-' and start with a letter or digit"
        )
    unknown = set(raw) - set(SITE_FIELDS)
    if unknown:
        raise SiteError(f"{source}: site {key!r} has unknown fields {sorted(unknown)}")
    site = dict(SITE_FIELDS)
    site.update(raw)
    site["key"] = key
    site["source"] = source
    if not site["enabled"]:
        return site
    url = site["url"]
    if not url or not isinstance(url, str) or not url.lower().startswith("https://"):
        raise SiteError(f"{source}: site {key!r} needs an https:// url")
    site["name"] = site["name"] or key
    domains = site["domains"]
    if domains is None:
        domains = [_host_of(url)]
    elif isinstance(domains, str):
        domains = [domains]
    site["domains"] = [d.lower().lstrip(".") for d in domains if d]
    if not site["domains"]:
        raise SiteError(f"{source}: site {key!r} has no cookie domains")
    conn = site["connection"]
    if conn is not None and conn not in CONNECTIONS:
        raise SiteError(
            f"{source}: site {key!r} connection must be one of {CONNECTIONS}"
        )
    auth = site["auth"]
    if auth is None:
        auth = list(AUTH_METHODS)
    elif isinstance(auth, str):
        auth = [auth]
    bad = [a for a in auth if a not in AUTH_METHODS]
    if bad:
        raise SiteError(f"{source}: site {key!r} auth methods {bad} unknown")
    site["auth"] = list(auth)
    site["js_redirect"] = bool(site["js_redirect"])
    site["notes"] = site["notes"] or ""
    if site["expect"] is not None and not isinstance(site["expect"], str):
        raise SiteError(f"{source}: site {key!r} expect must be a string")
    return site


# --------------------------------------------------------------------------
# reading catalog files
# --------------------------------------------------------------------------


def parse_sites_text(text: str, source: str = "<text>") -> Tuple[Dict, Dict[str, Dict]]:
    """
    Parse a catalog document. Returns (settings, sites) where sites maps
    key -> raw entry. YAML needs PyYAML; a document that is JSON (starts
    with '{') is read with the stdlib so the tools work without it.
    """
    head = text.lstrip()
    if not head:
        return {}, {}
    if head.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise SiteError(f"{source}: {exc}")
    else:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - depends on the venv
            raise SiteError(
                f"{source}: reading YAML needs PyYAML (pip install pyyaml), "
                f"or write the file as JSON"
            ) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SiteError(f"{source}: {exc}")
    if data is None:
        return {}, {}
    if not isinstance(data, dict):
        raise SiteError(f"{source}: top level must be a mapping")
    settings = data.get("settings") or {}
    sites = data.get("sites") or {}
    if not isinstance(settings, dict):
        raise SiteError(f"{source}: 'settings' must be a mapping")
    if not isinstance(sites, dict):
        raise SiteError(f"{source}: 'sites' must be a mapping of key -> entry")
    return settings, sites


def read_sites_file(path: str) -> Tuple[Dict, Dict[str, Dict]]:
    path = os.path.expanduser(path)
    with open(path, "r", encoding="utf-8") as handle:
        return parse_sites_text(handle.read(), path)


def candidate_files(
    explicit: Iterable[str] = (), environ: Optional[Dict[str, str]] = None
) -> List[str]:
    """
    The catalog files to merge, lowest priority first: the user file, then
    $FERMI_SSO_SITES_FILE entries, then the explicit (command line) ones.
    Missing files are kept in the list; load_catalog skips them.
    """
    environ = os.environ if environ is None else environ
    files = [USER_SITES_FILE]
    env_value = environ.get(ENV_SITES_FILE, "")
    if env_value:
        files += [p for p in env_value.split(os.pathsep) if p]
    files += list(explicit)
    return [os.path.expanduser(p) for p in files]


class Catalog:
    """
    The merged site catalog plus the ``settings`` block of the files.

    sites    key -> normalized entry (disabled ones removed)
    settings merged settings mapping, later files winning
    files    the files actually read, in order
    """

    def __init__(self):
        self.sites: Dict[str, Dict] = {}
        self.settings: Dict = {}
        self.files: List[str] = []
        self._raw: Dict[str, Dict] = {}

    def merge(self, raw_sites: Dict[str, Dict], source: str):
        for key, entry in raw_sites.items():
            if entry is None:
                entry = {"enabled": False}
            if not isinstance(entry, dict):
                raise SiteError(f"{source}: site {key!r} must be a mapping")
            base = dict(self._raw.get(key, {}))
            if "enabled" in entry and not entry["enabled"]:
                merged = dict(base, enabled=False)
            else:
                merged = dict(base, **entry)
                merged["enabled"] = True
            site = normalize_site(key, merged, source)
            self._raw[key] = {k: v for k, v in merged.items() if k in SITE_FIELDS}
            if site["enabled"]:
                self.sites[key] = site
            else:
                self.sites.pop(key, None)

    def get(self, key: str) -> Dict:
        try:
            return self.sites[key]
        except KeyError:
            raise SiteError(
                f"unknown site {key!r}; known: {', '.join(sorted(self.sites)) or '(none)'}"
            )

    def for_domain(self, domain: str) -> Optional[Dict]:
        """The site owning a cookie domain, or None."""
        d = domain.lstrip(".").lower()
        for site in self.ordered():
            for sd in site["domains"]:
                if d == sd or d.endswith("." + sd):
                    return site
        return None

    def ordered(self) -> List[Dict]:
        return [self.sites[k] for k in sorted(self.sites)]


def load_catalog(
    explicit_files: Iterable[str] = (),
    environ: Optional[Dict[str, str]] = None,
    builtin: bool = True,
) -> Catalog:
    """
    Build the catalog: built-ins, then every candidate file that exists.
    An explicitly named file that is missing is an error; the user file
    and $FERMI_SSO_SITES_FILE entries are skipped silently when absent.
    """
    cat = Catalog()
    if builtin:
        cat.merge(BUILTIN_SITES, "builtin")
    explicit = [os.path.expanduser(p) for p in explicit_files]
    for path in candidate_files(explicit, environ):
        if not os.path.isfile(path):
            if path in explicit:
                raise SiteError(f"sites file not found: {path}")
            continue
        settings, sites = read_sites_file(path)
        cat.merge(sites, path)
        cat.settings.update(settings)
        cat.files.append(path)
    return cat


# --------------------------------------------------------------------------
# writing the user catalog
# --------------------------------------------------------------------------


def dump_sites_text(settings: Dict, sites: Dict[str, Dict]) -> str:
    """Serialize a catalog document as YAML (or JSON without PyYAML)."""
    doc = {}
    if settings:
        doc["settings"] = settings
    doc["sites"] = sites
    try:
        import yaml
    except ImportError:  # pragma: no cover
        return json.dumps(doc, indent=2) + "\n"
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)


def write_sites_file(path: str, settings: Dict, sites: Dict[str, Dict]):
    """Write a catalog file, creating its directory, mode 600."""
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    text = dump_sites_text(settings, sites)
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


def user_entry(
    key: str,
    url: str,
    name: Optional[str] = None,
    expect: Optional[str] = None,
    domains: Optional[List[str]] = None,
    connection: Optional[str] = None,
    auth: Optional[List[str]] = None,
    js_redirect: bool = False,
    notes: str = "",
) -> Dict:
    """A minimal raw entry for the user file: only the non-default fields."""
    entry: Dict = {"url": url}
    if name:
        entry["name"] = name
    if expect:
        entry["expect"] = expect
    if domains:
        entry["domains"] = list(domains)
    if connection:
        entry["connection"] = connection
    if auth:
        entry["auth"] = list(auth)
    if js_redirect:
        entry["js_redirect"] = True
    if notes:
        entry["notes"] = notes
    normalize_site(key, entry, "new entry")  # validate before writing
    return entry


def add_user_site(key: str, entry: Dict, path: str = USER_SITES_FILE) -> str:
    """Add or replace key in the user catalog file. Returns the path."""
    path = os.path.expanduser(path)
    settings, sites = read_sites_file(path) if os.path.isfile(path) else ({}, {})
    sites[key] = entry
    write_sites_file(path, settings, sites)
    return path


def remove_user_site(key: str, path: str = USER_SITES_FILE) -> str:
    """
    Remove key from the user file. For a built-in site there is nothing to
    remove, so an ``enabled: false`` entry is written instead, which hides
    it from the merged catalog.
    """
    path = os.path.expanduser(path)
    settings, sites = read_sites_file(path) if os.path.isfile(path) else ({}, {})
    if key in BUILTIN_SITES:
        sites[key] = {"enabled": False}
    elif key in sites:
        del sites[key]
    else:
        raise SiteError(f"site {key!r} is not in {path}")
    write_sites_file(path, settings, sites)
    return path


def describe(site: Dict) -> str:
    """Multi-line human description of one entry."""
    lines = [
        f"{site['key']}: {site['name']}",
        f"  url        : {site['url']}",
        f"  expect     : {site['expect'] or '(none)'}",
        f"  domains    : {', '.join(site['domains'])}",
        f"  connection : {site['connection'] or 'unknown'}",
        f"  auth       : {', '.join(site['auth'])}",
    ]
    if site["js_redirect"]:
        lines.append("  js_redirect: yes")
    if site["notes"]:
        lines.append(f"  notes      : {site['notes']}")
    lines.append(f"  source     : {site['source']}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    for s in load_catalog(sys.argv[1:]).ordered():
        print(describe(s))
        print()
