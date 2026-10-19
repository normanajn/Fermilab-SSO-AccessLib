---
name: fermi-sso-embed
description: Add Fermilab SSO login to another project's code with the requests-fermi_sso package (FermiSSOSession, a requests.Session subclass) — pip dependency pinned to a git tag, YAML/env configuration of the credential source (password, Kerberos, YubiKey PIV, cookie jar), correct login-success checks via fermi_sso_probe.classify, cookie-jar reuse, threading rules, and offline tests. Use when the user wants a Python script, daemon, web backend, CI job or tool to fetch pages or APIs behind Fermilab SSO (pingprod.fnal.gov), approve CILogon OIDC device-flow codes (e.g. driving htgettoken --headless or another Vault/CILogon device client unattended), or asks how to depend on or call requests_fermi_sso from another codebase.
---

Canonical source: `$FERMI_SSO_HOME` (default
`~/Git-Repositories/Norman/Fermi-SSO-AccessLib`). Before writing
integration code, read `man/FermiSSOSession.3`, `docs/EXAMPLES.md`
(live-verified per-site recipes) and the "Using the session in your own
code" section of `docs/HOWTO.md`. Copy from them; do not improvise.
The library is Python only. For C/C++ hosts, run `fermi-sso-probe -o`
as a subprocess, or use a Python helper that writes the cookie jar,
which libcurl can then read (`CURLOPT_COOKIEFILE`, Netscape format).

## Dependency

The GitHub repo `normanajn/Fermi-SSO-AccessLib` is **private**, so
consumers need GitHub SSH or token access. Pin a tag, never `main`. Tags
have no `v` prefix (for example `0.2.0`). List them with
`git ls-remote --tags git@github.com:normanajn/Fermi-SSO-AccessLib.git`.

```
# requirements.txt
requests-fermi_sso @ git+ssh://git@github.com/normanajn/Fermi-SSO-AccessLib.git@0.2.0
# with Kerberos support
requests-fermi_sso[kerberos] @ git+ssh://git@github.com/normanajn/Fermi-SSO-AccessLib.git@0.2.0
```

Python >= 3.9. Runtime dependency is `requests` only. The `kerberos` extra
adds `requests-gssapi`. YubiKey mode needs OpenSSL 3, libp11, and a
PKCS#11 module at the system level (`docs/DEPENDENCIES.md`).

## API in one screen

```python
from requests_fermi_sso import FermiSSOSession
import fermi_sso_probe

s = FermiSSOSession(
    userpass=f"{user}:{password}",   # password mode only; no ':' in password
    auth_method="password",          # "password" | "kerberos" | "yubikey"
    cookie_file="~/.fermi_sso.cookies",  # loaded at init (missing OK), saved after each login
    cookie_format=None,              # "netscape" | "lwp" | "json" | None = detect
    cookie_save=True,                # default True when cookie_file given
)
r = s.get(url)
ok, reasons = fermi_sso_probe.classify(s, r, idp_host="pingprod.fnal.gov", expect="Dashboard")
```

- Kerberos: `auth_method="kerberos"`. This uses the local ticket cache;
  `spnego_auth=` overrides the handler.
- YubiKey: `auth_method="yubikey", cert_hop=fermi_sso_yubikey.YubiKeyCertHop(pin_source=...)`.
  Without `cert_hop` the constructor raises `ValueError`. It works on OIDC
  sites only (DocDB's SAML connection does not offer it), and it needs a TTY
  or a PIN file. `YubiKeyCertHop` is a context manager; `close()` removes
  its temp dir.
- Cookies only: pass `cookie_file` and no `userpass`. This is the route
  for MFA accounts (browser `cookies.txt` export) and for all
  non-interactive runs after the first login.
- CILogon device flow (0.3.0+): `s.approve_cilogon_device(url_or_code)`
  returns `CILogonResult(ok, reasons, response)` after walking CILogon's
  consent/IdP page, idpext.fnal.gov and pingprod. `cilogon_idp=` picks a
  non-Fermilab entityID; `cilogon_user_code=` fills the bare `/device/`
  form. Check `ok`, then let the device client's poll confirm. The
  host must start the device client itself and pass on only its own code.
  Expose this as an explicit opt-in config key (`cilogon_device: true`),
  since it signs on in the user's name.
- Explicit `s.load_cookies(path, fmt=None, missing_ok=False)` and
  `s.save_cookies(path, fmt=None)` are available. Session counters:
  `s.login_count`, `s.cookies_loaded`.
- Errors: `ValueError` for bad arguments or an unparseable jar,
  `ImportError` if Kerberos is requested without `requests-gssapi`, and
  ordinary `requests.RequestException` for network problems. **A rejected
  login does not raise.** It returns the IdP login page with status 200.

## Rules for the integration code

1. **Always verify the login.** Call `fermi_sso_probe.classify()` (or at
   minimum `s.login_page_re.search(r.text)`) on the first SSO response,
   and pass `expect=` with text known to be on the target page. Convert a
   failure into one clear error that includes `reasons`. Never treat
   `status_code == 200` as success.
2. **Configurable.** Add a `fermi_sso:` block to the host's `config/*.yaml`
   with `enabled`, `auth` (password/kerberos/yubikey/cookies), `user`,
   `cookie_file`, `cookie_format`, `url`, `expect`, `idp_host`, `timeout`.
   Reuse the package's env names so one `~/.fermi_sso.env` serves both
   the probe and the host: `FERMI_USER`, `FERMI_PASSWORD`, `FERMI_SSO_AUTH`,
   `FERMI_SSO_COOKIE_FILE`, `FERMI_SSO_COOKIE_FORMAT`, `FERMI_SSO_PIN_SOURCE`,
   `FERMI_SSO_IDP_HOST`, `FERMI_SSO_DEBUG`, and for CILogon
   `FERMI_SSO_CILOGON_IDP`. Precedence is
   CLI > env > `.env` > YAML > defaults. `fermi_sso_probe.load_env_file()`,
   `find_env_file()` and `resolve()` implement the env-file part and
   can be reused.
3. **No secrets in config or code.** Read the password only from
   `FERMI_PASSWORD` or a mode-600 env file. Prefer cookie-jar or Kerberos
   in production; a password is needed only to refresh an expired jar.
   Treat the jar as a bearer credential: mode 600, local disk, never
   committed or logged (add it to `.gitignore`).
4. **Handle jar expiry.** A dead jar shows up as a failed `classify()`, not
   as an exception. In unattended code, try cookies first. If a password
   source is configured, fall back to a password login once, which rewrites
   the jar. Otherwise, report "re-login needed" and stop. Do not retry
   in a loop: the IdP throttles ("Multiple Sign-On Delay") and repeated
   bad passwords can lock the account.
5. **Threading.** A session is not thread-safe (it keeps per-login state).
   Use one `FermiSSOSession` per thread, or serialize access with a lock.
   In daemons, log in from a daemon worker thread. In Qt, do the network
   work in a worker and return results with signals. Several sessions
   can share one jar file read-only; let only one of them save
   (`cookie_save=False` on the others).
6. **Timeouts.** Pass `timeout=` on every request (`s.get(url, timeout=30)`).
   `YubiKeyCertHop` has its own `timeout` (default 180 s) that covers
   PIN entry.
7. **Use the SSO entry URL** for the first request, not the site root. See
   the table in the fermi-sso skill and EXAMPLES.md. Two sites need
   special handling: ServiceNow's JavaScript redirect has to be extracted
   by hand, and Workday is unsupported (SecurID).
8. **Offline tests.** Never let a test suite log in live. Do one of the
   following:
   - Mount a scripted `requests` transport adapter on the session. Copy
     the pattern and the captured IdP page fixtures from
     `$FERMI_SSO_HOME/tests/conftest.py`.
   - Inject a fake session behind the host's own wrapper, and test that
     `enabled: false` makes no request and that a login page yields the
     wrapper's error.
9. **Document it** in the host's README and man page. Cover the config keys
   and env vars, which auth modes are supported, how to seed the cookie
   jar (`fermi-sso-probe -u USER -c JAR URL`), and what the error looks
   like when the jar has expired.

## Minimal wrapper to start from

```python
import logging
import fermi_sso_probe
from requests_fermi_sso import FermiSSOSession

log = logging.getLogger(__name__)

class SSOLoginError(RuntimeError):
    pass

def open_session(cfg, password=None):
    kw = {"cookie_file": cfg.get("cookie_file")}
    auth = cfg.get("auth", "cookies")
    if auth == "password":
        kw["userpass"] = f"{cfg['user']}:{password}"
    elif auth in ("kerberos", "yubikey"):
        kw["auth_method"] = auth
        if auth == "yubikey":
            from fermi_sso_yubikey import YubiKeyCertHop
            kw["cert_hop"] = YubiKeyCertHop(pin_source=cfg.get("pin_source"))
    s = FermiSSOSession(**kw)
    r = s.get(cfg["url"], timeout=cfg.get("timeout", 30))
    ok, reasons = fermi_sso_probe.classify(
        s, r, cfg.get("idp_host", "pingprod.fnal.gov"), cfg.get("expect"))
    if not ok:
        raise SSOLoginError("; ".join(reasons))
    log.info("SSO login ok: %s (logins=%d)", r.url, s.login_count)
    return s
```

## Verify before handing over

- `pip install` of the pinned tag works in a clean venv.
- Offline tests cover success, a login-page response (the error must
  include the reasons), and `enabled: false`.
- One live check with the user's jar:
  `fermi-sso-probe -c ~/.fermi_sso.cookies -n -x TEXT URL` exits 0 before
  the host code is pointed at the same URL. Password or PIN runs are the
  user's to execute (`! ...`).
