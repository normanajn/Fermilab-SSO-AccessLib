
## Fermi SSO signon for Scripts

This is a Session subclass for the Python requests library that will let scripts sign into Fermilab SSO with a user name and password, with a Kerberos ticket, with a YubiKey's PIV certificate, or with cookies saved from an earlier login.

Basic theory:  If we go to fetch a page and get sent to the SSO pages, we choose password authentication and login and then go on to the page.
Both the SAML (`/idp/`) and OIDC (`/as/`) flavours of the Fermilab PingFederate pages are handled, as are the confirmation form django-allauth puts in front of them and the auto-submitting SAML AuthnRequest form some service providers use to reach the IdP.
Non-interactive scripts would need to request a "special account" from the authentication folks for a username and password to pass.
Alternatively the cookies from one successful login (including a browser login that passed MFA) can be saved to a file and reused until the site's session expires.

### Install

```
pip install .                # password and cookie-jar modes: requests only
pip install '.[kerberos]'    # adds requests-gssapi for --auth kerberos
```

The YubiKey mode needs system tools (OpenSSL 3, the pkcs11 engine, a PKCS#11
module); see [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

This also installs the `fermi-sso-probe` and `fermi-sso-cookies` commands. For development:

```
./bootstrap.sh          # creates venv/, installs with test extras, runs tests
```

### Library usage

```python
from requests_fermi_sso import FermiSSOSession

s = FermiSSOSession(userpass=f"{user}:{password}")
resp = s.get("https://site/page")

# A rejected login is served as the login page with status 200,
# so check the body rather than the status code.
if s.login_page_re.search(resp.text):
    raise SystemExit("SSO login failed")
```

Cookies persist on the session, so later requests skip the login round trip.

### Kerberos

With a `kinit` ticket no password is needed. Install the optional dependency
and pick the method:

```
pip install '.[kerberos]'
fermi-sso-probe -a kerberos -c ~/.fermi_sso.cookies
```

```python
s = FermiSSOSession(auth_method="kerberos")
```

The ticket must be in the **FERMI.WIN.FNAL.GOV** realm. Fermilab has two
separate Kerberos realms: the FNAL.GOV ticket a plain `kinit` gives you
(the one Vault accepts) is refused by the SSO identity provider. Without a
FERMI.WIN.FNAL.GOV ticket, use the YubiKey or a cookie jar. See the HOWTO.

### YubiKey

The FNAL Yubikey adapter is a PIV client certificate on the IdP's mutual-TLS
port. Python cannot use the token's key, so the one request that needs it is
done by `openssl s_client` with the PKCS#11 engine:

```
brew install openssl@3 libp11 yubico-piv-tool opensc ykman
fermi-sso-yubikey                                # readiness check
fermi-sso-probe -a yubikey -c ~/.fermi_sso.cookies URL   # prompts for the PIN
```

### CILogon device flow (htgettoken, Vault)

OIDC device-flow clients such as `htgettoken --headless` print a CILogon URL
and user code for a person to approve. The session can approve it instead,
with any of the methods above:

```
fermi-sso-probe -a yubikey --user-code N3X-2R4-GRR
fermi-sso-probe -a yubikey "https://cilogon.org/device/?user_code=N3X-2R4-GRR"
```

```python
from fermi_sso_yubikey import YubiKeyCertHop

s = FermiSSOSession(auth_method="yubikey", cert_hop=YubiKeyCertHop())
result = s.approve_cilogon_device("N3X-2R4-GRR")   # or the full URL
if not result.ok:
    raise SystemExit("; ".join(result.reasons))
```

The walk is CILogon's identity-provider page (which is also the consent to
release attributes to the client named on it), Fermilab's Shibboleth proxy
`idpext.fnal.gov`, the usual pingprod choose and login pages, and the SAML
postbacks back to CILogon. `cilogon_idp=` selects an identity provider other
than Fermilab. Approving a request is a sign-on in your name: only pass codes
from clients you started yourself.

### Reusing cookies across runs

Pass `cookie_file` and the jar is loaded before the first request and saved
after each completed login. A later process needs no password:

```python
# once, or whenever the saved session has expired
FermiSSOSession(userpass=f"{user}:{password}", cookie_file="~/.fermi_sso.cookies").get(url)

# afterwards
s = FermiSSOSession(cookie_file="~/.fermi_sso.cookies")
resp = s.get(url)
```

The identity provider's session cookie is saved too, so one jar typically
covers every site behind Fermilab SSO: log in to one, and the others sign in
through a bare redirect chain.

The file may also be a browser's exported `cookies.txt`, which is the only
way to use an MFA-enrolled account: log in once in the browser, export the
cookies, and hand them to the session. Netscape `cookies.txt`, LWP, and
JSON formats are read and written; see `man ./man/FermiSSOSession.3`.
The jar holds live session cookies, so it is written mode 600 and should be
treated like a password.

### Checking that a login works

`fermi-sso-probe` fetches an SSO-protected URL and reports whether the login
actually completed. It defaults to the Mu2e DocDB entry point; pass any other
URL to check a different site.

```
fermi-sso-probe -u myaccount
fermi-sso-probe -u myaccount -x "Welcome" https://other-site.fnal.gov/private
```

Credentials come from the command line, the environment, or a `.env` file, in
that order of priority; failing all three it prompts. Copy `env.example` to
`.env` or `~/.fermi_sso.env` to set them up. Exit status is 0 on success, 1
on a failed login, 2 on a usage error.

With `-c FILE` the probe keeps its cookies between runs. The first run logs
in with a password and writes the jar; later runs need neither:

```
fermi-sso-probe -u myaccount -c ~/.fermi_sso.cookies
fermi-sso-probe -c ~/.fermi_sso.cookies -n -q
```

`fermi-sso-cookies` shows what a jar holds without touching the network:
every cookie with its domain, path, expiry and flags, expired ones included.
Values are masked unless `-s` is given.

```
fermi-sso-cookies ~/.fermi_sso.cookies
fermi-sso-cookies -D pingprod.fnal.gov -l ~/.fermi_sso.cookies   # is the IdP session still live?
```

### Claude Code skills

`claude-skills/` holds two Claude Code skills: `fermi-sso` (running the
tools, diagnosing logins) and `fermi-sso-embed` (using `FermiSSOSession` in
another project). Install them at user level so every session sees them:

```
./install-claude-skills.sh          # ${CLAUDE_CONFIG_DIR:-~/.claude}
./install-claude-skills.sh -a       # every ~/.claude* config dir
./install-claude-skills.sh -l       # symlink instead of copy
.\install-claude-skills.ps1 -All    # Windows
```

See `man ./man/install-claude-skills.sh.1`.

### Documentation

- [docs/EXAMPLES.md](docs/EXAMPLES.md) — copy-paste recipes for DocDB, the shift scheduler, Mu2eTalks, ServiceNow, Kerberos, the YubiKey, and CILogon device codes
- [docs/HOWTO.md](docs/HOWTO.md) — install, credentials, troubleshooting
- [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) — external dependencies per authentication method, with install commands per platform
- `examples/` — small hand-run scripts; start with `check_cdcvs_login.py`
- `man ./man/bootstrap.sh.1` — the bootstrap script
- `man ./man/install-claude-skills.sh.1` — the Claude Code skills installer
- `man ./man/fermi_sso_probe.1` — the probe utility
- `man ./man/fermi_sso_cookies.1` — the cookie jar inspector
- `man ./man/FermiSSOSession.3` — the library API

### Tests

```
python -m pytest tests/
```

The suite runs offline against a scripted transport adapter that serves
captured copies of the real identity provider pages, so no network access or
credentials are needed.

### Limitations

Four adapters are driven: the `ad..FormBased` password adapter, the Kerberos
adapter under whichever id the connection offers it, and the FNAL Yubikey and
HSPD-12 hardware-token adapters. An interactive second factor is not among
them — an account enrolled in MFA cannot complete the password flow itself, so
that is what the "special account" above is for, or else a browser login whose
cookies are exported and passed in via `cookie_file`. PingFederate's RSA
SecurID form is recognized and reported, not answered.

On CILogon only the user-code and identity-provider forms are answered, and
a Shibboleth attribute-release consent page, if one is ever shown, is not.
A CILogon approval is reported as successful when CILogon shows no error;
the device-flow client's token poll is the final word.

Saved cookies last only as long as the site's session; expiry shows up as a
login page, not an error. Page recognition is regex-based and will break if
the identity provider changes its markup. Only HTML responses under 2 MB are
inspected for login forms, so a protected download that is served without an
intervening login page is passed through untouched. Sessions hold per-login
state and are not thread-safe.
