
## Fermi SSO signon for Scripts

This is a Session subclass for the Python requests library that will let scripts sign into Fermilab SSO with a user name and password, or with cookies saved from an earlier login.

Basic theory:  If we go to fetch a page and get sent to the SSO pages, we choose password authentication and login and then go on to the page.
Non-interactive scripts would need to request a "special account" from the authentication folks for a username and password to pass.
Alternatively the cookies from one successful login (including a browser login that passed MFA) can be saved to a file and reused until the site's session expires.

### Install

```
pip install .
```

This also installs the `fermi-sso-probe` command. For development:

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

### Documentation

- [docs/HOWTO.md](docs/HOWTO.md) — install, credentials, troubleshooting
- `man ./man/fermi_sso_probe.1` — the probe utility
- `man ./man/FermiSSOSession.3` — the library API

### Tests

```
python -m pytest tests/
```

The suite runs offline against a scripted transport adapter that serves
captured copies of the real identity provider pages, so no network access or
credentials are needed.

### Limitations

Only the `ad..FormBased` password adapter is driven, so accounts enrolled in
MFA cannot complete this flow themselves — that is what the "special account"
above is for, or else a browser login whose cookies are exported and passed
in via `cookie_file`. Saved cookies last only as long as the site's session;
expiry shows up as a login page, not an error. Page recognition is regex-based
and will break if the identity provider changes its markup. Sessions hold
per-login state and are not thread-safe.
