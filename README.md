
## Fermi SSO signon for Scripts

This is a Session subclass for the Python requests library that will let scripts sign into Fermilab SSO with a user name and password.

Basic theory:  If we go to fetch a page and get sent to the SSO pages, we choose password authentication and login and then go on to the page.
Non-interactive scripts would need to request a "special account" from the authentication folks for a username and password to pass.

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
MFA cannot complete this flow — that is what the "special account" above is
for. Page recognition is regex-based and will break if the identity provider
changes its markup. Sessions hold per-login state and are not thread-safe.
