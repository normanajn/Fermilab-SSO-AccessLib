# HOWTO: Authenticating to Fermilab SSO from a Script

This guide covers installing `requests-fermi-sso`, supplying credentials,
verifying a login with the `fermi_sso_probe` utility, and using the session
in your own code.

- [What this package does](#what-this-package-does)
- [Install](#install)
- [Quick start](#quick-start)
- [Supplying credentials](#supplying-credentials)
- [Verifying a login with fermi_sso_probe](#verifying-a-login-with-fermi_sso_probe)
- [Using the session in your own code](#using-the-session-in-your-own-code)
- [Choosing the right URL](#choosing-the-right-url)
- [Running the tests](#running-the-tests)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## What this package does

`FermiSSOSession` is a `requests.Session` subclass. It overrides `send()`, so
every response is checked before you see it. If the response is part of the
Fermilab PingFederate single sign-on sequence, the session answers it and
keeps going, and you get the protected page back instead of a login form.

The sequence it walks:

```
your GET  ->  service provider  ->  303 redirect to pingprod.fnal.gov
                                          |
                                    choose-auth page      (pick "Services Username and Password")
                                          |
                                    login form            (POST pf.username / pf.pass)
                                          |
                                    SAML postback form    (POST RelayState + SAMLResponse)
                                          |
                                    the page you asked for
```

There is no `login()` call. You construct the session with credentials and
use it like any other `requests.Session`; the first request that hits a
protected resource triggers the flow, and the resulting cookies make every
later request go straight through.

## Install

Requires Python 3.6+ and `requests`.

```bash
git clone <this repo>
cd requests-fermi-sso

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install .
```

For development, install editable with the test extras:

```bash
pip install -e ".[test]"
```

Installing also puts the `fermi-sso-probe` command on your `PATH`.

### Manual pages

The manpages are not installed by `pip` in a virtualenv. To read them from
the source tree:

```bash
man ./man/fermi_sso_probe.1     # the probe utility
man ./man/FermiSSOSession.3     # the library API
```

To install them system-wide:

```bash
sudo install -m 644 man/fermi_sso_probe.1 /usr/local/share/man/man1/
sudo install -m 644 man/FermiSSOSession.3 /usr/local/share/man/man3/
```

## Quick start

Check that SSO works for your account, against the Mu2e DocDB:

```bash
fermi-sso-probe -u myaccount
```

You will be prompted for your password (not echoed). On success:

```
RESULT: login SUCCEEDED
  landed on https://mu2e-docdb.fnal.gov/cgi-bin/DocDB/DocumentDatabase
```

## Supplying credentials

Four sources are supported. They resolve highest priority first:

| Priority | Source | Username | Password |
|---|---|---|---|
| 1 | command line | `-u NAME` | `-p PASSWORD` |
| 2 | environment | `$FERMI_USER` | `$FERMI_PASSWORD`, or `--password-env NAME` |
| 3 | env file | `FERMI_USER=` | `FERMI_PASSWORD=` |
| 4 | default | `$USER` | interactive prompt |

An environment variable set to the empty string counts as absent.

### Command line

```bash
fermi-sso-probe -u myaccount -p 'mypassword'
```

Fastest for a one-off, with a real caveat: command lines are visible to every
user on the machine via `ps`, and your shell writes them to its history file.
Prefixing the command with a space avoids the history file in `bash` and
`zsh` (with `HIST_IGNORE_SPACE`), but does nothing about `ps`. Use one of the
options below for anything you run more than once.

### Environment variables

```bash
export FERMI_USER=myaccount
read -rs FERMI_PASSWORD && export FERMI_PASSWORD   # prompts without echo
fermi-sso-probe
```

Or point at a differently-named variable, which is useful when a CI system
already injects one:

```bash
fermi-sso-probe -u myaccount --password-env CI_FERMI_SECRET
```

### Env file

Create `.env` in the working directory, or `~/.fermi_sso.env` for a
per-user default. Copy `env.example` from the repo as a starting point:

```bash
cp env.example ~/.fermi_sso.env
chmod 600 ~/.fermi_sso.env
$EDITOR ~/.fermi_sso.env
```

Contents:

```ini
FERMI_USER=myaccount
FERMI_PASSWORD=mypassword
FERMI_SSO_URL=https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

Syntax notes:

- `KEY=value`, one per line
- blank lines and `#` comments are ignored
- a leading `export ` is stripped, so the file can also be `source`d
- values may be single- or double-quoted; quotes are removed
- **quote any value containing `#`**, or the rest of the line is treated as a
  comment
- `=` inside a value is fine, so URLs with query strings need no quoting

Because the file holds a password, the probe warns if it is readable by
group or other. Keep it at mode 600.

Then simply:

```bash
fermi-sso-probe
```

Use `--env-file PATH` to point somewhere else, or `--no-env-file` to ignore
env files entirely — worth doing in cron and CI so a stray `.env` in the
working directory cannot change behavior.

### Interactive prompt

If nothing supplies a password and stdin is a terminal, you are prompted.
Pass `-n` / `--no-prompt` to fail instead, which is what you want in
automation. The prompt is skipped automatically when stdin is not a tty.

## Verifying a login with fermi_sso_probe

The probe exists because **a successful HTTP status does not mean a
successful login**. When credentials are rejected, PingFederate re-serves its
login page with status 200. Code that checks `resp.status_code` sees success
and then parses a login form as if it were data.

The probe declares success only when all of these hold:

- the final URL is off the identity provider host
- the body matches none of the choose-auth, login-form, or postback patterns
- the `--expect` text is present, if given

Common invocations:

```bash
# default target (Mu2e DocDB), prompt for password
fermi-sso-probe -u myaccount

# any other protected URL, positionally or with -U
fermi-sso-probe -u myaccount https://some-site.fnal.gov/private
fermi-sso-probe -u myaccount -U https://some-site.fnal.gov/private

# require known text on the page, not just a completed login
fermi-sso-probe -u myaccount -x "Document Database"

# save the page and the full wire trace separately
fermi-sso-probe -u myaccount -d -o /tmp/page.html 2> /tmp/trace.log

# non-interactive, for cron
fermi-sso-probe --env-file ~/.fermi_sso.env -n -q
```

Exit codes: `0` success, `1` login failed or `--expect` missing, `2` usage
error. Diagnostics go to stderr and the page body to stdout (with `-o -`), so
you can pipe the body without the noise.

Behind a different identity provider, override the host used for the
stall check:

```bash
fermi-sso-probe --idp-host idp.example.org https://elsewhere.example.org/private
```

Set `--idp-host ''` to disable that check.

## Using the session in your own code

```python
from requests_fermi_sso import FermiSSOSession

s = FermiSSOSession(userpass=f"{user}:{password}")

r = s.get("https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase")

# The status code will be 200 even if the login failed. Check explicitly.
if s.login_page_re.search(r.text):
    raise SystemExit("SSO login failed: bad password, or MFA is required")

# Cookies persist; subsequent requests skip the login round trip.
r2 = s.get("https://mu2e-docdb.fnal.gov/cgi-bin/DocDB/ShowDocument?docid=1234")
```

To reuse the probe's own check rather than writing your own:

```python
import fermi_sso_probe

ok, reasons = fermi_sso_probe.classify(s, r, idp_host="pingprod.fnal.gov")
if not ok:
    raise SystemExit("login failed: " + "; ".join(reasons))
```

`FermiSSOSession` keeps in-flight login state on the instance, so **do not
share one session across threads**. Construct one per thread.

## Choosing the right URL

Point at a URL that is actually protected. `https://mu2e-docdb.fnal.gov/` is
an unprotected landing page — fetching it returns HTML without ever touching
the identity provider, so it tells you nothing about whether SSO works. The
SSO entry point is:

```
https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

which is the probe's default. For other sites, look for a path containing
`/sso/`, or any URL that redirects you to `pingprod.fnal.gov` in a browser.

## Running the tests

```bash
pip install -e ".[test]"
python -m pytest tests/ -q
```

The suite runs offline. It mounts a scripted transport adapter on the session
that serves canned copies of the real IdP pages, so the actual `send()` logic
is exercised end to end without network access or credentials.

Coverage is in two parts:

- `tests/test_fermi_sso_session.py` — page recognition, URL construction, and
  the full four-request login walk
- `tests/test_probe_config.py` — env-file parsing, the precedence chain, the
  success classifier, and `main()` exit codes

The HTML fixtures in `tests/conftest.py` reproduce the live markup captured
2026-08-18, including attribute order and the upper/lowercase of each form's
`method`. That casing matters: the choose-auth and login pages are told apart
only by `method="GET"` versus `method="POST"`, and the postback form is
distinguished by its lowercase `method="post"`. If the IdP changes its markup,
these fixtures are the place to update.

## Troubleshooting

Run with `-d` to see the full exchange. Diagnostics from the probe:

**`still on the login form`** — the password was rejected, or the account
requires MFA. See [Limitations](#limitations). Verify the password by logging
in at <https://pingprod.fnal.gov/> in a browser.

**`still on the choose-authentication page`** — the IdP did not accept the
password-adapter selection. The adapter id may have changed; the library
hardcodes `ad..FormBased`. Fetch the choose page and look at the
`<option value="...">` entries in the `pfidpadapterid` select.

**`stopped on the SAML postback form`** — authentication worked but the
assertion was not posted back. Usually a service-provider-side problem.

**`stranded on pingprod.fnal.gov`** — the flow ended on the IdP at a page the
library does not recognize, such as an error or consent interstitial. Dump it
with `-o /tmp/page.html` and read it.

**`password contains ':'`** — `FermiSSOSession` packs credentials as
`"user:pass"` and splits on every colon, so a colon in the password cannot be
represented. The library raises `ValueError`; the probe catches it early and
says so. Use an account whose password has no colon.

**`env file not found`** — an explicit `--env-file` path does not exist. The
probe treats this as an error rather than silently falling through, so a typo
does not turn into a confusing prompt.

**Everything looks right but the page is wrong** — the login completed and
landed somewhere unexpected. Add `-x` with text you know is on the target
page to catch this.

## Limitations

**MFA is not supported.** The library drives only the `ad..FormBased`
adapter — the IdP's "a. Services Username and Password" option. There is no
path for a second factor, so an account enrolled in MFA will loop back to the
login form. Non-interactive scripts generally need a *service account*
provisioned for password authentication; request one through the Service
Desk. The DocDB landing page also links instructions for applying for
DocDB access.

**Kerberos and certificate auth are not supported.** The IdP offers
`ad..KrbOrForm`, `ad..KrbOrFormForWin`, and a CILogon certificate option;
this package selects none of them.

**Page recognition is regex-based.** The library matches raw HTML with
regular expressions that are sensitive to attribute order, quoting, and
case. An IdP markup change presents as a login failure, not a parse error.

**Sessions are not thread-safe.** The `logging_in_already` recursion guard is
per-instance mutable state. Use one session per thread.
