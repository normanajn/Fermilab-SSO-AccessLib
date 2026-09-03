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

The sequence it walks (the first step only on django-allauth sites, see
[Django applications using allauth](#django-applications-using-allauth)):

```
your GET  ->  allauth "Sign in with SSO" confirmation form   (POST csrf token)
                                          |
              service provider  ->  30x redirect to pingprod.fnal.gov,
                                    or an auto-submitting SAMLRequest form (POSTed)
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
later request go straight through. Those cookies can also be saved to a file
and loaded by a later process, or imported from a browser, so that the
password step is skipped altogether; see [Reusing cookies instead of a
password](#reusing-cookies-instead-of-a-password).

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

An environment variable set to the empty string counts as absent. Two more
routes make both columns optional: a saved cookie jar (`-c FILE`,
`$FERMI_SSO_COOKIE_FILE`) and a Kerberos ticket (`-a kerberos`,
`$FERMI_SSO_AUTH`). Each has its own section below.

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
automation. The prompt is skipped automatically when stdin is not a tty, and
when a cookie file already exists (see the next section).

## Logging in with a Kerberos ticket

The identity provider offers a Kerberos adapter on both of its connections,
`ad..KrbOrForm` on SAML and `ad..kerbForm` on OIDC. With
`auth_method="kerberos"` (probe: `--auth kerberos`, or `FERMI_SSO_AUTH=`),
the library selects whichever of those the choose page lists and lets
`requests-gssapi` answer the IdP's `401 Negotiate` challenge from your
ticket cache. No username or password is involved.

```bash
pip install 'requests-fermi_sso[kerberos]'     # adds requests-gssapi
kinit
fermi-sso-probe -a kerberos -c ~/.fermi_sso.cookies
```

```python
s = FermiSSOSession(auth_method="kerberos", cookie_file="~/.fermi_sso.cookies")
```

If a connection offers no Kerberos adapter, the password adapter is selected
instead, so `auth_method="kerberos"` plus `userpass` covers both cases.

### When the challenge goes unanswered

The probe reports "the identity provider's Kerberos (Negotiate) challenge was
not answered". The cause is usually on the Kerberos side, not the HTTP side.
The IdP's principal is `HTTP/pingprod.fnal.gov` in the **FERMI.WIN.FNAL.GOV**
realm, reached from an FNAL.GOV ticket by cross-realm trust. Check it
directly:

```bash
klist                                              # a krbtgt/FNAL.GOV ticket?
kgetcred HTTP/pingprod.fnal.gov@FERMI.WIN.FNAL.GOV # can you get the service ticket?
```

Seen 2026-09-02: `klist` showed a valid FNAL.GOV ticket and a cross-realm
ticket for FERMI.WIN.FNAL.GOV, yet `kgetcred` answered **"Clients credentials
have been revoked"**. That is the Windows-realm KDC saying the account it
maps your principal to is disabled, locked, or expired; nothing in the
library can change that outcome. Requesting the principal in FNAL.GOV
instead gives `LOOKING_UP_SERVER`, because it does not exist there. The
library and probe paths were verified against a scripted IdP that issues the
same challenge; the live path is blocked until that account state is fixed.

## Logging in with a YubiKey

The "FNAL Yubikey" and "HSPD12" options on the OIDC connection are
certificate authentication: after the adapter is selected, the IdP redirects
to a mutual-TLS listener on `pingprod.fnal.gov:9032` that asks for a client
certificate, and the certificate is the one in the YubiKey's PIV
authentication slot (9A, issued by FERMI Sub CA 01). Its key never leaves the
token, so Python cannot present it. `auth_method="yubikey"` (probe:
`--auth yubikey`) therefore hands that one request to `fermi_sso_yubikey`,
which runs `openssl s_client` with the PKCS#11 engine and feeds the result
back into the session.

Setup on macOS, once:

```bash
brew install openssl@3 libp11 yubico-piv-tool opensc ykman
fermi-sso-yubikey            # readiness report; prints the openssl command
```

Then, **from a real terminal** because openssl prompts for the PIV PIN:

```bash
fermi-sso-probe -a yubikey -c ~/.fermi_sso.cookies "https://mu2e-shifts.fnal.gov/login/oidc?next=/"
```

Or put the PIN in a mode-600 file and pass `--pin-source FILE`
(`FERMI_SSO_PIN_SOURCE=`), which also works where there is no terminal.
Once the jar holds the site's session, later runs are cookies-only as usual.

```python
from fermi_sso_yubikey import YubiKeyCertHop
s = FermiSSOSession(auth_method="yubikey", cert_hop=YubiKeyCertHop(), cookie_file="~/.fermi_sso.cookies")
```

Verified live 2026-09-02 against the Mu2e shift scheduler: with an empty jar
and no password, the probe prompted for the PIN once, the IdP accepted the
certificate, and the run landed on the calendar with the jar written.

Notes:

- The SAML connection (DocDB) does not offer the Yubikey adapter at all;
  a password or Kerberos login there, then cookie reuse, is the route.
- A refused certificate shows up as the application's login page with an
  error banner; the probe reports "the identity provider sent the
  application 'access_denied'".
- Wrong PINs count against the token's retry limit (`ykman piv info` shows
  it). Check the readiness report before trying.

## Reusing cookies instead of a password

A completed login leaves session cookies for both the identity provider and
the service provider in the session jar. Within one process those already
make every request after the first free. `--cookie-file` (library:
`cookie_file=`) extends that across processes: the jar is loaded before the
first request and written back after each completed login.

```bash
# first run: password login, jar created
fermi-sso-probe -u myaccount -c ~/.fermi_sso.cookies

# every later run: no username, no password, no prompt
fermi-sso-probe -c ~/.fermi_sso.cookies -n -q
```

Rules of the road:

- **Existing jar, no password**: the cookies are tried alone. If the service
  provider rejects them the probe fails with "the cookie file did not yield a
  live session" and exit status 1. Nothing is written.
- **Existing jar plus a password**: the cookies are tried first; if they are
  stale the normal password login runs and the jar is rewritten. This is the
  right combination for cron, with the password in a mode-600 env file.
- **Jar that does not exist yet**: a password is required, and the login that
  results creates the file.
- **Saving**: the jar is rewritten after a login, and after any request that
  changed the jar, such as a second site issuing its own session cookie. A
  request that leaves the jar unchanged leaves the file unchanged.
- **`--no-save-cookies`**: never rewrite the file. Use it with a browser
  export you want to keep as-is.
- The path can also come from `$FERMI_SSO_COOKIE_FILE` or a
  `FERMI_SSO_COOKIE_FILE=` line in the env file, with the usual precedence.

The probe's summary says which path was taken:

```
login     : not needed (existing cookies accepted)
login     : performed; cookies saved to /home/me/.fermi_sso.cookies
```

### One jar, several sites

The identity provider's own session cookie is saved alongside the site
cookies. Once the jar holds a live IdP session, a second site behind the same
IdP usually signs in with no login sequence at all: the site redirects to
pingprod, pingprod recognizes the session and redirects straight back with an
authorization code. The library notices that the jar gained cookies and saves
it, so the second site is then also covered.

Verified 2026-09-02: a password login to `mu2e-shifts.fnal.gov` followed by a
cookies-only request to `mu2e-talks.fnal.gov` landed on the Talks dashboard
without ever seeing a login form.

### Two things that end a saved IdP session

- **A forced re-authentication elsewhere.** Workday's SAML request carries
  `ForceAuthn="true"`. Attempting it re-authenticated the IdP session and,
  abandoned at the SecurID step, left both IdP sessions in the jar invalid.
  The next cookies-only probes of unrelated sites failed until one password
  login per connection restored them.
- **The sign-on throttle.** Many sign-ons in a few minutes make pingprod
  serve a "Multiple Sign-On Delay" page. It carries a GET form with
  `pfidpadapterid`, so it looks like the choose page; the library recognizes
  it by title, returns it unanswered rather than re-selecting an adapter, and
  the probe reports "the identity provider is throttling sign-ons". Wait a
  few minutes.

### Two identity-provider sessions, not one

pingprod runs two connections and they do not share a login. Sites using
OIDC (`/as/…`: the Mu2e shift scheduler, Mu2eTalks, SCD Reporting) share one
IdP session; sites using SAML (`/idp/…`: DocDB, ServiceNow) share another.
A jar filled by logging in to an OIDC site signs you in to the other OIDC
sites with no login form, but the first SAML site still asks for the
password once. After that, the SAML sites share too. Verified 2026-09-02: a
password login to ServiceNow made a cookies-only DocDB request succeed.

### Sites that need more than this library does

- **Workday** (`wd5.myworkday.com/fermilab`). The home URL is a JavaScript
  redirect stub and the identity portal is a single-page app, so start from
  its "Services account log in" URL, `/fermilab/login-saml2.flex`. That ends
  in an auto-submitting SAML `AuthnRequest` form with `ForceAuthn="true"`,
  which the library submits. The IdP then takes the password and demands an
  RSA SecurID passcode, and the probe says so:

  ```
  fermi-sso-probe -c ~/.fermi_sso.cookies https://wd5.myworkday.com/fermilab/login-saml2.flex
  RESULT: login FAILED
    the identity provider requires a second factor (RSA SecurID passcode form); ...
  ```

  Nothing short of a passcode prompt gets past that.
- **ServiceNow** (`fermi.servicenowservices.com`). Protected pages redirect to
  `auth_redirect.do`, a page whose only content is a JavaScript
  `location = <IdP URL>` assignment. The library does not follow JavaScript
  redirects, so point it at the IdP URL from that page, or log in once by
  hand as above and let the jar carry the session; `/navpage.do` then works
  directly.

### Django applications using allauth

Several Fermilab Django apps (Mu2eTalks, SCD Activity Reporting) use
django-allauth for Fermilab SSO. Their protected URLs redirect to a local
sign-in *menu* at `/accounts/login/` with a "Log in with Fermilab SSO" link
and a passkey form. The link goes to the allauth provider URL, e.g.
`/accounts/oidc/keycloak/login/?next=%2F`, which serves a confirmation page
whose form must be POSTed with its CSRF token before anything redirects to
pingprod.

The library handles that confirmation page. It is recognized only when all
three hold:

- the URL path matches `/accounts/.../login/`
- the page has a `method="post"` form whose only fields are
  `csrfmiddlewaretoken` and optionally `next`
- that form posts back to the page's own URL

The third rule matters. When you are already signed in, the site's nav bar
adds a "Sign out" button, which is also a CSRF-only POST form, to
`/accounts/logout/`. Without the rule the library submitted it and signed
you out on every other run; that happened live on 2026-09-02 and is now a
regression test.

So for these sites, give the probe the SSO link's URL, not the site root:

```bash
fermi-sso-probe -c ~/.fermi_sso.cookies -x Dashboard \
    "https://mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/?next=%2F"
```

Once the jar holds the site's session cookie, the site root works too.
Pointed at the menu itself, the probe reports "landed on an application
sign-in page".

### Using an MFA-enrolled account

The library cannot drive a second factor, but a browser can. Log in to the
service provider in the browser, export its cookies with any "cookies.txt"
extension (Chrome: *Get cookies.txt LOCALLY*; Firefox: *cookies.txt*), and
point the session at the export:

```bash
fermi-sso-probe -c ~/Downloads/mu2e-docdb.fnal.gov_cookies.txt --no-save-cookies -n
```

Export the cookies for the **service provider host** (`mu2e-docdb.fnal.gov`),
not the identity provider; it is the application session cookie that grants
access. The session lasts as long as the site allows, typically hours, and
then the export must be redone.

### File formats

| Format | Detected by | Notes |
|---|---|---|
| Netscape `cookies.txt` | anything else | Default. What curl `-c`, wget, and browser export extensions write. HttpOnly cookies carry a `#HttpOnly_` domain prefix, which the library reads and writes itself because Python < 3.10's `MozillaCookieJar` treats those lines as comments and silently drops them. |
| LWP | `.lwp` extension or `#LWP-Cookies-2.0` header | `http.cookiejar.LWPCookieJar` format. |
| JSON | `.json` extension or a leading `[` / `{` | A list of `{name, value, domain, path, secure, httponly, host_only, expires}`. Also reads the `expirationDate` / `httpOnly` / `hostOnly` keys of the Cookie-Editor and EditThisCookie extensions. |

Session cookies, which have no expiry, are written with expiry 0 rather than
dropped, because the SSO cookies are exactly that kind. Expired cookies are
skipped on both load and save.

### Security of the jar

The cookies are bearer credentials: anyone holding the file *is* you at that
site until the session expires. The library creates the file mode 600 via a
temporary file and atomic rename. Keep it on local disk, not in a shared
home directory or a repository; the project `.gitignore` excludes
`*.cookies` and `cookies.txt`.

## Verifying a login with fermi_sso_probe

The probe exists because **a successful HTTP status does not mean a
successful login**. When credentials are rejected, PingFederate re-serves its
login page with status 200. Code that checks `resp.status_code` sees success
and then parses a login form as if it were data.

The probe declares success only when all of these hold:

- the final URL is off the identity provider host
- the body matches none of the choose-auth, login-form, or postback patterns
- the page title does not read as a sign-in page (a heuristic that catches
  an application's own sign-in menu)
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

To carry the login across processes, add `cookie_file`. With both a
`userpass` and a `cookie_file`, the saved cookies are tried first and the
password is only used, and the jar rewritten, if they have gone stale:

```python
s = FermiSSOSession(userpass=f"{user}:{password}", cookie_file="~/.fermi_sso.cookies")
r = s.get(url)
print("logged in" if s.login_count else "reused cookies")

# cookies only, e.g. from a browser export of an MFA account
s = FermiSSOSession(cookie_file="~/Downloads/cookies.txt", cookie_save=False)
```

`load_cookies(path)` and `save_cookies(path)` are also available directly.

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

**`still on the login form -- wrong password, or the account requires MFA`**
— the password was rejected, or the account requires MFA. See
[Limitations](#limitations). Verify the password by logging in at
<https://pingprod.fnal.gov/> in a browser.

**`still on the login form -- the cookie file did not yield a live session`**
— the run was cookies-only and the service provider started SSO over, which
means the saved session has expired. Run again with a password to log in and
refresh the jar, or re-export from the browser.

**`cannot load cookie file`** — the file exists but is not parseable in the
detected or requested format. Force it with `--cookie-format`, or check that
a `.json` export is really JSON.

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

**MFA is not supported in the login flow.** The library drives only the
`ad..FormBased` adapter — the IdP's "a. Services Username and Password"
option. There is no path for a second factor, so an account enrolled in MFA
will loop back to the login form. Non-interactive scripts generally need a
*service account* provisioned for password authentication; request one
through the Service Desk. The DocDB landing page also links instructions for
applying for DocDB access. The workaround is a browser login whose cookies
are exported and reused; see [Reusing cookies instead of a
password](#reusing-cookies-instead-of-a-password).

**Saved cookies expire.** Cookie reuse lasts only as long as the service
provider's session. The library has no way to know the lifetime up front
and detects expiry only by being served the login page again.

**File-based certificate auth is not supported.** The IdP offers CILogon
certificate adapters; this package selects none of them. The YubiKey's PIV
certificate is supported through the openssl hop, see
[Logging in with a YubiKey](#logging-in-with-a-yubikey); Kerberos is
supported too.

**JavaScript redirects are not followed.** Workday and ServiceNow both
interpose a page whose only job is a `window.location` assignment. Give the
library the URL from that page instead. (Auto-submitting SAML `AuthnRequest`
forms, the other pattern seen there, *are* handled.)

**Second factors are not supported.** Where the IdP connection requires one,
as Workday's does (RSA SecurID after the password), the flow stops at the
passcode form.

**Page recognition is regex-based.** The library matches raw HTML with
regular expressions that are sensitive to attribute order, quoting, and
case. An IdP markup change presents as a login failure, not a parse error.

**Sessions are not thread-safe.** The `logging_in_already` recursion guard is
per-instance mutable state. Use one session per thread.
