# Examples

Short, copy-paste recipes for reaching Fermilab SSO-protected sites with
`requests_fermi_sso`. Every example below was run against the real site on
2026-09-02. Replace `anorman` with your own account.

The pattern is always the same: construct a `FermiSSOSession` with a
credential, and use it like a normal `requests.Session`. The first request
that hits SSO performs the login; the cookie jar makes later runs skip it.

```python
from requests_fermi_sso import FermiSSOSession
```

## 1. DocDB (SAML) with a password, jar saved for next time

```python
s = FermiSSOSession(userpass="anorman:PASSWORD", cookie_file="~/.fermi_sso.cookies")
r = s.get("https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase")

# A failed login is served as the login page with status 200. Check for it.
if s.login_page_re.search(r.text):
    raise SystemExit("login failed")

r = s.get("https://mu2e-docdb.fnal.gov/cgi-bin/DocDB/ShowDocument?docid=1234")
print(r.status_code, len(r.text))
```

Command-line equivalent, password prompted:

```bash
fermi-sso-probe -u anorman -c ~/.fermi_sso.cookies -x "Document" \
    https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

## 2. Any later run: cookies only, no password

```python
s = FermiSSOSession(cookie_file="~/.fermi_sso.cookies")
r = s.get("https://mu2e-docdb.fnal.gov/cgi-bin/DocDB/ListBy?days=7")
```

```bash
fermi-sso-probe -c ~/.fermi_sso.cookies -n https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

## 3. Mu2e shift scheduler (OIDC)

Fetch the site's SSO entry point, not its root. The root redirects to a
local login menu; the entry point goes to the identity provider.

```python
s = FermiSSOSession(userpass="anorman:PASSWORD", cookie_file="~/.fermi_sso.cookies")
r = s.get("https://mu2e-shifts.fnal.gov/login/oidc?next=/")     # lands on /calendar
r = s.get("https://mu2e-shifts.fnal.gov/calendar")
```

## 4. Mu2eTalks and SCD Reporting (Django + allauth)

These sites put a "Sign in with SSO" confirmation page in front of the IdP;
the library submits it. Give the SSO link's URL. With a jar that already
holds a live IdP session from example 3, no password is needed at all:

```python
s = FermiSSOSession(cookie_file="~/.fermi_sso.cookies")
s.get("https://mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/?next=%2F")     # dashboard
s.get("https://scd-reporting.fnal.gov/accounts/oidc/keycloak/login/?next=%2F")  # dashboard
r = s.get("https://mu2e-talks.fnal.gov/api/talks/")   # whatever the app offers
```

Once each site's own session cookie is in the jar, the site root works too:

```bash
fermi-sso-probe -c ~/.fermi_sso.cookies -n -x Dashboard https://mu2e-talks.fnal.gov/
```

## 5. ServiceNow (SAML behind a JavaScript redirect)

Protected pages redirect to `auth_redirect.do`, whose only content is a
JavaScript jump to the IdP. The library does not run JavaScript, so pull the
URL out and give it to the session; from there the SAML login and postback
are handled.

```python
import html, re

s = FermiSSOSession(userpass="anorman:PASSWORD", cookie_file="~/.fermi_sso.cookies")
r = s.get("https://fermi.servicenowservices.com/navpage.do")
if "auth_redirect.do" in r.url:
    idp_url = html.unescape(re.search(r"location(?:\.href)?\s*=\s*['\"]([^'\"]+)", r.text).group(1))
    r = s.get(idp_url)                                   # login form -> postback -> ServiceNow
print(r.url)                                             # .../now/nav/ui/classic/params/target/home.do
```

After that, `navpage.do` works directly and cookies-only.

## 6. Kerberos ticket instead of a password

```bash
pip install '.[kerberos]'
kinit
fermi-sso-probe -a kerberos -c ~/.fermi_sso.cookies https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

```python
s = FermiSSOSession(auth_method="kerberos", cookie_file="~/.fermi_sso.cookies")
r = s.get("https://mu2e-shifts.fnal.gov/login/oidc?next=/")
if r.status_code == 401:
    raise SystemExit("Kerberos challenge not answered; check klist")
```

Note: on this site the IdP's principal lives in FERMI.WIN.FNAL.GOV. If the
probe reports the challenge unanswered, run
`kgetcred HTTP/pingprod.fnal.gov@FERMI.WIN.FNAL.GOV` to see the KDC's answer.

## 7. YubiKey (PIV certificate), from a terminal

The OIDC sites offer "FNAL Yubikey". openssl prompts for the PIN, so run
this in a real terminal, or give `--pin-source` a mode-600 file.

```bash
brew install openssl@3 libp11 yubico-piv-tool opensc ykman   # once
fermi-sso-yubikey                                             # readiness report
fermi-sso-probe -a yubikey -c ~/.fermi_sso.cookies "https://mu2e-shifts.fnal.gov/login/oidc?next=/"
```

```python
from fermi_sso_yubikey import YubiKeyCertHop

s = FermiSSOSession(auth_method="yubikey", cert_hop=YubiKeyCertHop(),
                    cookie_file="~/.fermi_sso.cookies")
r = s.get("https://mu2e-shifts.fnal.gov/login/oidc?next=/")
```

## 8. Checking the result properly

Status 200 does not mean logged in. Reuse the probe's classifier:

```python
import fermi_sso_probe

ok, reasons = fermi_sso_probe.classify(s, r, idp_host="pingprod.fnal.gov", expect="Calendar")
if not ok:
    raise SystemExit("; ".join(reasons))
```

## 9. What does not work, and why

- **Workday** (`wd5.myworkday.com/fermilab`): after the password the IdP
  demands an RSA SecurID passcode. The probe stops there and says so:

  ```bash
  fermi-sso-probe -c ~/.fermi_sso.cookies https://wd5.myworkday.com/fermilab/login-saml2.flex
  # RESULT: login FAILED
  #   the identity provider requires a second factor (RSA SecurID passcode form); ...
  ```

- **Site roots that are login menus** (`mu2e-shifts.fnal.gov/`,
  `mu2e-talks.fnal.gov/` before the jar holds their session): the probe
  reports "landed on an application sign-in page". Use the SSO link's URL.

- **MFA-enrolled accounts on the password path**: loop back to the login
  form. Log in once in a browser, export the site's cookies, and pass the
  file as `cookie_file`.

## 10. Cron

Password in a mode-600 env file, jar reused while it lasts, re-login and
refresh when it expires, quiet output, exit status 0/1/2:

```bash
fermi-sso-probe --env-file ~/.fermi_sso.env -c ~/.fermi_sso.cookies -n -q \
    -x "Document" https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase
```

## 11. CILogon device code (htgettoken --headless, Vault)

A device-flow client prints a CILogon URL and code. Approve it from the same
machine instead of a phone. Checked against cilogon.org and idpext.fnal.gov
on 2026-10-19 as far as pingprod's choose and login pages.

```bash
htgettoken -a htvaultprod.fnal.gov -i mu2e --headless &   # prints the code
fermi-sso-probe -a kerberos --user-code N3X-2R4-GRR
# RESULT: login SUCCEEDED
#   landed on https://cilogon.org/secure/getuser/
wait                                                      # htgettoken's poll completes
```

```python
s = FermiSSOSession(auth_method="kerberos")
result = s.approve_cilogon_device("https://cilogon.org/device/?user_code=N3X-2R4-GRR")
if not result.ok:
    raise SystemExit("; ".join(result.reasons))
```

A wrong or expired code is reported as
`CILogon reported: Error: User code not found.`
