---
name: fermi-sso
description: Log in to Fermilab SSO (pingprod.fnal.gov, SAML /idp/ and OIDC /as/) from scripts using the requests-fermi_sso package and its CLIs — fermi-sso-probe (check a login, fetch a protected page), fermi-sso-cookies (inspect a cookie jar), fermi-sso-yubikey (YubiKey PIV readiness). Covers password, Kerberos, YubiKey and cookie-jar modes, reusing a browser cookies.txt export for MFA accounts, approving CILogon OIDC device-flow codes (htgettoken --headless, Vault) without a browser, and diagnosing failed logins. Use when the user wants to fetch an SSO-protected Fermilab page (DocDB, mu2e-shifts, Mu2eTalks, SCD Reporting, ServiceNow), approve a cilogon.org/device user code from a script, check whether an SSO login or saved cookie jar still works, or debug a "login failed" from this package.
---

Source and docs: `$FERMI_SSO_HOME` (default
`~/Git-Repositories/Norman/Fermi-SSO-AccessLib`). Read
`docs/HOWTO.md` (troubleshooting, limitations) and `docs/EXAMPLES.md`
(live-verified per-site recipes) there before improvising. Man pages:
`fermi_sso_probe(1)`, `fermi_sso_cookies(1)`, `FermiSSOSession(3)`,
`fermi_sso_yubikey(3)`.

## Install / locate the tools

```bash
cd $FERMI_SSO_HOME && ./bootstrap.sh     # venv/ + test extras + test run
source venv/bin/activate
pip install '.[kerberos]'                # only for --auth kerberos
```

If `fermi-sso-probe` is not on PATH, use `$FERMI_SSO_HOME/venv/bin/fermi-sso-probe`.

## Pick the auth mode

| Situation | Mode | Command shape |
|---|---|---|
| Service ("special") account, no MFA | password | `fermi-sso-probe -u USER -c JAR URL` |
| `kinit` ticket present | kerberos | `fermi-sso-probe -a kerberos -c JAR URL` |
| YubiKey PIV, OIDC site (not DocDB) | yubikey | `fermi-sso-probe -a yubikey -c JAR URL` (real terminal, PIN prompt) |
| Jar from an earlier login | cookies | `fermi-sso-probe -c JAR -n URL` |
| MFA-enrolled personal account | browser export | `fermi-sso-probe -c ~/Downloads/HOST_cookies.txt --no-save-cookies -n URL` |
| CILogon device code to approve | any of the above | `fermi-sso-probe -a kerberos --user-code CODE` |

Conventional jar: `~/.fermi_sso.cookies`. One jar covers all sites on the
same IdP connection: OIDC sites (mu2e-shifts, Mu2eTalks, SCD Reporting)
share one session, SAML sites (DocDB, ServiceNow) share another. The
first SAML site after an OIDC login still needs one real login.

## fermi-sso-probe

Settings: CLI > environment > env file (`./.env`, then `~/.fermi_sso.env`,
or `-e FILE` / `$FERMI_SSO_ENV_FILE`) > defaults. See `env.example`.
Exit status: 0 logged in, 1 login failed, 2 usage/config error.

| Option | Env | Meaning |
|---|---|---|
| `URL` / `-U` | `FERMI_SSO_URL` | default `https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase` |
| `-u` | `FERMI_USER` | account, then `$USER` |
| `--password-env NAME` | `FERMI_PASSWORD` | never use `-p` (visible in ps) |
| `-a password\|kerberos\|yubikey` | `FERMI_SSO_AUTH` | |
| `--pin-source FILE` | `FERMI_SSO_PIN_SOURCE` | PIV PIN file, mode 600 |
| `-c FILE` | `FERMI_SSO_COOKIE_FILE` | load, and save after a completed login |
| `--cookie-format` | `FERMI_SSO_COOKIE_FORMAT` | netscape (default) / lwp / json |
| `--no-save-cookies` | | read-only jar |
| `--user-code CODE` | `FERMI_SSO_USER_CODE` | approve a CILogon device code; default URL becomes `https://cilogon.org/device/?user_code=CODE` |
| `--cilogon-idp ID` | `FERMI_SSO_CILOGON_IDP` | entityID picked on CILogon (default `https://idp.fnal.gov/idp/shibboleth`) |
| `-x TEXT` | | require TEXT in the final page |
| `-o FILE` | | write final body (`-` = stdout) |
| `-n` / `-q` / `-d` | `FERMI_SSO_DEBUG=1` | no prompt / verdict only / wire trace |

Examples:

```bash
fermi-sso-probe -u anorman -c ~/.fermi_sso.cookies -x Document      # DocDB, prompts
fermi-sso-probe -c ~/.fermi_sso.cookies -n -q \
    "https://mu2e-shifts.fnal.gov/login/oidc?next=/"                 # cookies only
fermi-sso-probe -c ~/.fermi_sso.cookies -n -o page.html URL          # fetch a page
```

## CILogon device codes (htgettoken --headless, Vault)

A device-flow client prints `https://cilogon.org/device/?user_code=CODE`
and polls. The probe (or `FermiSSOSession.approve_cilogon_device()`)
approves it: CILogon's IdP page (which is also the consent page for the
client named on it), the Shibboleth proxy idpext.fnal.gov, the usual
pingprod SAML choose and login pages, then SAML postbacks back to CILogon.
Success means it ended on cilogon.org with no error alert; the client's
poll is the final word.

```bash
htgettoken -a htvaultprod.fnal.gov -i mu2e --headless &    # prints CODE
fermi-sso-probe -a kerberos --user-code CODE               # or the full URL
```

```python
r = FermiSSOSession(auth_method="kerberos").approve_cilogon_device(code_or_url)
r.ok, r.reasons, r.response
```

- Approving is a sign-on in the user's name. Only approve codes from a
  client the user started in this session; never one pasted from elsewhere.
- Codes are single-use and expire in minutes. Do not retry a failed one;
  restart the client for a new code.
- The pingprod connection behind CILogon is the SAML one (`ad..KrbOrForm`,
  `ad..FNALYubikey`, ...), so Kerberos, YubiKey and password all apply.
  MFA accounts still cannot use the password path.
- Live-verified end to end 2026-10-19 with `-a yubikey`.
- htgettoken (normanajn fork, `feature/sso-approve`) can do this itself:
  `htgettoken -a VAULT -i ISSUER --ssoapprove=kerberos|yubikey|password`
  (implies `--headless`; `--ssocookiefile`, `--ssopinfile`, `--ssoidp`).
  OIDC only runs when the cached vault token and Kerberos-to-Vault
  logins fail, so force it with `--nokerberos --nossh
  --vaulttokeninfile /nonexistent` when testing.

## fermi-sso-cookies (offline)

```bash
fermi-sso-cookies ~/.fermi_sso.cookies                     # table, values masked
fermi-sso-cookies -D pingprod.fnal.gov -l ~/.fermi_sso.cookies   # IdP session live?
fermi-sso-cookies --live -j ~/.fermi_sso.cookies           # JSON of loadable cookies
```

Filters `-D DOMAIN`, `-N NAME` (globs, repeatable), `--live`, `--expired`.
Exit 1 if nothing matched. `-s` prints values in full: do not use it
unless the user asks, and never paste values into chat, logs or commits.

## fermi-sso-yubikey

`fermi-sso-yubikey` prints an ok/FAIL line per prerequisite (OpenSSL 3,
pkcs11 engine, PKCS#11 module, certificate on the token, PIN file) and the
`openssl s_client` command for `pingprod.fnal.gov:9032`. Exit 0 = ready.
Run it before any YubiKey login: wrong PINs consume the token's retry
count (`ykman piv info`). Apple's `/usr/bin/openssl` (LibreSSL) will not
work. System prerequisites per OS are in `docs/DEPENDENCIES.md`.

## Choosing the URL

Use the SSO entry point, not the site root. Site roots are either
unprotected (mu2e-docdb.fnal.gov/) or local login menus (mu2e-shifts,
mu2e-talks), and the probe reports "landed on an application sign-in page".

- DocDB: `https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase`
- Shift scheduler: `https://mu2e-shifts.fnal.gov/login/oidc?next=/`
- allauth apps: `https://mu2e-talks.fnal.gov/accounts/oidc/keycloak/login/?next=%2F`
- ServiceNow: JavaScript redirect stub; see EXAMPLES.md §5.

## Diagnosing failures (probe reasons)

- `still on the login form -- wrong password, or the account requires MFA`:
  MFA accounts cannot use the password path. Use a service account or a
  browser cookie export.
- `... the cookie file did not yield a live session`: the jar expired.
  Re-run once with credentials, or re-export from the browser.
- `the identity provider is throttling sign-ons`: the "Multiple Sign-On
  Delay" page. Wait a few minutes; do not loop retries.
- `requires a second factor (RSA SecurID ...)`: Workday. Not supported.
- Kerberos 401 or challenge unanswered: `klist`, then
  `kgetcred HTTP/pingprod.fnal.gov@FERMI.WIN.FNAL.GOV`.
- `stranded on pingprod.fnal.gov`: dump it with `-o page.html -d` and read it.
- `the login did not return to CILogon (stopped on HOST)`: a CILogon
  approval stopped at the IdP; the reasons listed with it say why.
- `CILogon reported: Error: User code not found.`: wrong, used or expired
  code. Restart the device-flow client.
- `stopped on a Shibboleth client-storage form`: idpext served an unexpected
  run of storage forms. Use `-d -o page.html`.
- Anything else: `-d`, then HOWTO.md "Troubleshooting".

## Rules

1. HTTP 200 does not mean logged in. Check the probe's exit status or
   `classify()`, never only the status code.
2. Treat the cookie jar as a password. It is mode 600; do not copy it to
   shared disks, commit it, or print its values.
3. Do not put passwords on the command line. Use a mode-600 `.env` /
   `~/.fermi_sso.env`, `--password-env`, or the prompt. A password cannot
   contain `:`.
4. Do not repeat failing logins in a loop. This triggers the IdP throttle
   and, with password mode, risks an account lockout.
5. YubiKey and prompted-password runs need a real terminal. From Claude,
   suggest the user runs them with `! fermi-sso-probe ...`, or use
   `--pin-source` / an env file with `-n`.
6. For code that embeds `FermiSSOSession`, use the fermi-sso-embed skill.
