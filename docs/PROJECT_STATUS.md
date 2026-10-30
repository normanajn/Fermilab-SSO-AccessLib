# Project status, design and test matrix

Tracks the phases of `requests-fermi-sso`, the decisions behind them, and
what has been tested where. Updated 2026-10-30 for 0.4.0.

## Phases

| Phase | Deliverable | Status |
|---|---|---|
| 1. Session subclass | `FermiSSOSession` walks the PingFederate SAML and OIDC sequences, allauth confirmation, SAML AuthnRequest POST binding | done, live-verified 2026-09-02 |
| 2. Credentials | password adapter, Kerberos (SPNEGO via requests-gssapi), YubiKey PIV through an `openssl s_client` hop | done; Kerberos offline only (realm mismatch for the test account) |
| 3. Cookie reuse | load/save Netscape, LWP, JSON jars; browser exports; atomic mode-600 writes | done |
| 4. Diagnostics | `fermi-sso-probe` with result classification, `fermi-sso-cookies` offline inspector, `fermi-sso-yubikey` readiness | done |
| 5. CILogon device flow | `approve_cilogon_device()`, `--user-code` | done, live-verified 2026-10-19 |
| 6. Jar management | site catalog, `fermi-sso-jar` (status / prime / refresh / verify / clear / sites / setup), `open_session()` | done 2026-10-30, offline-tested |
| 7. Viewers | `fermi-sso-jar-tui` (curses) and `fermi-sso-jar-gui` (Qt) over the same engine | done 2026-10-30; GUI tested offscreen, TUI by hand |
| 8. Live verification of phase 6/7 against pingprod | run `fermi-sso-jar prime --all` with a real account and record the per-site result below | pending (needs a terminal and credentials) |

## Design: the jar tools (0.4.0)

**One engine, three fronts.** `fermi_sso_jar.JarManager` owns the jar path
and the catalog and exposes `status()`, `prime()`, `verify()`,
`prime_many()`, `clear()`, `purge_expired()`. The command line, the curses
viewer and the Qt viewer are thin front ends over it, so a capability added
to the manager appears in all three. Both viewers re-read the jar file on a
timer rather than keeping state, because the probe, scripts and the other
viewer rewrite the same file.

**Offline state judgement.** A site's state (`live`, `soon`, `session`,
`expired`, `absent`) is computed from cookie expiries without the network,
so `status` is instant and safe to run from anything. The SSO flow issues
mostly session cookies, whose lifetime the file does not record, hence the
explicit `session` state and the separate `verify` network check instead
of pretending to know.

**Prompt only when needed, once.** `prime_many()` tries the cookies alone
first and asks for the password only when they fail, then keeps it for the
rest of the run. A user with a live jar is never asked; a user with a dead
jar types the password once for every site in the catalog.

**Throttle-aware.** The identity provider serves a "Multiple Sign-On Delay"
page after repeated sign-ons. A multi-site run stops at the first one, and
`refresh` only touches stale sites, so a 30-minute timer never trips it.

**Extensible catalog.** Built-in entries are a Python dict mirrored in
`config/sites.yaml` (a test keeps them in step). User entries live in
`~/.fermi_sso/sites.yaml`; project catalogs via `$FERMI_SSO_SITES_FILE`
or `-S`; later files override by key field by field; `enabled: false`
hides. Unknown fields are rejected so a typo cannot silently disable a
check. YAML needs PyYAML; JSON is read with the stdlib as a fallback.

**Precedence.** commandline > environment > .env file > catalog `settings:`
block > defaults, extending the existing probe convention by one layer so a
shared project catalog can carry a default jar path and margin.

**Security.** Jar, env file and user catalog are written mode 600 via a
temp file and `os.replace`. Values are masked in both viewers until asked
for. `open_session()` returns a session without the password on it.
Passwords are never written unless `setup --store-password` is used
explicitly.

**JavaScript redirect stubs.** ServiceNow answers protected URLs with a
page whose only content is a `location =` assignment. Rather than teach
the library JavaScript, the catalog flags the site and `prime_site()`
follows one such hop, with a size cap and an https check.

## Test matrix

Offline, through the scripted transport adapter in `tests/conftest.py`;
no network or credentials. `python -m pytest tests/` on 2026-10-30:
317 passed, 1 skipped (setup.py version check; setuptools not in the venv).

| Area | File | What is covered |
|---|---|---|
| Site catalog | `tests/test_sites.py` | normalization and every validation error, built-in/YAML agreement, merge and override across files, env var and CLI file precedence, disable/re-enable, settings merge, add/remove user entries, mode 600 |
| Jar engine | `tests/test_jar_tool.py` | per-site states, stale and unclaimed detection, clear/purge rewrite, priming through a three-site scripted IdP (SAML postback, OIDC 302 callback, JS stub), second site riding the IdP session with no POST, verify cookies-only, prompt-once rule, cancelled prompt, throttle stop, transport and setup errors, credential precedence |
| Command line | `tests/test_jar_tool.py` | status table/JSON/`--cookies`/`--stale`, prime/refresh/verify/clear exit statuses, `refresh --verify`, sites list/show/add/remove/`--test`, setup dry-run and write (merge keeps a password), env-file and format errors, catalog settings and margin precedence, command word after options |
| Programmatic | `tests/test_jar_tool.py` | `open_session()` primes then returns a cookies-only session; raises when it cannot; jar-only load |
| Viewers | `tests/test_jar_gui.py` | Qt window tables, masking toggle, clear/purge via patched confirmation (pytest-qt, offscreen); TUI refuses without a TTY; both parsers carry the shared options |
| Docs/packaging | `tests/test_docs.py`, `tests/test_packaging.py` | every `FERMI_*` setting documented in `env.example`; a man page per console script; one version across all eight modules |

Not covered by automation: the curses screen itself (exercised by hand on
macOS Terminal), the Qt worker thread against the scripted adapter, and
any live login.

## Compatibility matrix

| Platform | Python | CLI (`fermi-sso-jar`) | TUI | GUI | Notes |
|---|---|---|---|---|---|
| macOS 26 | 3.12 | tested | tested by hand | tested offscreen, PySide6 6.12 | development platform |
| Linux | 3.9 to 3.12 | by inspection (stdlib + requests + PyYAML) | by inspection (stdlib curses) | by inspection | scheduler recipe: crontab |
| Windows 11 | 3.9 to 3.12 | by inspection | needs `pip install windows-curses` | by inspection | scheduler recipe: schtasks; mode-600 checks are skipped on NT |

Python 3.9 compatibility is maintained by inspection: no `match`, no
`X | Y` type unions, `typing` generics throughout.

## Open items

- Phase 8: live run of `prime --all` and `verify` per built-in site; record
  which connection each site's first login landed on.
- A Kerberos live check still needs a FERMI.WIN.FNAL.GOV ticket.
- The TUI has no automated test of its key handling; a `curses`-free
  `App.handle_key` test with a fake screen is the obvious next step.
