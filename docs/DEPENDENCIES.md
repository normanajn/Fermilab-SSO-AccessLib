# External dependencies

Everything the library, the probe, and the YubiKey helper need beyond the
Python standard library, grouped by what you want to do. The core install is
deliberately small: one Python package. Each authentication method adds only
what it needs.

## Summary

| Need | Python packages | System tools / libraries | Platforms verified |
|---|---|---|---|
| Password login, cookie reuse, allauth and SAML/OIDC handling, the probe | `requests` | none | macOS 26 / Python 3.12 (live); Python 3.9 by inspection |
| Kerberos (`auth_method="kerberos"`, `--auth kerberos`) | `requests-gssapi`, which pulls in `gssapi` | a Kerberos client with a ticket cache: macOS built-in Heimdal; MIT krb5 on Linux (`krb5-user` / `krb5-workstation`); `gssapi` needs krb5 headers only where no wheel exists | code path offline only; live blocked by the FERMI.WIN.FNAL.GOV KDC for this account |
| YubiKey PIV certificate (`auth_method="yubikey"`, `--auth yubikey`) | none beyond `requests` | OpenSSL 3 with engine support, the libp11 `pkcs11` engine, a PKCS#11 module for the token (libykcs11 or opensc-pkcs11), `pkcs11-tool`; `ykman` optional for inspection | macOS 26 (live, 2026-09-02) |
| Jar manager and terminal viewer (`fermi-sso-jar`, `fermi-sso-jar-tui`) | `PyYAML` for the site catalog (JSON catalogs work without it); `curses` from the stdlib (on Windows: `windows-curses`) | none | macOS 26 / Python 3.12 (offline tests) |
| Qt viewer (`fermi-sso-jar-gui`) | `PySide6` (or an already-installed `PyQt6`) | a display; `QT_QPA_PLATFORM=offscreen` for headless tests | macOS 26 / PySide6 6.12 (offscreen) |
| Development | `pytest`, `pytest-qt`, `black` | `mandoc` or `man` to render the manpages | macOS |

Python 3.9 is the floor for the code. `gssapi` wheels exist for current
macOS and manylinux; on other platforms it compiles against the krb5 headers.

## Python packages

```bash
pip install .                 # requests, PyYAML
pip install '.[kerberos]'     # + requests-gssapi (+ gssapi)
pip install '.[gui]'          # + PySide6, for fermi-sso-jar-gui
pip install '.[test]'         # + pytest, pytest-qt
```

`requests-gssapi` is imported lazily, only when a session is constructed
with `auth_method="kerberos"`, so the base install never needs it.

## System packages for the YubiKey hop

The hop shells out to `openssl s_client`. It needs a real OpenSSL 3 with
engine support and the PKCS#11 pieces below. **Apple's `/usr/bin/openssl` is
LibreSSL and cannot load engines**; use Homebrew's.

| Component | Purpose | macOS (Homebrew) | Debian / Ubuntu | RHEL / Fedora |
|---|---|---|---|---|
| OpenSSL 3 | the TLS client | `openssl@3` | `openssl` | `openssl` |
| libp11 `pkcs11` engine | lets openssl use a PKCS#11 key | `libp11` | `libengine-pkcs11-openssl` | `openssl-pkcs11` |
| PKCS#11 module | talks to the token | `yubico-piv-tool` (libykcs11) or `opensc` | `yubico-piv-tool` or `opensc-pkcs11` | `yubico-piv-tool` or `opensc` |
| `pkcs11-tool` | exports the certificate without a PIN | `opensc` | `opensc` | `opensc` |
| `ykman` | inspect the token (optional) | `ykman` | `yubikey-manager` | `yubikey-manager` |

One-line installs:

```bash
# macOS
brew install openssl@3 libp11 yubico-piv-tool opensc ykman

# Debian / Ubuntu
sudo apt install openssl libengine-pkcs11-openssl yubico-piv-tool opensc yubikey-manager

# RHEL / Fedora
sudo dnf install openssl openssl-pkcs11 yubico-piv-tool opensc yubikey-manager
```

`pkcs11-provider` (the OpenSSL 3 provider replacing engines) is not
packaged by Homebrew; the engine route is what is implemented and tested.
Engines are deprecated in OpenSSL 3 but still functional in 3.6.

### Where the helper looks

`fermi_sso_yubikey` searches these paths, in order, and each can be
overridden by an environment variable or constructor argument:

| Setting | Environment | Default search |
|---|---|---|
| OpenSSL binary | `FERMI_SSO_OPENSSL` | `/opt/homebrew/opt/openssl@3/bin/openssl`, `/usr/local/opt/openssl@3/bin/openssl`, `/usr/bin/openssl` |
| Engine directory | `FERMI_SSO_ENGINES_DIR` | `/opt/homebrew/lib/engines-3`, `/usr/local/lib/engines-3`, `/usr/lib/x86_64-linux-gnu/engines-3`, `/usr/lib64/engines-3` |
| PKCS#11 module | `FERMI_SSO_PKCS11_MODULE` | libykcs11 then opensc-pkcs11 under `/opt/homebrew/lib`, `/usr/local/lib`, `/usr/lib/x86_64-linux-gnu`, `/usr/lib64` |
| Private key URI | `FERMI_SSO_PKCS11_KEY` | `pkcs11:id=%01;type=private` (PIV slot 9A) |
| PIN file | `FERMI_SSO_PIN_SOURCE` | none; openssl prompts |
| `pkcs11-tool` | `FERMI_SSO_PKCS11_TOOL` | first on `PATH` |

Run `fermi-sso-yubikey` to see what was found and whether the token's PIV
authentication certificate is visible. It never touches the PIN.

## Kerberos client

The `requests-gssapi` handler uses whatever GSSAPI library Python's `gssapi`
package binds to: the system Heimdal framework on macOS, MIT krb5 on Linux.
You need a ticket (`kinit`) and a realm configuration that can reach the
identity provider's realm. On this site the principal `HTTP/pingprod.fnal.gov`
lives in FERMI.WIN.FNAL.GOV; an FNAL.GOV ticket reaches it through
cross-realm trust. Check with:

```bash
klist
kgetcred HTTP/pingprod.fnal.gov@FERMI.WIN.FNAL.GOV     # Heimdal (macOS)
kvno HTTP/pingprod.fnal.gov@FERMI.WIN.FNAL.GOV         # MIT krb5 (Linux)
```

## Windows

The library itself runs anywhere `requests` does. The Kerberos and YubiKey
methods are untested on Windows: `gssapi` there needs MIT Kerberos for
Windows, and the YubiKey hop needs an OpenSSL 3 build with the pkcs11 engine
and libykcs11, none of which ship with the platform. The cookie-jar mode
0600 is advisory on NTFS.

## Not dependencies

Nothing here needs a browser, Java, or a Fermilab-specific client. A
browser is useful once: to export cookies for an account that can only
authenticate interactively (see the HOWTO).
