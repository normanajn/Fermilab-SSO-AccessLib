#!/usr/bin/env python3
"""
fermi_sso_yubikey -- perform the one mutual-TLS request of a Fermilab SSO
login with the certificate on a YubiKey (PIV slot 9A).

Python's TLS stack needs the private key as a file, and a PIV key never
leaves the token. So the identity provider's redirect to its mutual-TLS
listener (pingprod.fnal.gov:9032) is handed to this module, which runs

    openssl s_client -engine pkcs11 -keyform engine -key <pkcs11 URI> \\
        -cert <PEM exported from the token> ...

sends the single GET over that connection, and returns the raw response.
FermiSSOSession absorbs the cookies and follows the redirect back to the
application. openssl prompts for the PIN on the terminal unless a
pin-source file is given.

Requirements (macOS, Homebrew): openssl@3, libp11 (the pkcs11 engine),
yubico-piv-tool (libykcs11) or opensc, and pkcs11-tool from opensc.

Settings resolve as: constructor argument > environment > built-in default.
Environment: FERMI_SSO_OPENSSL, FERMI_SSO_ENGINES_DIR, FERMI_SSO_PKCS11_MODULE,
FERMI_SSO_PKCS11_KEY, FERMI_SSO_PIN_SOURCE, FERMI_SSO_PKCS11_TOOL.

See fermi_sso_yubikey(3) and docs/HOWTO.md.
"""

import glob
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from requests_fermi_sso import HopResponse

logger = logging.getLogger(__name__)

__version__ = "0.2.0"

ENV_OPENSSL = "FERMI_SSO_OPENSSL"
ENV_ENGINES_DIR = "FERMI_SSO_ENGINES_DIR"
ENV_MODULE = "FERMI_SSO_PKCS11_MODULE"
ENV_KEY = "FERMI_SSO_PKCS11_KEY"
ENV_PIN_SOURCE = "FERMI_SSO_PIN_SOURCE"
ENV_PKCS11_TOOL = "FERMI_SSO_PKCS11_TOOL"

#: PIV slot 9A ("PIV Authentication") is PKCS#11 object id 1 on a YubiKey.
DEFAULT_KEY_URI = "pkcs11:id=%01;type=private"
DEFAULT_CERT_ID = "01"

_OPENSSL_CANDIDATES = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
    "/usr/bin/openssl",
)
_ENGINES_DIR_CANDIDATES = (
    "/opt/homebrew/lib/engines-3",
    "/usr/local/lib/engines-3",
    "/usr/lib/x86_64-linux-gnu/engines-3",
    "/usr/lib64/engines-3",
)
_MODULE_CANDIDATES = (
    "/opt/homebrew/lib/libykcs11.dylib",
    "/usr/local/lib/libykcs11.dylib",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/lib64/libykcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
)


def _first_existing(candidates, extra_globs=()) -> Optional[str]:
    for path in candidates:
        if os.path.exists(path):
            return path
    for pattern in extra_globs:
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[0]
    return None


class YubiKeyCertHop:
    """
    Callable for FermiSSOSession(cert_hop=...): one GET over a client-cert
    TLS connection driven by openssl s_client and the pkcs11 engine.

    All arguments are optional and fall back to the environment, then to
    Homebrew paths. openssl_bin must be an OpenSSL 3 build with engine
    support; Apple's /usr/bin/openssl is LibreSSL and will not do.
    """

    def __init__(
        self,
        openssl_bin: Optional[str] = None,
        engines_dir: Optional[str] = None,
        module_path: Optional[str] = None,
        key_uri: Optional[str] = None,
        pin_source: Optional[str] = None,
        pkcs11_tool: Optional[str] = None,
        cert_pem: Optional[str] = None,
        timeout: float = 180.0,
        environ: Optional[Dict[str, str]] = None,
        runner=None,
    ):
        env = os.environ if environ is None else environ
        self.openssl_bin = (
            openssl_bin or env.get(ENV_OPENSSL) or _first_existing(_OPENSSL_CANDIDATES)
        )
        self.engines_dir = (
            engines_dir
            or env.get(ENV_ENGINES_DIR)
            or _first_existing(_ENGINES_DIR_CANDIDATES)
        )
        self.module_path = (
            module_path or env.get(ENV_MODULE) or _first_existing(_MODULE_CANDIDATES)
        )
        self.key_uri = key_uri or env.get(ENV_KEY) or DEFAULT_KEY_URI
        self.pin_source = pin_source or env.get(ENV_PIN_SOURCE)
        self.pkcs11_tool = (
            pkcs11_tool or env.get(ENV_PKCS11_TOOL) or shutil.which("pkcs11-tool")
        )
        self.cert_pem = cert_pem  # path; exported from the token when None
        self.timeout = timeout
        self._runner = runner or self._run
        self._tmpdir = None
        self.last_command: List[str] = []
        self.last_stderr = ""

    # ------------------------------------------------------------------
    # readiness
    # ------------------------------------------------------------------

    def check(self) -> List[Tuple[str, bool, str]]:
        """[(what, ok, detail)] for each prerequisite; nothing touches the PIN."""
        results = []
        results.append(
            (
                "openssl",
                bool(self.openssl_bin and os.path.exists(self.openssl_bin)),
                self.openssl_bin or "not found",
            )
        )
        if self.openssl_bin and os.path.exists(self.openssl_bin):
            try:
                out = subprocess.run(
                    [self.openssl_bin, "version"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                ).stdout.strip()
            except Exception as exc:  # pragma: no cover
                out = f"error: {exc}"
            results.append(("openssl is OpenSSL 3", out.startswith("OpenSSL 3"), out))
        engine = os.path.join(self.engines_dir or "", "pkcs11.dylib")
        engine_alt = os.path.join(self.engines_dir or "", "pkcs11.so")
        results.append(
            (
                "pkcs11 engine",
                bool(self.engines_dir)
                and (os.path.exists(engine) or os.path.exists(engine_alt)),
                self.engines_dir or "not found",
            )
        )
        results.append(
            (
                "PKCS#11 module",
                bool(self.module_path and os.path.exists(self.module_path)),
                self.module_path or "not found",
            )
        )
        results.append(
            (
                "pkcs11-tool",
                bool(self.pkcs11_tool and os.path.exists(self.pkcs11_tool)),
                self.pkcs11_tool or "not found",
            )
        )
        if self.pkcs11_tool and self.module_path and os.path.exists(self.module_path):
            try:
                out = subprocess.run(
                    [self.pkcs11_tool, "--module", self.module_path, "-O"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                seen = "PIV Authentication" in out.stdout
                results.append(
                    (
                        "token with PIV Authentication certificate",
                        seen,
                        (
                            "present"
                            if seen
                            else (
                                out.stderr.strip().splitlines() or ["no such object"]
                            )[-1]
                        ),
                    )
                )
            except Exception as exc:  # pragma: no cover
                results.append(
                    (
                        "token with PIV Authentication certificate",
                        False,
                        f"error: {exc}",
                    )
                )
        if self.pin_source:
            results.append(
                ("pin-source file", os.path.isfile(self.pin_source), self.pin_source)
            )
        return results

    # ------------------------------------------------------------------
    # certificate export
    # ------------------------------------------------------------------

    def ensure_cert_pem(self) -> str:
        """Path of the 9A certificate as PEM, exporting it from the token if needed."""
        if self.cert_pem and os.path.exists(self.cert_pem):
            return self.cert_pem
        if not (self.pkcs11_tool and self.module_path):
            raise RuntimeError(
                "cannot export the certificate: pkcs11-tool or the PKCS#11 module is missing"
            )
        self._tmpdir = self._tmpdir or tempfile.mkdtemp(prefix="fermi-sso-yk-")
        der = os.path.join(self._tmpdir, "piv-9a.der")
        pem = os.path.join(self._tmpdir, "piv-9a.pem")
        cmd = [
            self.pkcs11_tool,
            "--module",
            self.module_path,
            "--read-object",
            "--type",
            "cert",
            "--id",
            DEFAULT_CERT_ID,
            "-o",
            der,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            raise RuntimeError(
                f"pkcs11-tool could not read the certificate: {res.stderr.strip()}"
            )
        res = subprocess.run(
            [self.openssl_bin, "x509", "-inform", "DER", "-in", der, "-out", pem],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if res.returncode != 0:
            raise RuntimeError(
                f"openssl could not convert the certificate: {res.stderr.strip()}"
            )
        os.chmod(pem, 0o600)
        self.cert_pem = pem
        return pem

    # ------------------------------------------------------------------
    # the hop
    # ------------------------------------------------------------------

    def command(self, host: str, port: int) -> List[str]:
        key = self.key_uri
        if self.pin_source and "pin-source" not in key and "pin-value" not in key:
            key = f"{key};pin-source=file:{os.path.abspath(self.pin_source)}"
        return [
            self.openssl_bin,
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-engine",
            "pkcs11",
            "-keyform",
            "engine",
            "-key",
            key,
            "-cert",
            self.ensure_cert_pem(),
            "-quiet",
        ]

    def environment(self) -> Dict[str, str]:
        env = dict(os.environ)
        if self.engines_dir:
            env["OPENSSL_ENGINES"] = self.engines_dir
        if self.module_path:
            env["PKCS11_MODULE_PATH"] = self.module_path
        return env

    def __call__(self, url: str, prepared) -> HopResponse:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or 443
        request = build_request(prepared, parts)
        cmd = self.command(host, port)
        self.last_command = cmd
        if not self.pin_source:
            print("YubiKey: openssl will prompt for the PIV PIN", file=sys.stderr)
        stdout, stderr, code = self._runner(
            cmd, request, self.environment(), self.timeout
        )
        self.last_stderr = stderr
        if not stdout.strip():
            raise RuntimeError(
                "no HTTP response over the client-certificate connection; openssl said: "
                + (stderr.strip().splitlines() or ["nothing"])[-1]
            )
        return parse_http_response(stdout)

    @staticmethod
    def _run(cmd, request: bytes, env, timeout) -> Tuple[bytes, str, int]:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        try:
            out, err = proc.communicate(request, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            err = (err or b"") + b"\n(timed out waiting for the PIN or the server)"
        return out, err.decode("utf-8", "replace"), proc.returncode


# ----------------------------------------------------------------------
# raw HTTP/1.1 over the s_client pipe
# ----------------------------------------------------------------------


def build_request(prepared, parts) -> bytes:
    """
    Serialize the prepared GET as HTTP/1.1 for the s_client stdin.

    Uses the headers requests prepared (User-Agent, Accept, and the Cookie
    header for the target host, which carries the IdP's PF session cookie
    that ties this request to the sign-on in progress). Connection: close
    makes the server end the exchange so s_client exits.
    """
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host = parts.hostname + (
        f":{parts.port}" if parts.port and parts.port != 443 else ""
    )
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}"]
    for name, value in prepared.headers.items():
        if name.lower() in ("host", "connection", "accept-encoding"):
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def parse_http_response(raw: bytes) -> HopResponse:
    """Parse status line, headers, and body (Content-Length or chunked)."""
    # s_client may echo a stray line before the response; find the status line
    idx = raw.find(b"HTTP/")
    if idx < 0:
        raise ValueError("no HTTP status line in response")
    raw = raw[idx:]
    head, _, body = raw.partition(b"\r\n\r\n")
    if not _:
        head, _, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1").splitlines()
    status = int(lines[0].split()[1])
    headers: Dict[str, str] = {}
    set_cookies: List[str] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        if name.lower() == "set-cookie":
            set_cookies.append(value)
        headers[name.lower()] = value
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk(body)
    elif "content-length" in headers:
        body = body[: int(headers["content-length"])]
    return HopResponse(status, headers, body, set_cookies)


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    while data:
        size_line, _, rest = data.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2 :]
    return bytes(out)


# ----------------------------------------------------------------------
# command line: readiness check
# ----------------------------------------------------------------------


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="fermi_sso_yubikey",
        description="Check that this machine can perform a YubiKey (PIV) certificate "
        "login to Fermilab SSO, and show the openssl command that would be used.",
    )
    parser.add_argument(
        "--openssl", default=None, help=f"OpenSSL 3 binary (${ENV_OPENSSL})"
    )
    parser.add_argument(
        "--engines-dir",
        default=None,
        help=f"directory holding pkcs11.dylib/.so (${ENV_ENGINES_DIR})",
    )
    parser.add_argument(
        "--module", default=None, help=f"PKCS#11 module, e.g. libykcs11 (${ENV_MODULE})"
    )
    parser.add_argument(
        "--key",
        default=None,
        help=f"PKCS#11 URI of the private key (${ENV_KEY}; default {DEFAULT_KEY_URI})",
    )
    parser.add_argument(
        "--pin-source",
        default=None,
        help=f"file holding the PIV PIN, mode 600 (${ENV_PIN_SOURCE}); default: openssl prompts",
    )
    parser.add_argument(
        "--export-cert",
        metavar="FILE",
        default=None,
        help="also export the 9A certificate as PEM to FILE",
    )
    parser.add_argument("-V", "--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    hop = YubiKeyCertHop(
        openssl_bin=args.openssl,
        engines_dir=args.engines_dir,
        module_path=args.module,
        key_uri=args.key,
        pin_source=args.pin_source,
    )
    ok_all = True
    for what, ok, detail in hop.check():
        ok_all &= ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what:44s} {detail}")
    if args.export_cert:
        try:
            pem = hop.ensure_cert_pem()
            shutil.copyfile(pem, args.export_cert)
            os.chmod(args.export_cert, 0o600)
            print(f"ok    certificate exported to {args.export_cert}")
        except Exception as exc:
            print(f"FAIL  certificate export: {exc}")
            ok_all = False
    if ok_all:
        try:
            cmd = hop.command("pingprod.fnal.gov", 9032)
            print("\ncommand for the hop:\n  " + " ".join(cmd))
        except Exception as exc:
            print(f"FAIL  building the command: {exc}")
            ok_all = False
    print("\nRESULT:", "ready" if ok_all else "not ready")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
