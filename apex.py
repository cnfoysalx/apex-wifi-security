#!/usr/bin/env python3
"""
APEX v6.1 - Advanced Network Security Auditor
Defensive, non-destructive checks for systems and websites you are authorized to assess.
Python standard library only. No Wi-Fi cracking, packet capture, deauthentication,
credential attacks, exploitation, or stealth scanning.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import math
import platform
import secrets
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

VERSION = "6.1.0"
REPORT_DIR = Path("reports")
COMMON_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "qwerty123",
    "admin123", "iloveyou", "welcome123", "letmein123", "11111111",
    "00000000", "abcdefgh", "qwertyuiop", "adminadmin"
}
WEAK_PATTERNS = ("1234", "abcd", "qwerty", "asdf", "password", "admin")
SECURITY_HEADERS = {
    "strict-transport-security": "Enforces HTTPS for future visits",
    "content-security-policy": "Restricts where page content can load from",
    "x-content-type-options": "Helps prevent MIME-type sniffing",
    "referrer-policy": "Controls referrer information sent to other sites",
    "permissions-policy": "Restricts browser features such as camera and microphone",
    "frame-protection": "Helps reduce clickjacking risk (CSP frame-ancestors or X-Frame-Options)"
}


def banner() -> None:
    print(r"""
     █████╗ ██████╗ ███████╗██╗  ██╗
    ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
    ███████║██████╔╝█████╗   ╚███╔╝
    ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗
    ██║  ██║██║     ███████╗██╔╝ ██╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
       ADVANCED NETWORK SECURITY AUDITOR
    """)
    print(f" APEX v{VERSION} | Authorized defensive use only\n")


def local_ip() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_gateway() -> str | None:
    try:
        lines = Path("/proc/net/route").read_text(errors="ignore").splitlines()[1:]
        for line in lines:
            cols = line.split()
            if len(cols) > 3 and cols[1] == "00000000":
                return socket.inet_ntoa(bytes.fromhex(cols[2])[::-1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def network_report() -> dict[str, Any]:
    ip = local_ip()
    try:
        subnet = str(ipaddress.ip_network(ip + "/24", strict=False)) if ip else None
    except ValueError:
        subnet = None
    neighbors = []
    try:
        for line in Path("/proc/net/arp").read_text(errors="ignore").splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6 and cols[3] != "00:00:00:00:00:00":
                neighbors.append({"ip": cols[0], "mac": cols[3].lower(), "interface": cols[5]})
    except OSError:
        pass
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "local_ip": ip,
        "default_gateway": default_gateway(),
        "estimated_subnet": subnet,
        "neighbor_cache": neighbors,
        "neighbor_cache_note": "Read-only OS cache; not a full device scan."
    }


def dns_audit(host: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({entry[4][0] for entry in records})
        return {
            "ok": True, "hostname": host, "addresses": addresses,
            "lookup_ms": round((time.perf_counter() - started) * 1000, 2)
        }
    except (OSError, UnicodeError) as exc:
        return {"ok": False, "hostname": host, "error": str(exc)}


def tls_audit(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                expires = cert.get("notAfter")
                days_left = None
                if expires:
                    expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                return {
                    "ok": True,
                    "hostname": host,
                    "port": port,
                    "tls_version": tls.version(),
                    "cipher": cipher[0] if cipher else None,
                    "certificate_subject": cert.get("subject"),
                    "certificate_issuer": cert.get("issuer"),
                    "certificate_expires": expires,
                    "certificate_days_remaining": days_left,
                    "handshake_ms": round((time.perf_counter() - started) * 1000, 2),
                    "verification": "System certificate validation succeeded"
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {
            "ok": False, "hostname": host, "port": port,
            "error": str(exc),
            "note": "Connection or certificate validation failed; investigate before trusting this host."
        }


def normalize_https_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value if "://" in value else "https://" + value)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are accepted by the web audit.")
    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return parsed.geturl(), parsed.hostname


class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects that downgrade an HTTPS audit to plain HTTP."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlparse(urljoin(req.full_url, newurl))
        if target.scheme.lower() != "https":
            raise urllib.error.URLError("Blocked redirect: HTTPS audit cannot follow a non-HTTPS URL.")
        if target.username or target.password:
            raise urllib.error.URLError("Blocked redirect: embedded credentials are not accepted.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def web_security_audit(url: str, timeout: float = 8.0) -> dict[str, Any]:
    normalized, host = normalize_https_url(url)
    request = urllib.request.Request(
        normalized,
        headers={"User-Agent": "APEX-Security-Auditor/6.1 (defensive-check)"},
        method="GET"
    )
    started = time.perf_counter()
    try:
        opener = urllib.request.build_opener(
            HTTPSOnlyRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )
        with opener.open(request, timeout=timeout) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = response.status
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        status = exc.code
        final_url = exc.geturl()
    except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
        return {"ok": False, "url": normalized, "hostname": host, "error": str(exc)}

    checks = []
    for key, purpose in SECURITY_HEADERS.items():
        if key == "frame-protection":
            present = "content-security-policy" in headers and "frame-ancestors" in headers.get("content-security-policy", "").lower()
            present = present or "x-frame-options" in headers
        else:
            present = key in headers
        checks.append({
            "header": key,
            "present": present,
            "purpose": purpose,
            "value": headers.get(key) if key in headers else None
        })
    return {
        "ok": True,
        "requested_url": normalized,
        "final_url": final_url,
        "hostname": host,
        "http_status": status,
        "response_ms": round((time.perf_counter() - started) * 1000, 2),
        "security_headers": checks,
        "missing_headers": [item["header"] for item in checks if not item["present"]],
        "note": "Informational header review only; missing headers are not proof of exploitability."
    }


def password_entropy(password: str) -> tuple[float, int]:
    pool = 0
    for test, size in (
        (str.islower, 26), (str.isupper, 26), (str.isdigit, 10),
        (lambda s: any(c in string.punctuation for c in s), len(string.punctuation)),
        (str.isspace, 1)
    ):
        if test(password):
            pool += size
    return (round(len(password) * math.log2(pool), 1) if pool else 0.0, pool)


def password_audit(password: str) -> dict[str, Any]:
    bits, pool = password_entropy(password)
    findings = []
    low = password.lower()
    if len(password) < 8:
        findings.append("Below the WPA2/WPA3 passphrase minimum of 8 characters.")
    if len(password) > 63:
        findings.append("Exceeds the 63-character passphrase limit.")
    if low in COMMON_PASSWORDS:
        findings.append("Matches a common weak password.")
    if any(part in low for part in WEAK_PATTERNS):
        findings.append("Contains a predictable word or sequence.")
    if len(set(password)) <= 2 and password:
        findings.append("Contains too few distinct characters.")
    if password and (password.isalpha() or password.isdigit()):
        findings.append("Uses only letters or only digits.")
    if password and password.strip() != password:
        findings.append("Has leading or trailing whitespace.")
    rating = "Strong (heuristic)" if len(password) >= 16 and bits >= 80 and not findings else (
        "Moderate (heuristic)" if len(password) >= 12 and bits >= 60 and not findings else "Weak / improve"
    )
    return {
        "rating": rating, "length": len(password),
        "estimated_entropy_bits": bits, "character_pool_estimate": pool,
        "findings": findings or ["No obvious weak patterns detected."],
        "warning": "Heuristic estimate only; not a crack-time prediction or guarantee."
    }


def generate_password(length: int = 24) -> str:
    if not 16 <= length <= 63:
        raise ValueError("Length must be between 16 and 63.")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+"]
    alphabet = "".join(groups)
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def router_checklist() -> list[str]:
    return [
        "Prefer WPA3-Personal; otherwise use WPA2-AES/CCMP.",
        "Disable WPS if it is not required.",
        "Replace the router administrator password with a unique strong password.",
        "Install firmware only from the manufacturer's official update mechanism.",
        "Disable remote administration unless there is a clear need.",
        "Review connected devices in the router's official administration interface.",
        "Use a separate guest network for visitors and untrusted IoT devices.",
        "Use a unique Wi-Fi passphrase and keep it private.",
        "Change default SSID if it exposes router model or personal details.",
        "Back up router configuration securely after making changes."
    ]


def make_full_report() -> dict[str, Any]:
    net = network_report()
    gateway = net.get("default_gateway")
    return {
        "tool": "APEX",
        "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "network": net,
        "dns": dns_audit("example.com"),
        "internet_connectivity": tls_audit("1.1.1.1", 443),
        "gateway_connectivity": tls_audit(gateway, 443) if gateway else {
            "ok": False, "note": "No default gateway detected; skipped."
        },
        "router_hardening_checklist": router_checklist(),
        "privacy": "No Wi-Fi passwords or credentials are collected or stored."
    }


def save_report(data: dict[str, Any]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    name = "apex_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    path = REPORT_DIR / name
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="APEX v6.1 defensive network auditor",
        epilog="Only assess networks and websites you own or are authorized to test."
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("network", help="show local IP, gateway and cached neighbors")
    dns_parser = sub.add_parser("dns", help="resolve a hostname")
    dns_parser.add_argument("host")
    tls_parser = sub.add_parser("tls", help="validate a host TLS certificate")
    tls_parser.add_argument("host")
    web_parser = sub.add_parser("web", help="audit HTTPS security response headers")
    web_parser.add_argument("url")
    pass_parser = sub.add_parser("password", help="offline passphrase strength check")
    gen_parser = sub.add_parser("generate", help="generate a secure passphrase")
    gen_parser.add_argument("--length", type=int, default=24)
    sub.add_parser("checklist", help="show router hardening checklist")
    sub.add_parser("diagnose", help="run diagnostics and save a JSON report")
    parser.add_argument("--version", action="version", version=f"APEX {VERSION}")
    args = parser.parse_args()

    banner()
    if args.command == "network":
        print_json(network_report())
    elif args.command == "dns":
        print_json(dns_audit(args.host))
    elif args.command == "tls":
        print_json(tls_audit(args.host))
    elif args.command == "web":
        try:
            print_json(web_security_audit(args.url))
        except ValueError as exc:
            parser.error(str(exc))
    elif args.command == "password":
        entered = getpass.getpass("Passphrase (hidden; never saved): ")
        print_json(password_audit(entered))
        del entered
    elif args.command == "generate":
        try:
            print("Generated passphrase (store it securely):")
            print(generate_password(args.length))
            print("Never commit or share this password.")
        except ValueError as exc:
            parser.error(str(exc))
    elif args.command == "checklist":
        for i, item in enumerate(router_checklist(), 1):
            print(f"{i}. {item}")
    elif args.command == "diagnose":
        report = make_full_report()
        print_json(report)
        print(f"\nSaved report: {save_report(report)}")
        print("Review local IP/MAC details before sharing the report.")
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted safely.")
        raise SystemExit(130)
