#!/usr/bin/env python3
"""
APEX Wi-Fi Security Toolkit v5.0
Defensive diagnostics for networks you own or are authorized to assess.
No password cracking, packet capture, deauthentication, or credential attacks.
Python 3 standard library only; Termux-friendly.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import platform
import secrets
import socket
import string
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "5.0.0"
REPORT_DIR = Path("reports")
COMMON_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "qwerty123",
    "admin123", "iloveyou", "welcome123", "letmein123", "11111111",
    "00000000", "abcdefgh", "qwertyuiop"
}
WEAK_PATTERNS = ("1234", "abcd", "qwerty", "asdf", "password", "admin")


def banner() -> None:
    print(r"""
    █████╗ ██████╗ ███████╗██╗  ██╗
   ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
   ███████║██████╔╝█████╗   ╚███╔╝
   ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗
   ██║  ██║██║     ███████╗██╔╝ ██╗
   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
          Wi-Fi DEFENSE TOOLKIT
    """)
    print(f"  APEX v{VERSION} | Authorized defensive use only\n")


def default_route_gateway() -> str | None:
    """Read Android/Linux IPv4 route table without changing device settings."""
    route_file = Path("/proc/net/route")
    try:
        lines = route_file.read_text(errors="ignore").splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) > 3 and fields[1] == "00000000":
                raw = bytes.fromhex(fields[2])
                return socket.inet_ntoa(raw[::-1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def local_ip() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def network_info() -> dict:
    ip = local_ip()
    gateway = default_route_gateway()
    info = {
        "local_ip": ip,
        "gateway": gateway,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }
    if ip:
        try:
            info["likely_subnet"] = str(ipaddress.ip_network(ip + "/24", strict=False))
        except ValueError:
            info["likely_subnet"] = None
    else:
        info["likely_subnet"] = None
    return info


def check_dns(host: str = "example.com") -> dict:
    started = time.perf_counter()
    try:
        answers = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        return {
            "ok": True,
            "host": host,
            "addresses": answers,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except OSError as exc:
        return {"ok": False, "host": host, "error": str(exc)}


def check_tcp(host: str, port: int = 443, timeout: float = 3.0) -> dict:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "ok": True, "host": host, "port": port,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2)
            }
    except OSError as exc:
        return {"ok": False, "host": host, "port": port, "error": str(exc)}


def read_neighbor_table() -> list[dict]:
    """Read the OS neighbor cache only; does not probe or scan other devices."""
    entries = []
    for file_path in (Path("/proc/net/arp"), Path("/proc/net/ndisc_cache")):
        try:
            lines = file_path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        if file_path.name == "arp":
            for line in lines[1:]:
                cols = line.split()
                if len(cols) >= 6 and cols[3] != "00:00:00:00:00:00":
                    entries.append({
                        "ip": cols[0], "mac": cols[3].lower(),
                        "interface": cols[5], "source": "ARP cache"
                    })
    return entries


def estimate_entropy(password: str) -> tuple[float, int]:
    """Heuristic only: estimated search-space entropy, not crack-time prediction."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool += 1
    bits = len(password) * math.log2(pool) if pool else 0.0
    return round(bits, 1), pool


def audit_passphrase(password: str) -> dict:
    bits, pool = estimate_entropy(password)
    findings = []
    lowered = password.lower()

    if len(password) < 8:
        findings.append("Below the 8-character WPA2/WPA3 passphrase minimum.")
    if len(password) > 63:
        findings.append("Over the 63-character passphrase limit; use a 64-hex PSK only if your router explicitly supports it.")
    if lowered in COMMON_PASSWORDS:
        findings.append("Matches a commonly used weak password.")
    if any(pattern in lowered for pattern in WEAK_PATTERNS):
        findings.append("Contains a predictable word or sequence.")
    if len(set(password)) <= 2 and password:
        findings.append("Uses too few distinct characters.")
    if password and (password.isalpha() or password.isdigit()):
        findings.append("Uses only letters or only digits.")
    if password and password.strip() != password:
        findings.append("Has leading or trailing whitespace; this can cause connection problems.")

    if len(password) >= 16 and bits >= 80 and not findings:
        rating = "Strong (heuristic)"
    elif len(password) >= 12 and bits >= 60 and not findings:
        rating = "Moderate (heuristic)"
    else:
        rating = "Weak / needs improvement"

    return {
        "rating": rating,
        "length": len(password),
        "estimated_entropy_bits": bits,
        "character_pool_estimate": pool,
        "findings": findings or ["No obvious weak patterns detected by this basic check."],
        "note": "This is a local heuristic, not a password-cracking test or guarantee of security."
    }


def generate_passphrase(length: int = 24) -> str:
    if not 16 <= length <= 63:
        raise ValueError("Choose a length between 16 and 63.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    # Ensure at least one character from each major class.
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def router_checklist() -> list[str]:
    return [
        "Use WPA3-Personal where supported; otherwise WPA2-AES/CCMP.",
        "Disable WPS if you do not specifically need it.",
        "Change the router administrator password from its factory default.",
        "Install firmware updates from the router manufacturer's official source.",
        "Disable remote administration unless it is essential.",
        "Review connected devices and remove unknown devices through the router's official app/admin page.",
        "Use a separate guest network for visitors and smart-home/IoT devices when available.",
        "Use a unique Wi-Fi passphrase; do not reuse email or social-media passwords.",
    ]


def save_report(data: dict) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"apex_report_{stamp}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def run_diagnostics() -> dict:
    return {
        "tool": "APEX",
        "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "network": network_info(),
        "dns": check_dns(),
        "internet_tcp_443": check_tcp("1.1.1.1", 443),
        "neighbor_cache": read_neighbor_table(),
        "router_security_checklist": router_checklist(),
        "privacy": "No passwords or Wi-Fi credentials are collected or stored."
    }


def print_menu() -> None:
    print(" [1] Network & gateway information")
    print(" [2] DNS and internet connectivity test")
    print(" [3] View local neighbor cache")
    print(" [4] Offline Wi-Fi passphrase audit")
    print(" [5] Generate secure Wi-Fi passphrase")
    print(" [6] Router security checklist")
    print(" [7] Run all diagnostics and save JSON report")
    print(" [0] Exit")


def main() -> int:
    parser = argparse.ArgumentParser(description="APEX defensive Wi-Fi toolkit")
    parser.add_argument("--diagnose", action="store_true", help="run diagnostics and save a JSON report")
    parser.add_argument("--version", action="version", version=f"APEX {VERSION}")
    args = parser.parse_args()

    banner()
    if args.diagnose:
        data = run_diagnostics()
        print(json.dumps(data, indent=2))
        print(f"\nReport saved: {save_report(data)}")
        return 0

    while True:
        print_menu()
        choice = input("\nAPEX > ").strip()
        if choice == "1":
            print(json.dumps(network_info(), indent=2))
        elif choice == "2":
            print("DNS:", json.dumps(check_dns(), indent=2))
            print("Internet:", json.dumps(check_tcp("1.1.1.1", 443), indent=2))
        elif choice == "3":
            print(json.dumps(read_neighbor_table(), indent=2))
            print("Note: this is only the OS cache; an empty list does not mean no devices are connected.")
        elif choice == "4":
            secret = input("Enter passphrase locally (input is not saved): ")
            print(json.dumps(audit_passphrase(secret), indent=2))
            del secret
        elif choice == "5":
            try:
                length = int(input("Length (16-63, default 24): ").strip() or "24")
                print("\nGenerated passphrase (save it securely):")
                print(generate_passphrase(length))
                print("Do not paste this password into chat or commit it to GitHub.")
            except ValueError as exc:
                print(f"Error: {exc}")
        elif choice == "6":
            for number, item in enumerate(router_checklist(), 1):
                print(f"{number}. {item}")
        elif choice == "7":
            data = run_diagnostics()
            path = save_report(data)
            print(f"\nDiagnostics complete. Report: {path}")
            print("Review the report before sharing; it may contain local IP/MAC information.")
        elif choice == "0":
            print("APEX signing off. Stay secure!")
            return 0
        else:
            print("Choose a valid menu number.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting safely.")
        raise SystemExit(130)
