# APEX Wi-Fi Security Toolkit

**APEX v5.0** is a Termux-friendly, Python-standard-library toolkit for authorized, defensive Wi-Fi and network checks.

## Features

- Local IP, default gateway, device and platform information
- DNS resolution and outbound TCP connectivity checks
- Read-only view of the operating system's ARP neighbor cache
- Offline Wi-Fi passphrase strength heuristic
- Cryptographically secure passphrase generator
- Router hardening checklist
- JSON diagnostics reports

## Install on Android / Termux

```bash
pkg update -y
pkg install python git -y
git clone https://github.com/cnfoysalx/apex-wifi-security.git
cd apex-wifi-security
python apex.py
```

Run diagnostics directly:

```bash
python apex.py --diagnose
```

No third-party Python packages are required.

## Important notes

- Use only on networks and devices you own or are explicitly authorized to assess.
- Neighbor information comes from the local OS cache; it is not a full device discovery scan.
- Entropy and strength labels are estimates, not crack-time predictions or security guarantees.
- Reports may contain local IP/MAC information. Review them before sharing.
- Entered passphrases are checked locally and are not written to reports.

## Safety scope

APEX is a defensive auditing tool. It does not implement Wi-Fi password cracking, handshake capture, deauthentication, credential attacks, or unauthorized access.

## Development

Keep credentials, router passwords, tokens, private reports, and personal network data out of Git commits.
