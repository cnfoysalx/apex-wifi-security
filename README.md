# APEX Wi-Fi Security Toolkit

**APEX v6.0** is a Termux-friendly defensive network auditor built with Python's standard library. No paid API or third-party package is required.

## Features

- **Network overview:** local IP, default gateway, estimated subnet and read-only ARP cache
- **DNS diagnostics:** hostname resolution and lookup timing
- **TLS audit:** certificate validation, TLS version, cipher and certificate expiry
- **HTTPS header audit:** checks common browser security headers
- **Offline passphrase audit:** heuristic feedback without saving the entered password
- **Secure generator:** cryptographically random Wi-Fi passphrase generation
- **Router checklist:** WPA2/WPA3 and router-hardening recommendations
- **JSON report:** timestamped diagnostics saved locally under `reports/`
- **Offline unit tests:** validates URL input, password rules, generator constraints and JSON report writing

## Install on Android / Termux

```bash
pkg update -y
pkg install python git -y
git clone https://github.com/cnfoysalx/apex-wifi-security.git
cd apex-wifi-security
```

If already installed, update it:

```bash
cd ~/apex-wifi-security
git pull
```

## Commands

```bash
python apex.py                  # show command help
python apex.py network          # local network information
python apex.py dns example.com  # DNS lookup
python apex.py tls example.com  # TLS certificate check
python apex.py web example.com  # HTTPS response-header audit
python apex.py password         # hidden-input passphrase audit
python apex.py generate        # generate a secure passphrase
python apex.py checklist       # router hardening checklist
python apex.py diagnose        # full diagnostics + JSON report
```

For a longer generated passphrase:

```bash
python apex.py generate --length 32
```

## Run the offline test suite

No internet connection or extra package is needed for these tests:

```bash
python -m unittest -v
```

The tests do not contact external hosts and do not perform network scanning.

## Important limitations

- Use only on networks, devices and websites you own or have explicit permission to assess.
- TLS and HTTPS header checks are informational; they do not prove that a website is secure or vulnerable.
- The neighbor list is the local operating system's cached ARP data, not a full network scan.
- Entropy ratings are rough heuristics, not crack-time predictions.
- Gateway TLS checks may fail when a router uses a private/self-signed certificate; this does not by itself mean the router is compromised.
- Diagnostic reports can include local IP/MAC information. Review them before sharing.
- Entered passphrases are not stored in reports or sent to a server.

## Safety scope

APEX is a defensive, non-destructive toolkit. It does not perform Wi-Fi password cracking, handshake capture, deauthentication, credential attacks, exploitation, stealth scanning or unauthorized access.

## Development

Keep passwords, API tokens, private keys, `.env` files and private network reports out of Git commits.
