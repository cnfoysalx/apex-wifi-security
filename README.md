# APEX Wi-Fi Security Toolkit

A Termux-friendly toolkit for **authorized, defensive Wi-Fi and network security checks**.

## Project status

Initial repository scaffold. The next step is to add and test the APEX Python modules from the Termux project.

## Planned capabilities

- Local network and gateway inventory
- Connectivity, DNS, and latency diagnostics
- Router security configuration checklist
- Offline Wi-Fi passphrase strength assessment
- Secure passphrase generation
- JSON reports that do not store entered passwords

## Safety scope

Use this toolkit only on networks and devices you own or have explicit permission to assess.

This project does not provide Wi-Fi password cracking, handshake capture, deauthentication, credential attacks, or unauthorized access features.

## Environment

Designed for Android Termux with Python 3.

```bash
pkg update -y
pkg install python git -y
git clone https://github.com/cnfoysalx/apex-wifi-security.git
cd apex-wifi-security
```

## Development

Contributions should preserve the defensive-only scope. Test changes on your own devices and avoid committing secrets, passwords, tokens, or private network data.

## License

License to be selected.
