# APEX Enterprise Android (Native Kotlin)

APEX Enterprise is a dark-theme Android companion for authorized, non-destructive network security assessment.

## Features in v2.0

- Local Android device and IPv4 interface summary
- Explicit private IPv4 /24 LAN inventory using selected common TCP ports
- Common TCP port audit for a single RFC1918 private IPv4 target
- DNS lookup and TLS certificate handshake validation
- Router hardening checklist
- Offline passphrase heuristic and SecureRandom passphrase generator
- Shareable assessment output
- Dark Jetpack Compose interface

LAN discovery is limited to the private /24 subnet manually entered by the operator. It reports hosts responding on selected TCP ports, not every device. Port audit is restricted to private RFC1918 IPv4 targets. An open port is not automatically a vulnerability.

## Build APK

The repository includes `.github/workflows/android-apk.yml`. It builds a debug APK when Android source changes are pushed, or when manually started.

1. Open the repository on GitHub.
2. Select **Actions** → **Build APEX Android APK** → **Run workflow**.
3. Open the completed run and download the **APEX-debug-apk** artifact.
4. Extract the ZIP and install `app-debug.apk` on your Android phone. Android may ask you to allow installation from the app used to open the ZIP.

## Termux source setup

First-time setup:

    pkg update -y
    pkg install git -y
    git clone https://github.com/cnfoysalx/apex-wifi-security.git
    cd apex-wifi-security

If the folder already exists:

    cd ~/apex-wifi-security
    git pull

To inspect the Android source:

    cd ~/apex-wifi-security
    ls android

A full native Android build directly inside Termux requires a compatible Android SDK, build-tools, Gradle and JDK setup. The included GitHub Actions workflow uses a standard Android build runner; Termux manages and inspects the source while GitHub Actions compiles the APK.

## Safety and scope

Use only on networks and devices you own or have explicit permission to assess. APEX does not include Wi-Fi password cracking, handshake capture, deauthentication, exploit execution, credential theft, stealth, or unauthorized access. Router settings are not changed by the app.
