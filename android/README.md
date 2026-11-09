# APEX Android (Native Kotlin)

This is the first native Android companion for the APEX defensive network auditor.

## Build APK

The repository includes a GitHub Actions workflow at `.github/workflows/android-apk.yml`.
It builds a debug APK whenever Android source changes are pushed, or when manually started from the Actions tab.

1. Open the repository on GitHub.
2. Select **Actions** → **Build APEX Android APK** → **Run workflow**.
3. Open the completed run and download the **APEX-debug-apk** artifact.
4. Extract the ZIP and install `app-debug.apk` on your Android phone.

## Termux source setup

```sh
pkg update -y
pkg install git -y
git clone https://github.com/cnfoysalx/apex-wifi-security.git
cd apex-wifi-security
```

To update source later:

```sh
git pull
```

A full native Android build directly inside Termux requires a compatible Android SDK, build-tools, Gradle and JDK setup; this workflow uses a standard Android build runner to avoid unreliable SDK/aapt2 setup on-device. Termux is used to manage and inspect the source, while GitHub Actions compiles the APK.

## Included in v1.0

- Dark Compose dashboard
- Local interface/IP overview
- DNS lookup
- TLS certificate handshake validation
- Offline passphrase heuristic
- Secure passphrase generator
- Router hardening checklist

Only assess networks and websites you own or are authorized to test. This initial build does not perform Wi-Fi scanning, cracking, packet capture or router configuration changes.
