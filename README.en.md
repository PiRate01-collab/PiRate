# PiRate — Raspberry Pi VPN Router & Wi-Fi Hotspot

**PiRate** is an open-source Wi-Fi hotspot and VPN/proxy router for **compatible Raspberry Pi devices running Raspberry Pi OS 64-bit**. Manage **WireGuard, OpenVPN, SOCKS5, HTTP proxy and Direct** through a simple local WebUI.

[Русский README](README.md) · [Telegram — preferred bug reports](https://t.me/pirate_open) · [GitHub Issues](https://github.com/PiRate01-collab/PiRate/issues/new/choose)

> **v0.5.9-beta.1 — first public beta (Pre-release).** This is not a stable release. Prior hands-on testing used Raspberry Pi 4; compatibility with every Raspberry Pi model or Wi-Fi chipset is **not** verified.

## Features

- Raspberry Pi Wi-Fi hotspot with an AP-capable radio.
- Direct, WireGuard, OpenVPN, SOCKS5 and HTTP Proxy profiles.
- Local WebUI for Wi-Fi, connection management and readable Linux-style logs.
- Apply/Confirm/Rollback and fail-closed connection safety.
- One-command installer with automatic dependency installation on standard configurations.

**PPTP is not included in this release.**

## Requirements

- Compatible Raspberry Pi running **Raspberry Pi OS Lite 64-bit (ARM64)**, currently targeting Debian Trixie.
- Internet uplink, SSH access and `sudo`.
- An AP-capable Wi-Fi radio that is not used by WAN or SSH.
- Internet access during installation to fetch missing Debian packages.

Some devices with multiple suitable Wi-Fi radios may require manual interface selection. The installer should fail safely rather than disconnecting a management interface.

## Install / upgrade

**[Beginner guide: find your Raspberry Pi IP address, transfer files from your computer, and install PiRate](INSTALL.en.md).** Includes Windows drag-and-drop with WinSCP, PowerShell SCP, and macOS/Linux instructions.

Briefly, download `pirate-0.5.9-beta.1.tar.gz` and its `.sha256` from GitHub Releases **after publication**, copy **both files onto the Raspberry Pi** over SFTP/SCP, and run **on the Pi**:

```bash
cd ~
sha256sum -c pirate-0.5.9-beta.1.tar.gz.sha256
tar -xzf pirate-0.5.9-beta.1.tar.gz
cd pirate-0.5.9-beta.1
sudo ./install-pi.sh
```

The same command handles upgrades. Missing dependencies are installed automatically when possible; saved settings are retained and a backup is created. These filenames are not live download links yet.

## Open WebUI

On the Pi itself, when a browser is available, open `http://127.0.0.1:8765`. From Windows, macOS or Linux, run this command on **your computer** (using your actual SSH credentials and Pi address):

```bash
ssh -N -L 127.0.0.1:8765:127.0.0.1:8765 USER@PI_ADDRESS
```

Keep the terminal open and browse to **http://127.0.0.1:8765**. Default WebUI username: `admin`. Set or change its password locally using `sudo pirate passwd`.

## First connection

Set up the Wi-Fi hotspot, create or import a WireGuard/OpenVPN configuration or proxy profile, **Apply** the change and **Confirm** after connectivity succeeds. Saving a profile does not activate it. A clean install keeps AP/client routing disabled until explicitly confirmed.

The Logs tab contains connection diagnostics and downloadable sanitized logs. Proxy health checks validate an actual HTTPS request through the proxy and its external IPv4 address. Isolated end-to-end WireGuard/OpenVPN checks are not included in this beta; simple endpoint reachability is not proof that a VPN works.

## Bugs, support and security

**Preferred bug-report channel: [PiRate Telegram](https://t.me/pirate_open)**, via channel discussions/comments **where available**. If you cannot submit there, use [GitHub Issues](https://github.com/PiRate01-collab/PiRate/issues/new/choose).

Include Raspberry Pi model, Raspberry Pi OS version, PiRate version, reproduction steps and a small **sanitized** log excerpt. Never post passwords, private keys, tokens, complete VPN configs or backups. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) and use a **private** reporting channel, not public Telegram or Issues.

## FAQ

**Does PiRate support every Raspberry Pi?** It targets compatible hardware running Raspberry Pi OS 64-bit with a suitable AP radio; not all models and radios have been tested.

**Can I use Raspberry Pi as a WireGuard/OpenVPN Wi-Fi router?** Yes. PiRate configures an access point and selected VPN/proxy profiles through WebUI with explicit Apply/Confirm.

**Do I need to install dependencies manually?** Normally no — the installer installs missing packages when the Pi can reach its package repositories.

**Why is the UI not listening on my Pi's LAN IP?** It defaults to loopback for SSH-tunnel access, to avoid exposing administrative UI on the network.

## Documentation

[Installation](INSTALL.en.md) · [Configuration](CONFIGURATION.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[MIT License](LICENSE) — © 2026 **PiRate01-collab**.
