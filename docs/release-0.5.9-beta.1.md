# PiRate v0.5.9-beta.1 — First public beta


The first public beta of **PiRate**, an open-source Raspberry Pi OS (64-bit) Wi-Fi hotspot with a browser-based VPN/proxy router interface.

### Included

- **Direct, WireGuard, OpenVPN, SOCKS5 and HTTP Proxy** profiles.
- Wi-Fi AP configuration and connection management in WebUI 2.0.
- Linux-style connection logs and diagnostic exports.
- Safe Apply / Confirm / Rollback and fail-closed policies.
- One-command install/upgrade with automatic Debian dependency handling.
- A simpler installer summary for first-time users.
- MIT license, © 2026 PiRate01-collab.

**Not included:** PPTP, ISP DNS Auto and experimental gateway functionality.

### Install

Follow the [beginner-friendly installation guide](https://github.com/PiRate01-collab/PiRate/blob/main/INSTALL.en.md) to find your Raspberry Pi IP address and transfer the release archive + checksum from your PC (Windows, macOS or Linux).

After transferring both files, run **on the Raspberry Pi**:

```bash
cd ~
sha256sum -c pirate-0.5.9-beta.1.tar.gz.sha256
tar -xzf pirate-0.5.9-beta.1.tar.gz
cd pirate-0.5.9-beta.1
sudo ./install-pi.sh
```

The installer displays the WebUI access instructions. By default, connect through an SSH tunnel to `http://127.0.0.1:8765`. 

### Compatibility

Intended for **compatible Raspberry Pi devices with Raspberry Pi OS Lite 64-bit**, currently targeting Debian Trixie. The available real-device evidence involves Raspberry Pi 4; all models and radios have **not** been validated. A separate AP-capable radio and safe WAN/SSH access are required.

### Known limitations

- This is a **beta**, not a stable release.
- Isolated real-tunnel health checks for WireGuard/OpenVPN are not available in the evaluated rc4 base. Do not treat DNS/TCP reachability as a working VPN.
- Physical tests of the **repackaged beta.1** have not yet been confirmed.
- The full historical test-discovery suite did not pass in the rc4 approval report. The failures include outdated/laboratory tests and sandbox socket limitations; they still need to be correctly classified and documented.

### Validation

- Rebuilt beta.1 Python tests: **110 passed**.
- Rebuilt beta.1 WebUI tests: **39 passed**.
- Selected rc4 source tests: **274 passed** (earlier evidence, not rerun).
- Rebuilt beta.1 manifest and SHA256: **passed**. rc4 extracted upgrade/rollback were previously tested; full beta.1 installation on hardware has not been verified.
- Historical suite: **932 run, 6 failures, 48 errors**; not a full green suite.


### Report bugs

**Preferred: [Telegram PiRate](https://t.me/pirate_open)** (comments/discussions where available). Otherwise use GitHub Issues. Include the Pi model, OS/version and sanitized error logs. **Never** publish credentials or private keys. Security problems must go through the repository's private vulnerability reporting workflow.

**Repository / tag:** `PiRate01-collab/PiRate` · `v0.5.9-beta.1` · **Pre-release**.
