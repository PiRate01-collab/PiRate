# Install PiRate — beginner-friendly guide

PiRate targets **compatible Raspberry Pi devices running Raspberry Pi OS Lite 64-bit**. You need a Raspberry Pi with a microSD card, a computer on the same LAN, an internet connection, and an AP-capable Wi-Fi radio. Not all Raspberry Pi models and radios have been physically tested.

> Once the archive has been transferred, install or upgrade on the Pi with just **`sudo ./install-pi.sh`**. The installer installs missing system packages when the Pi has internet access.

## 1. Set up your Raspberry Pi

In **Raspberry Pi Imager**, install **Raspberry Pi OS Lite (64-bit)** and explicitly set a username/password (for example, `pi`) and **enable SSH**. Connect the Pi to your home router using Ethernet and boot it. Both devices must be on the same LAN.

## 2. Find the Pi's IP address

**Recommended:** open your home router administration page and look for **Connected devices / DHCP clients**. Find your Pi's hostname as configured in Imager. `192.168.1.50` is an **example only**; use the address actually shown on your network.

With a screen and keyboard connected to the Pi, run:

```bash
hostname -I
```

You can also try `ping -4 raspberrypi.local` in Windows PowerShell, substituting the hostname you set in Imager (such as `pi.local`). `.local` name resolution is not available on every network.

Test SSH **on your computer** (replace username/IP):

```bash
ssh pi@192.168.1.50
```

Accept the host key when first connecting, then use the password from Raspberry Pi Imager. If login fails, check the IP address, username and SSH enablement first.

## 3. Download and transfer the release files

On **your computer**, download these two files from GitHub Releases **once the release is published**:

- `pirate-0.5.9-beta.1.tar.gz`
- `pirate-0.5.9-beta.1.tar.gz.sha256`

### Windows: drag and drop with WinSCP

1. Open [WinSCP](https://winscp.net/); select **SFTP**.
2. Enter the Pi's IP (e.g. `192.168.1.50`), SSH port `22`, the username you set in Imager (`pi` in the example) and its password.
3. In the remote/right pane, open `/home/pi/` (or `/home/YOUR_USERNAME/`).
4. Drag **both downloaded files** from Windows Downloads to that folder.

### Windows: built-in PowerShell instead

Run **on your Windows PC**:

```powershell
scp "$env:USERPROFILE\Downloads\pirate-0.5.9-beta.1.tar.gz" "$env:USERPROFILE\Downloads\pirate-0.5.9-beta.1.tar.gz.sha256" pi@192.168.1.50:/home/pi/
```

In Windows CMD, use `%USERPROFILE%` instead of `$env:USERPROFILE`.

### macOS / Linux

Run **on your computer**:

```bash
scp ~/Downloads/pirate-0.5.9-beta.1.tar.gz ~/Downloads/pirate-0.5.9-beta.1.tar.gz.sha256 pi@192.168.1.50:/home/pi/
```

Replace the username, IP and destination home directory with your actual values.

## 4. Install PiRate on the Raspberry Pi

Connect via SSH (or use the Pi's local terminal):

```bash
ssh pi@192.168.1.50
```

The following commands run **on the Raspberry Pi**:

```bash
cd ~
sha256sum -c pirate-0.5.9-beta.1.tar.gz.sha256
tar -xzf pirate-0.5.9-beta.1.tar.gz
cd pirate-0.5.9-beta.1
sudo ./install-pi.sh
```

The checksum command should report `OK`. If extraction uses a different folder name, use `ls` to check. The installer auto-detects the standard network setup and installs missing dependencies. When interface selection is truly ambiguous, it stops rather than disrupting SSH/WAN connectivity.

## 5. Open WebUI

With a browser running **on the Pi**: **http://127.0.0.1:8765**.

On **your computer**, open a **second** terminal/PowerShell window:

```bash
ssh -N -L 127.0.0.1:8765:127.0.0.1:8765 pi@192.168.1.50
```

Leave that terminal open and browse to **http://127.0.0.1:8765** on your computer. Default WebUI username: `admin`; set/change its password on the Pi with `sudo pirate passwd`.

Configure the AP and VPN/proxy profile via WebUI, then **Apply** and **Confirm** when connectivity is verified. Client connectivity may remain blocked until confirmation by design.

## Troubleshooting

- **Can't find your Pi?** Check the router's DHCP client list or run `hostname -I` on the Pi.
- **SSH or SCP says Permission denied?** Check IP, username, password and SSH configuration in Imager.
- **Transfer fails?** Upload into the user's home folder, not a root-only system directory.
- **WebUI doesn't load?** Keep the SSH tunnel open and use `127.0.0.1`, not the Pi's IP, in your browser URL.
- **Diagnostics?** Use `pirate status` on the Pi and the WebUI **Logs** tab. Do not share passwords, private keys or unredacted VPN configurations.

**Bug reports:** [PiRate Telegram](https://t.me/pirate_open) is preferred when comments/discussions are available, with GitHub Issues as a fallback. Report security issues privately according to [SECURITY.md](SECURITY.md).

