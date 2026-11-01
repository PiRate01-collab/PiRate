# Contributing to PiRate / Как помочь

PiRate aims to make Raspberry Pi VPN/proxy routing approachable without Linux expertise. Small, reproducible changes are preferred over broad refactors.

## Bugs and questions

**Preferred:** [Telegram PiRate](https://t.me/pirate_open), via channel comments/discussions when available. Otherwise use GitHub Issues with the supplied bug-report form.

Include the Pi model, Raspberry Pi OS version, PiRate version, reproduction steps, expected/actual behavior and a small sanitized log excerpt.

**Never** post passwords, access tokens, private VPN keys, unredacted `.ovpn`/WireGuard configs or full backups. Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Pull requests

- Keep a focused scope and describe the bug addressed.
- Preserve existing WireGuard/OpenVPN/Proxy/Direct behavior, Safe Apply/Confirm/Rollback and fail-closed.
- Do not include PPTP or experimental DNS Auto in the beta branch.
- Validate with the existing selected tests and disclose any unrun hardware/network scenarios.
- Do not attach private lab bundles, real credentials or diagnostics.

This first beta uses a clean public source snapshot; its history intentionally excludes private development/lab material.
