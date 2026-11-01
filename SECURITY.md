# Security Policy / Политика безопасности

PiRate is a network router. Do not expose the WebUI, management APIs, SSH credentials or private VPN profiles to the public internet. Use the documented SSH tunnel for local administration and keep fail-closed / rollback protection enabled.

## Reporting security vulnerabilities

**Do not open a public GitHub Issue or Telegram discussion for a vulnerability**, particularly when it includes credentials, bypass techniques or private logs.

Before public release the repository owner must enable **GitHub Private Vulnerability Reporting** (GitHub repository → Settings → Security → Code security and analysis / Private vulnerability reporting, where available). When enabled, use the repository's **Security → Report a vulnerability** action.

If private reporting is not configured, publication should be paused until a verified private security contact is provided. Do not invent an email address or ask people to disclose vulnerabilities publicly.

## Safe diagnostics

- Remove passwords, access tokens, SSH/VPN private keys and full VPN configs before sharing logs.
- Sanitized ZIPs may still contain IP addresses, hostnames and other environment details: review them manually.
- Do not attach live backups or credential stores to public bug reports.
- If an issue concerns the ordinary installer or connection errors rather than a security vulnerability, prefer the [PiRate Telegram channel](https://t.me/pirate_open) where comments are enabled, or GitHub Issues.

## Supported versions

The first proposed supported public version is **v0.5.9-beta.1** (pre-release). Security fixes and support policy may evolve as initial bug reports arrive.
