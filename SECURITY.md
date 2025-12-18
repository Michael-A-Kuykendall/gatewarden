# Security Policy

Gatewarden’s purpose is security-sensitive license validation. If you find a vulnerability, please disclose it responsibly.

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities.

Report privately via one of:

- GitHub Security Advisories (preferred, if enabled for the repo)
- Email: michaelallenkuykendall@gmail.com (subject: "SECURITY: Gatewarden")

## What to include

- Description and impact
- Steps to reproduce
- Affected versions / commit hash
- Any suggested remediation

## Notes

Gatewarden verifies Keygen responses via public-key cryptography. The client should never ship Keygen admin tokens or any private signing material.
