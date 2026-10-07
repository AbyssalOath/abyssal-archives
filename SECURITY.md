# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub Security
Advisories: on this repository, open **Security → Report a vulnerability**
(private vulnerability reporting). Do not open a public issue for security
problems.

Include what you found, how to reproduce it, the affected version/commit,
and the impact you expect. If you have a fix, attach it to the advisory
rather than opening a public pull request.

## What to expect

- Acknowledgement within **7 days**.
- An initial assessment (severity, affected versions) within **14 days**.
- A fix or mitigation as soon as practical; for serious issues the aim is
  **30 days**. You will be kept informed and credited in the advisory unless
  you prefer otherwise.
- Coordinated disclosure: the advisory is published once a fixed release is
  available.

## Supported versions

Only the latest release (the default branch) receives security fixes.
Upgrade by pulling the latest version and re-running `./install.sh` (see the
README, "Upgrading").

## Scope

The application, its Docker images and compose files, the install and
helper scripts. Third-party services the deployment talks to (Cloudflare,
VPN providers, mirror hosts) are out of scope; report to them directly.

See docs/SECURITY-REVIEW.md for the hardening review and docs/PRIVACY.md for
what the application collects.
