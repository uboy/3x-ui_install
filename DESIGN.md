# 3x-ui Installer Design

## Classification
- Task type: non-trivial (new production installer, security decisions, multi-phase setup).

## Goal
- Provide one idempotent Ubuntu 24.04 script that installs and configures Docker + 3x-ui with secure defaults and certificate auto-renewal.
- Use interactive input as the primary startup mode, so secrets are not passed via command line.
- Configure panel credentials, optional panel 2FA, and optional inbound creation directly from console/API.

## Architecture
1. Interactive input collection at the beginning (domain, email, ports, SSH params, panel creds/current creds, optional 2FA and inbound params).
2. Preflight and input validation.
3. User and SSH hardening.
4. Host fail2ban for SSH.
5. Docker and Compose install.
6. 3x-ui compose deployment with persistent volumes.
7. Panel API detection and credential apply (API-first fallback flow).
8. UFW policy and inbound port openings.
9. Deferred SSH restart after UFW enable.
10. Let's Encrypt issue and deploy hook into mounted 3x-ui cert path.
11. Optional API setup: enable panel 2FA and create inbound.
12. Systemd timer for cert renewal.
13. Post-install health checks and output of access details.

## Security Decisions
- Panel ports `2053`/`2096` denied by default (`EXPOSE_PANEL_PUBLIC=false`).
- Root SSH login disabled.
- `AllowUsers` enforced.
- Password set via hash (`openssl passwd -6`) to safely support special characters.
- fail2ban enabled for `sshd` with `ufw` action.
- Mandatory passwordless sudo for the selected user through `/etc/sudoers.d/90-3xui-<user>` with `NOPASSWD:ALL`.
- Existing explicit users keep their password unless operator set a new one; if account has no usable password, script generates a strong one.
- Panel secret handling avoids passing sensitive values as plain CLI values where possible (file-backed form fields for API calls).

## Idempotency
- Reuses existing user/container/paths when present.
- `certbot --keep-until-expiring` prevents unnecessary re-issue.
- Renew handled via persistent systemd timer + deploy hook.
- If user already exists, script ensures sudo group membership and `NOPASSWD` sudo rule without recreating user.
- Inbound auto-create checks existing same-port/same-protocol inbound before adding a new one.
