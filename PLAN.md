# Implementation Plan

1. Add interactive prompt block at script start for all required inputs and validate them.
2. Keep env-based fallback for non-interactive mode without exposing secrets by default.
3. Implement username generation/validation compatible with `/etc/adduser.conf` `NAME_REGEX`.
4. Ensure existing explicit user handling: verify/add sudo group membership and `NOPASSWD` sudo.
5. Implement secure password flow: hidden input, default strong generated password, hash-based apply, and existing-user usable-password check.
6. Add SSH hardening and fail2ban `sshd` jail.
7. Install Docker + Compose and deploy 3x-ui with `/opt/3x-ui/{db,cert}` volumes.
8. Add panel API detection + panel credential apply flow from console-provided values.
9. Configure UFW for SSH, web, and inbound ports; keep panel private by default.
10. Defer SSH daemon restart until after UFW enable to reduce lockout risk.
11. Add Certbot issuance + deploy script + `3xui-cert-renew.timer`.
12. Add optional panel 2FA enable and optional inbound creation via 3x-ui API.
13. Expand final output with resulting credentials, links, and next setup actions.
14. Run available local checks (syntax/lint/grep checks if tooling exists in environment).
