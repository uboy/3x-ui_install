# codex-team-lead state

- Session started: 2026-03-05
- Task: OC-001
- Classification: non-trivial
- Current phase: Startup ritual complete, beginning Research
- Latest findings:
  - `coordination/tasks.jsonl` was missing and initialized.
  - `coordination/state/` was missing and initialized.
  - Keenetic CLI reference file exists: `cli_manual_kn-2710_ru.pdf`.
- Next action:
  - Inspect project OpenConnect/ocserv configuration and scripts.

## Progress update 2026-03-05
- Created lifecycle artifacts:
  - `coordination/tasks.jsonl`
  - `.scratchpad/research.md`
  - `.scratchpad/plan.md`
- Proceeding to technical evidence collection.
## Progress update 2026-03-05 (evidence)
- Read: README.md, ARCHITECTURE.md, install.sh, modules/openconnect.sh, lib/firewall.sh, lib/cert.sh, lib/ui.sh, lib/utils.sh.
- Initial root-cause hypotheses recorded (MTU/MSS, DPD/NAT timeout, route policy, DTLS fallback behavior).
- Started Keenetic CLI PDF extraction; first pass found relevant OpenConnect command sections.
- Extracted detailed Keenetic CLI page content for:
  - `interface openconnect accept-addresses/accept-routes/authgroup/dtls`
  - `show interface`, `show interface <name> stat`
  - `show log`, `system debug`, `system log *`
- Updated checklist:
  - Context collection: completed
  - Keenetic CLI extraction: completed
  - Hypothesis-to-evidence mapping: completed
  - Keenetic debug command sequence: completed
  - Mitigation plan draft: completed
- Generated report:
  - `.scratchpad/openconnect_keenetic_debug_report.md`
- Current step:
  - Prepare final actionable command set for live verification on server + Keenetic.

## Final status update 2026-03-05
- Added runbook: `.scratchpad/openconnect_keenetic_runbook.md`
- Highest-confidence finding:
  - Regression in current `modules/openconnect.sh` settings around MTU/PMTU + fixed MSS.
- Verification status:
  - Static bash syntax check could not be executed in this environment (`bash` binary not available).
  - Live server/router verification is blocked until user runs runbook commands on target systems.

## Progress update 2026-03-05 (XUI-001)
- Completed 3x-ui deep-dive artifacts:
  - `.scratchpad/3xui_instability_report.md`
  - `.scratchpad/3xui_instability_runbook.md`
- Key observation:
  - frequent "panel disconnect" can be access-path issue (hardening -> panel private -> SSH tunnel dependency), not container crash.
- Task tracking:
  - restored `coordination/tasks.jsonl` after accidental empty write and preserved `OC-001` + `XUI-001`.
## Progress update 2026-03-05 (docs)
- Updated README.md with explicit 3x-ui operational behavior:
  - panel private by design under Hardening,
  - SSH tunnel access model,
  - troubleshooting commands for client disconnects,
  - note on Reality dest/serverNames consistency and Cloudflare option.

## Progress update 2026-03-05 (implementation)
- Implemented Cloudflare-aligned Reality defaults in `modules/xui.sh`:
  - `REALITY_DEST` default: `www.cloudflare.com:443`
  - `REALITY_SERVER_NAME` default: `www.cloudflare.com`
- Added explicit API failure logs in `lib/xui_api.sh` for:
  - `updateUser`
  - `add_inbound`
- Updated README to document new defaults and override environment variables.

## Progress update 2026-03-05 (compatibility adjustment)
- Updated auto-created Reality profile in `modules/xui.sh` to compatibility-first defaults from provided stable sample:
  - `REALITY_DEST` default -> `google.com:443`
  - `REALITY_SERVER_NAME` default -> `google.com`
  - added `REALITY_FLOW` with default empty string.
- Updated README accordingly (`REALITY_FLOW` documented).
## Progress update 2026-03-05 (new Keenetic logs)
- Parsed Keenetic disconnect window:
  - reason=disconnect
  - service unexpectedly stopped
  - reconnect completed within ~8s
- No explicit TLS/auth failure markers in excerpt.
- Need server-side ocserv log correlation at same timestamps to identify initiator/cause.
## Progress update 2026-03-05 (correlated RCA)
- Confirmed primary disconnect pattern in ocserv logs: periodic idle-timeout session closures (~20 min).
- Confirmed timezone mismatch is expected (MSK vs UTC), not clock drift.
- Identified secondary issue window: DPD timeouts + invalid DTLS decryption after MTU=1200 rollout.
