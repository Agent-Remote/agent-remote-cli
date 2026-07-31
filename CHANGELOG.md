# Changelog

All notable changes to this repository are recorded here.

## v0.1.4 - 2026-07-31

- fix: build arm64 release on compatible runner (c45fc44)

## v0.1.3 - 2026-07-31

- feat: install community-signed device app (8ef8d81)
- feat: add local device management commands (f6695a2)
- ci: run full cli checks on macos (0180e89)
- test: stabilize tunnel cleanup coverage (da46507)
- ci: isolate release tags from validation (812a4b8)

## v0.1.0 - 2026-07-31

- feat: add device install, status, diagnose, revoke, and token rotation commands
- feat: provision broker credentials without exposing device secrets
- build: pin the expected Apple Team ID in release binaries
- ci: run full cli checks on macos (0180e89)
- test: stabilize tunnel cleanup coverage (da46507)
- ci: isolate release tags from validation (812a4b8)

## v0.0.6 - 2026-07-29

- fix: compile tunnel process guards on windows (a5989bf)
- chore: release v0.0.6 (913ae79)
- feat: add secure session port forwarding (fcc9c7f)

## v0.0.5-fix.9 - 2026-07-29

- feat: elevate wireguard operations automatically (548dae1)
- fix: keep WireGuard checks portable (511a61b)
- test: cover WireGuard status paths (3af112b)

## v0.0.5-fix.8 - 2026-07-29

- feat: improve remote operations and status (70a45b1)
- ci: add codecov reporting (d079d81)

## v0.0.5-fix.7 - 2026-07-28

- fix: upgrade Windows with running Mutagen (44aaeb9)
- fix: improve Windows workdir display (f3631fa)

## v0.0.5-fix.6 - 2026-07-28

- fix: enforce managed ssh host verification (c49173f)

## v0.0.5-fix.5 - 2026-07-28

- fix: recover managed Mutagen sessions (aafa4c7)

## v0.0.5-fix.4 - 2026-07-28

- feat: add session deletion commands (5cc4dcd)

## v0.0.5-fix.3 - 2026-07-28

- fix: exclude generated python state from sync (a3d97ce)

## v0.0.5-fix.2 - 2026-07-28

- fix: isolate workspace git indexes (8ad38bb)

## v0.0.5-fix.1 - 2026-07-28

- fix: harden remote attach networking (806f65a)

## v0.0.5 - 2026-07-27

- feat: add branding and repository quality gates (a809a0b)

## v0.0.4-fix.16 - 2026-07-27

- fix: allow WireGuard service to read config (a529cea)
- fix: avoid GitHub API rate limit in Windows installer (9970c24)

## v0.0.4-fix.15 - 2026-07-26

- fix: satisfy Windows clippy (851c140)

## v0.0.4-fix.14 - 2026-07-26

- fix: resolve Windows OpenSSH tools (05b2976)
- ci: install and verify WireGuard on Windows (d824c50)
- ci: harden cross-platform install checks (978c269)
- ci: verify cross-platform CLI installation (05e47d7)

## v0.0.4-fix.13 - 2026-07-26

- fix: bundle WireGuard for Windows (89761b5)
- fix: preserve LF checkouts on Windows (9da4f3a)

## v0.0.4-fix.12 - 2026-07-26

- feat: support Windows clients (f1de6b2)
- docs: refresh third-party notices (f01c2de)

## v0.0.4-fix.11 - 2026-07-26

- feat: improve CLI help and output (1f672e0)

## v0.0.4-fix.10 - 2026-07-26

- feat: improve claude session listing (bbd4299)

## v0.0.4-fix.9 - 2026-07-24

- fix: forward authorized SSH agents (faa1f68)

## v0.0.4-fix.8 - 2026-07-24

- fix: force pty for remote attaches (a739d4a)

## v0.0.4-fix.7 - 2026-07-24

- fix: exclude Git reflogs from sync (f7de1eb)

## v0.0.4-fix.6 - 2026-07-24

- fix: exclude workspace marker from sync (2038cb9)

## v0.0.4-fix.5 - 2026-07-23

- fix: bundle Mutagen agent bootstrap dependencies (3c3c9af)

## v0.0.4-fix.4 - 2026-07-23

- fix: allocate tty for ssh attach (e5cc832)

## v0.0.4-fix.3 - 2026-07-23

- fix: refresh device token for online status (e8d55d6)

## v0.0.4-fix.2 - 2026-07-23

- fix static ncurses cross-linking (6f4a366)
- fix managed tool cross-linking (d720bf9)
- fix cross-platform managed tool builds (fba26dc)
- fix linux dependency manifest build (d19563b)
- fix token refresh and bundle managed tools (da05412)

## v0.0.4-fix.1 - 2026-07-23

- fix: generate usable wireguard client config (8804ab5)

## v0.0.4 - 2026-07-23

- feat: support runtime-aware sessions (9e5d650)
- fix: avoid GitHub API for latest installer version (f8d2940)
- fix: support piped installer execution (85b78b6)
- fix: keep release version examples in sync (8e06f86)

## v0.0.3 - 2026-07-07

- fix: update release installer docs (aca526d)
- feat: add one-click installer (696e9b7)
- docs: sync Chinese README with English (fac0b5b)
- chore: standardize release metadata (acd8c92)
- ci: allow manual release dispatch (075ea00)

## v0.0.2 - 2026-07-07

- ci: allow manual release dispatch (075ea00)
- chore: release v0.0.2 (05db10e)
- build: add release version injection and installer (93fdc5a)
