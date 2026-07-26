# Third-Party Notices

This repository is licensed under GPL-3.0-only. See `LICENSE`.

## Managed Release Components

| Component | Use | License or notice |
| --- | --- | --- |
| Mutagen 0.18.1 | Workspace synchronization | The source is MIT unless otherwise marked. Official builds from v0.17 include SSPL-licensed code; releases must include the notices matching the exact downloaded artifact. Source: https://github.com/mutagen-io/mutagen/blob/master/LICENSE |
| tmux 3.5a | Managed terminal multiplexer | ISC. Source: https://github.com/tmux/tmux/blob/master/COPYING |
| wireguard-tools 1.0.20210914 | WireGuard configuration and control | GPL-2.0-only. Source: https://git.zx2c4.com/wireguard-tools/tree/COPYING |
| wireguard-go 0.0.20250522 | macOS userspace WireGuard backend | MIT. Source: https://github.com/WireGuard/wireguard-go/blob/master/LICENSE |
| WireGuard for Windows 1.1 | Windows tunnel manager, WireGuard tools, and Wintun driver | MIT. Source: https://github.com/WireGuard/wireguard-windows/blob/master/COPYING |
| libevent 2.1.12-stable | Static tmux dependency | 3-clause BSD. Source: https://github.com/libevent/libevent/blob/master/LICENSE |
| ncurses 6.5 | Static tmux dependency | X11-style license. Source: https://invisible-island.net/ncurses/ncurses-license.html |
| libmnl 1.0.5 | Static Linux WireGuard dependency | LGPL-2.1-or-later. Source: https://netfilter.org/projects/libmnl/ |

Release archives include the source archives and license texts used to build
managed native tools. Their versions and checksums are recorded in
`dependencies/manifest.json`.

Rust crates linked into the CLI retain their upstream licenses. The exact crate
graph is recorded in `Cargo.lock`; release automation must include a
Cargo.lock-derived license inventory whenever the binaries are distributed.

## Distribution Requirements

When a release artifact redistributes third-party software, it must include:

- the exact component name and version;
- the source URL and checksum;
- the applicable license and notice text;
- any required source code, source offer, or relinking instructions.
