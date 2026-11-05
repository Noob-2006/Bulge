# systemd units

`ops/service.rs` (`ark service print [--system]`) is the single source of the unit text.
`arkd.service`, `arkd-system.service`, `ark-sysusers.conf` and `ark-tmpfiles.conf` here are generated
from it (the `packaged_units_are_generated_from_the_one_source` test fails when they drift;
`ARK_BLESS=1 cargo test -p ark packaged_units` rewrites them). `nix/nixos.nix` mirrors the system
unit's hardening list and is checked by another test.

System instance (what a package installs; `ark service install --system` prints the same steps):

    sudo install -m 644 ark-sysusers.conf /usr/lib/sysusers.d/ark.conf && systemd-sysusers
    sudo install -m 644 ark-tmpfiles.conf /usr/lib/tmpfiles.d/ark.conf && systemd-tmpfiles --create
    sudo install -m 644 arkd-system.service /etc/systemd/system/arkd.service
    sudo systemctl enable --now arkd

Dedicated account `ark`; FHS layout (`ARK_MODE=system`, see docs/paths.md): config and secrets in
`/etc/ark` (root:ark 1770, next to the root-owned policy), state in `/var/lib/ark`, cache in
`/var/cache/ark`, logs in `/var/log/ark`, socket in `/run/ark`. Installs from before ent-008
(`ARK_HOME=/var/lib/ark`) keep working; their config is read from `/var/lib/ark/config` until
`/etc/ark/config.toml` exists.
