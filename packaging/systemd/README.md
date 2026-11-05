# systemd units

`ops/service.rs` (`seagent service print [--system]`) is the single source of the unit text.
`seagentd.service`, `seagentd-system.service`, `seagent-sysusers.conf` and `seagent-tmpfiles.conf` here are generated
from it (the `packaged_units_are_generated_from_the_one_source` test fails when they drift;
`SEAGENT_BLESS=1 cargo test -p seagent packaged_units` rewrites them). `nix/nixos.nix` mirrors the system
unit's hardening list and is checked by another test.

System instance (what a package installs; `seagent service install --system` prints the same steps):

    sudo install -m 644 seagent-sysusers.conf /usr/lib/sysusers.d/seagent.conf && systemd-sysusers
    sudo install -m 644 seagent-tmpfiles.conf /usr/lib/tmpfiles.d/seagent.conf && systemd-tmpfiles --create
    sudo install -m 644 seagentd-system.service /etc/systemd/system/seagentd.service
    sudo systemctl enable --now seagentd

Dedicated account `seagent`; FHS layout (`SEAGENT_MODE=system`, see docs/paths.md): config and secrets in
`/etc/seagent` (root:seagent 1770, next to the root-owned policy), state in `/var/lib/seagent`, cache in
`/var/cache/seagent`, logs in `/var/log/seagent`, socket in `/run/seagent`. Installs from before ent-008
(`SEAGENT_HOME=/var/lib/seagent`) keep working; their config is read from `/var/lib/seagent/config` until
`/etc/seagent/config.toml` exists.
