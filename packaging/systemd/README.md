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

Dedicated account `ark`, state in `/var/lib/ark` (`ARK_HOME`), config in `/var/lib/ark/config/`.
