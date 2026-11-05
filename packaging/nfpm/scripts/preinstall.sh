#!/bin/sh
# Create the dedicated `ark` account before any file is unpacked (deb: preinst, rpm: %pre).
# systemd-sysusers owns this when present (postinstall.sh runs it again, idempotently); this is
# the fallback for hosts without it (containers, SysV, old distros) and runs on every install.
set -e
if ! getent passwd ark >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        getent group ark >/dev/null 2>&1 || groupadd -r ark
        useradd -r -g ark -d /var/lib/ark -s /usr/sbin/nologin -c "ark agent" ark 2>/dev/null \
            || useradd -r -g ark -d /var/lib/ark -s /sbin/nologin -c "ark agent" ark
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -h /var/lib/ark -s /sbin/nologin ark 2>/dev/null || true
    fi
fi
exit 0
