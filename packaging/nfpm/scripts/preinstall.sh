#!/bin/sh
# Create the dedicated `seagent` account before any file is unpacked (deb: preinst, rpm: %pre).
# systemd-sysusers owns this when present (postinstall.sh runs it again, idempotently); this is
# the fallback for hosts without it (containers, SysV, old distros) and runs on every install.
set -e
if ! getent passwd seagent >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        getent group seagent >/dev/null 2>&1 || groupadd -r seagent
        useradd -r -g seagent -d /var/lib/seagent -s /usr/sbin/nologin -c "seagent agent" seagent 2>/dev/null \
            || useradd -r -g seagent -d /var/lib/seagent -s /sbin/nologin -c "seagent agent" seagent
    elif command -v adduser >/dev/null 2>&1; then
        # busybox (Alpine): a system user gets no group of its own unless asked for one
        getent group seagent >/dev/null 2>&1 || addgroup -S seagent 2>/dev/null || true
        adduser -S -D -H -h /var/lib/seagent -s /sbin/nologin -G seagent seagent 2>/dev/null || true
    fi
fi
exit 0
