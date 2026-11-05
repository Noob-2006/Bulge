#!/bin/sh
# deb: postinst $1=configure | rpm: %post $1=1 (install) / 2 (upgrade). Never starts the daemon:
# a package that opens a network-capable agent without the operator's configuration is wrong.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then systemd-sysusers /usr/lib/sysusers.d/ark.conf 2>/dev/null || true; fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/ark.conf 2>/dev/null || true
fi
# Hosts where tmpfiles did not (or could not) run: same directories, same modes.
for d in /var/lib/ark /var/lib/ark/workspace; do
    [ -d "$d" ] || { mkdir -p "$d" && chown ark:ark "$d" 2>/dev/null && chmod 0750 "$d"; } || true
done
# ent-025: the packaged unit is rendered for a current systemd. An older manager (RHEL/CentOS 7 =
# 219) gets the same unit rewritten by ark itself, so the text never drifts from ops/service.rs.
if command -v systemctl >/dev/null 2>&1 && [ -x /usr/bin/ark ]; then
    if env -u ARK_HOME -u ARK_PROFILE /usr/bin/ark service print --system > /usr/lib/systemd/system/arkd.service.new 2>/dev/null \
        && [ -s /usr/lib/systemd/system/arkd.service.new ]; then
        mv -f /usr/lib/systemd/system/arkd.service.new /usr/lib/systemd/system/arkd.service
    else
        rm -f /usr/lib/systemd/system/arkd.service.new
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        case "$1" in 2|upgrade|configure)
            # an upgrade restarts a daemon that is already running; it never starts a stopped one
            systemctl try-restart arkd.service >/dev/null 2>&1 || true ;;
        esac
    fi
fi
cat <<MSG
ark installed. Next:
  1. put your provider settings in /var/lib/ark/config/config.toml  (sudo -u ark ark setup ...)
  2. systemctl enable --now arkd
  3. organisation policy (optional): /etc/ark/managed.toml  (example: /etc/ark/managed.toml.example)
MSG
exit 0
