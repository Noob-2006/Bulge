#!/bin/sh
# deb: postinst $1=configure | rpm: %post $1=1 (install) / 2 (upgrade). Never starts the daemon:
# a package that opens a network-capable agent without the operator's configuration is wrong.
# Layout (ent-008, seagent_core::layout::system): config /etc/seagent, state /var/lib/seagent,
# cache /var/cache/seagent, logs /var/log/seagent, runtime /run/seagent.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then systemd-sysusers /usr/lib/sysusers.d/seagent.conf 2>/dev/null || true; fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/seagent.conf 2>/dev/null || true
fi
# Hosts where tmpfiles did not (or could not) run: same directories, same modes.
for d in /var/lib/seagent /var/lib/seagent/workspace /var/cache/seagent /var/log/seagent; do
    [ -d "$d" ] || { mkdir -p "$d" && chown seagent:seagent "$d" 2>/dev/null && chmod 0750 "$d"; } || true
done
chown root:seagent /etc/seagent 2>/dev/null && chmod 1770 /etc/seagent 2>/dev/null || true
# ent-008 migration: before this layout the system instance ran with SEAGENT_HOME=/var/lib/seagent and kept
# its config in /var/lib/seagent/config. Copy (never move) it to /etc/seagent once; seagent itself keeps
# reading the old directory until /etc/seagent/config.toml exists, and data stays where it is.
old=/var/lib/seagent/config
if [ -f "$old/config.toml" ] && [ ! -e /etc/seagent/config.toml ]; then
    for f in config.toml secrets.toml secrets.enc secrets.key .env; do
        [ -e "$old/$f" ] && [ ! -e "/etc/seagent/$f" ] && cp -p "$old/$f" "/etc/seagent/$f" || true
    done
    echo "seagent: copied the system config from $old to /etc/seagent (the old copy is kept; seagent config path shows what is used)"
fi
# Rename (ark → SE Agent): the pre-rename package `ark-agent` kept config in /etc/ark and state
# in /var/lib/ark under the `ark` account. Config is copied (never moved; root-owned policy
# stays root-owned); state moves once, while the new state directory holds nothing but what
# this script just created. The old account is left for the operator to remove.
if [ -d /etc/ark ] && [ ! -e /etc/seagent/config.toml ]; then
    for f in config.toml secrets.toml secrets.enc secrets.key .env managed.toml; do
        [ -e "/etc/ark/$f" ] && [ ! -e "/etc/seagent/$f" ] && cp -p "/etc/ark/$f" "/etc/seagent/$f" || true
    done
    [ -d /etc/ark/managed.d ] && cp -pR /etc/ark/managed.d/. /etc/seagent/managed.d/ 2>/dev/null || true
    for f in config.toml secrets.toml secrets.enc secrets.key .env; do
        [ -e "/etc/seagent/$f" ] && chown seagent:seagent "/etc/seagent/$f" 2>/dev/null || true
    done
    echo "seagent: copied the configuration from /etc/ark to /etc/seagent (ark is now SE Agent; /etc/ark is kept)"
fi
if [ -d /var/lib/ark ] && [ -z "$(ls -A /var/lib/seagent 2>/dev/null | grep -v '^workspace$')" ] && [ -z "$(ls -A /var/lib/seagent/workspace 2>/dev/null)" ]; then
    rmdir /var/lib/seagent/workspace 2>/dev/null || true
    if mv /var/lib/ark/* /var/lib/ark/.[!.]* /var/lib/seagent/ 2>/dev/null || [ -n "$(ls -A /var/lib/seagent)" ]; then
        chown -R seagent:seagent /var/lib/seagent 2>/dev/null || true
        echo "seagent: moved the state from /var/lib/ark to /var/lib/seagent"
    fi
    mkdir -p /var/lib/seagent/workspace && chown seagent:seagent /var/lib/seagent/workspace 2>/dev/null || true
fi
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files arkd.service >/dev/null 2>&1 && systemctl is-enabled arkd.service >/dev/null 2>&1; then
    systemctl disable --now arkd.service >/dev/null 2>&1 || true
    echo "seagent: the old arkd.service was disabled; start seagentd as shown below"
fi
# ent-025: the packaged unit is rendered for a current systemd. An older manager (RHEL/CentOS 7 =
# 219) gets the same unit rewritten by seagent itself, so the text never drifts from ops/service.rs.
if command -v systemctl >/dev/null 2>&1 && [ -x /usr/bin/seagent ]; then
    if env -u SEAGENT_HOME -u SEAGENT_PROFILE -u SEAGENT_MODE /usr/bin/seagent service print --system > /usr/lib/systemd/system/seagentd.service.new 2>/dev/null \
        && [ -s /usr/lib/systemd/system/seagentd.service.new ]; then
        mv -f /usr/lib/systemd/system/seagentd.service.new /usr/lib/systemd/system/seagentd.service
    else
        rm -f /usr/lib/systemd/system/seagentd.service.new
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        case "$1" in 2|upgrade|configure)
            # an upgrade restarts a daemon that is already running; it never starts a stopped one
            systemctl try-restart seagentd.service >/dev/null 2>&1 || true ;;
        esac
    fi
fi
cat <<MSG
seagent installed: config /etc/seagent, state /var/lib/seagent, logs /var/log/seagent (seagent config path). Next:
  1. sudo -u seagent seagent setup bootstrap      (turns on the local web console, 127.0.0.1:8640)
  2. systemctl enable --now seagentd
  3. sudo -u seagent seagent setup link           (one-time link to the browser setup wizard)
     unattended instead: sudo -u seagent seagent setup --non-interactive --provider ... --model ...
  4. organisation policy (optional): /etc/seagent/managed.toml  (example: /etc/seagent/managed.toml.example)
MSG
exit 0
