#!/bin/sh
# deb: prerm $1=remove|upgrade|... | rpm: %preun $1=0 (erase) / 1 (upgrade).
set -e
case "$1" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop arkd.service >/dev/null 2>&1 || true
            systemctl disable arkd.service >/dev/null 2>&1 || true
        fi ;;
esac
exit 0
