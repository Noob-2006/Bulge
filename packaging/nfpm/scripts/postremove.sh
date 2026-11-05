#!/bin/sh
# State in /var/lib/ark and the `ark` account are deliberately kept (sessions, audit log, secrets):
# removing a package must not destroy evidence. `purge` of the data is an explicit operator step.
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
case "$1" in
    purge|0) echo "ark: /var/lib/ark and the 'ark' account were kept. To erase them: rm -rf /var/lib/ark && userdel ark" ;;
esac
exit 0
