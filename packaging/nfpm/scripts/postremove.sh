#!/bin/sh
# Config in /etc/seagent, state in /var/lib/seagent and the `seagent` account are deliberately kept (sessions, audit log, secrets):
# removing a package must not destroy evidence. `purge` of the data is an explicit operator step.
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
case "$1" in
    purge|0) echo "seagent: /etc/seagent (config, secrets), /var/lib/seagent, /var/cache/seagent, /var/log/seagent and the 'seagent' account were kept. To erase them: rm -rf /var/lib/seagent /var/cache/seagent /var/log/seagent /etc/seagent/config.toml /etc/seagent/secrets.* && userdel seagent" ;;
esac
exit 0
