#!/bin/sh
# Runs INSIDE a distro container (POSIX sh; CentOS 7 and busybox included). Prints one line per
# step:  RESULT <step> <ok|fail|skip> <detail>   and exits 0 when no step failed.
#   inner.sh <deb|rpm|pacman|apk|tar> <fake-provider-port>
# /dist (read-only) holds the package(s) / tarball. The fake model server runs on the HOST and is
# reached through the host network namespace (127.0.0.1:<port>); nothing leaves the machine.
KIND=$1 PORT=$2
FAILED=0
res() { printf 'RESULT %s %s %s\n' "$1" "$2" "$3"; [ "$2" = fail ] && FAILED=1; return 0; }

if [ -n "${PRE:-}" ]; then sh -c "$PRE" >/dev/null 2>&1 || true; fi
. /etc/os-release 2>/dev/null; res os ok "${PRETTY_NAME:-unknown} / glibc-or-musl: $(ldd --version 2>&1 | head -1 | cut -c1-60)"

# ---- 1. install --------------------------------------------------------------------------
ARCH=$(uname -m)
case "$KIND" in
  deb)
    DEB=$(ls /dist/seagent_*_amd64.deb | head -1)
    export DEBIAN_FRONTEND=noninteractive
    if apt-get install -y --no-install-recommends "$DEB" >/tmp/install.log 2>&1; then res install ok "apt-get install $(basename "$DEB")"
    else res install fail "$(tail -3 /tmp/install.log | tr '\n' ' ')"; fi ;;
  rpm)
    RPM=$(ls /dist/seagent-*.x86_64.rpm | head -1)
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y --nogpgcheck --setopt=install_weak_deps=False "$RPM" >/tmp/install.log 2>&1 && how="dnf install"
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive --no-gpg-checks install --no-recommends "$RPM" >/tmp/install.log 2>&1 && how="zypper install"
    elif command -v yum >/dev/null 2>&1; then
        yum --disablerepo='*' -y --nogpgcheck localinstall "$RPM" >/tmp/install.log 2>&1 && how="yum localinstall"
    fi
    if [ -z "${how:-}" ]; then
        # package managers whose repositories are unreachable/EOL (CentOS 7): the rpm itself is the test
        if rpm -Uvh "$RPM" >>/tmp/install.log 2>&1; then how="rpm -Uvh (package manager repos unavailable)"; fi
    fi
    if [ -n "${how:-}" ]; then res install ok "$how $(basename "$RPM")"; else res install fail "$(tail -3 /tmp/install.log | tr '\n' ' ')"; fi ;;
  pacman)
    PKG=$(ls /dist/seagent-*-x86_64.pkg.tar.zst | head -1)
    if pacman -U --noconfirm "$PKG" >/tmp/install.log 2>&1; then res install ok "pacman -U $(basename "$PKG")"
    else res install fail "$(tail -3 /tmp/install.log | tr '\n' ' ')"; fi ;;
  apk)
    APK=$(ls /dist/seagent_*_x86_64.apk | head -1)
    if apk add --allow-untrusted "$APK" >/tmp/install.log 2>&1; then res install ok "apk add $(basename "$APK")"
    else res install fail "$(tail -3 /tmp/install.log | tr '\n' ' ')"; fi ;;
  tar)
    T=$(ls /dist/seagent-x86_64-unknown-linux-musl.tar.gz | head -1)
    if tar -xzf "$T" -C /usr/local; then res install ok "tar -xzf $(basename "$T") -C /usr/local"; else res install fail "tar"; fi
    # tarball installs have no scriptlets: the account/dirs are the operator's (or the Ansible role's) job
    if command -v adduser >/dev/null 2>&1; then adduser -S -D -H -h /var/lib/seagent -s /sbin/nologin seagent 2>/dev/null; fi
    mkdir -p /var/lib/seagent && chown seagent /var/lib/seagent 2>/dev/null ;;
esac
SEAGENT=$(command -v seagent || echo /usr/bin/seagent)
[ -x "$SEAGENT" ] || { res binary fail "no seagent on PATH"; exit 1; }

# ---- 2. layout --------------------------------------------------------------------------
if [ "$KIND" != tar ]; then
  miss=""
  for p in /usr/bin/seagent /usr/share/seagent/blueprints.json /usr/share/seagent/skills /usr/share/seagent/roles /usr/share/seagent/managed-by-package /etc/seagent/managed.d /usr/lib/systemd/system/seagentd.service /usr/lib/sysusers.d/seagent.conf /usr/lib/tmpfiles.d/seagent.conf; do
      [ -e "$p" ] || miss="$miss $p"
  done
  if [ "$KIND" = apk ] && [ ! -x /etc/init.d/seagentd ]; then miss="$miss /etc/init.d/seagentd"; fi
  [ -z "$miss" ] && res layout ok "/usr/bin /usr/share/seagent /etc/seagent units" || res layout fail "missing:$miss"
  if getent passwd seagent >/dev/null 2>&1; then
      own=$(stat -c %U /var/lib/seagent 2>/dev/null || echo none)
      [ "$own" = seagent ] && res account ok "user seagent, /var/lib/seagent owned by seagent" || res account fail "/var/lib/seagent owner=$own"
  else res account fail "user seagent was not created"; fi
fi

# ---- 3. version ---------------------------------------------------------------------------
v=$("$SEAGENT" --version 2>&1); [ $? -eq 0 ] && res version ok "$v" || res version fail "$v"

# ---- 4. service unit (rendered for this host's systemd) -------------------------------------
if [ "$KIND" != tar ] && command -v systemctl >/dev/null 2>&1; then
    sv=$(systemctl --version 2>/dev/null | head -1)
    U=/usr/lib/systemd/system/seagentd.service
    if [ -n "$sv" ]; then
        n=$(echo "$sv" | awk '{print $2}' | sed 's/[^0-9].*//')
        if [ "${n:-999}" -lt 229 ]; then
            if grep -q '^StartLimitInterval=' "$U" && ! grep -q '^StartLimitIntervalSec=' "$U" && ! grep -q '^RestrictSUIDSGID' "$U"; then res unit-degrade ok "$sv: StartLimitInterval in [Service], unknown directives dropped"
            else res unit-degrade fail "$sv but the unit was not rewritten"; fi
        else
            if grep -q '^StartLimitIntervalSec=' "$U"; then res unit-degrade ok "$sv: current unit kept"; else res unit-degrade fail "$sv: unexpected unit"; fi
        fi
        if command -v systemd-analyze >/dev/null 2>&1; then
            a=$(systemd-analyze verify "$U" 2>&1 | grep -v 'Failed to\|bus\|Cannot\|not-found\|user seagent\|Unknown user' | head -3)
            [ -z "$a" ] && res unit-verify ok "systemd-analyze verify clean" || res unit-verify fail "$(echo "$a" | tr '\n' ' ')"
        else res unit-verify skip "no systemd-analyze in this image"; fi
    else res unit-degrade skip "systemctl present but no version output"; fi
else
    res unit-degrade skip "no systemctl in this image"
fi
if [ -d /run/systemd/system ]; then res service skip "systemd is present but not PID 1 in a rootless container?"; else res service skip "no systemd as PID 1 in the container (daemon start not exercised)"; fi

# ---- 5. doctor ---------------------------------------------------------------------------
H=/tmp/seagent-matrix-home; rm -rf $H; mkdir -p $H/config $H/ws; chmod 777 $H $H/ws $H/config
ENVV="SEAGENT_HOME=$H SEAGENT_OFFLINE=1 NO_COLOR=1 XDG_RUNTIME_DIR= HOME=$H"
d=$(env $ENVV "$SEAGENT" doctor 2>&1); rc=$?
# doctor exits 1 when it has findings (a fresh box always has some); 0/1 are answers, anything else is a crash
if [ $rc -le 1 ]; then res doctor ok "exit $rc: $(echo "$d" | tail -1 | cut -c1-90)"; else res doctor fail "exit $rc: $(echo "$d" | tail -2 | tr '\n' ' ' | cut -c1-160)"; fi
case "$d" in *"bundled share"*|*share*) : ;; esac
echo "$d" | grep -qi 'share' && res doctor-share ok "doctor reports the bundled share/" || res doctor-share skip "no share line in doctor output"

# ---- 6. unattended setup, then one offline conversation ---------------------------------------
S=$(env $ENVV SEAGENT_SETUP_API_KEY=sk-test-not-a-key "$SEAGENT" setup --non-interactive --no-service --provider openai --model fake-model --base-url "http://127.0.0.1:$PORT/v1" 2>&1); rc=$?
[ $rc -eq 0 ] && res setup ok "seagent setup --non-interactive (config.toml + vault)" || res setup fail "exit $rc: $(echo "$S" | tail -2 | tr '\n' ' ')"
# the e2e rig's provider block (tests/e2e/run.py) on top of what setup wrote
cat > $H/config/config.toml <<CONF
[model]
default = "fake/fake-model"
max_tokens = 1024
[providers.fake]
format = "openai_chat"
base_url = "http://127.0.0.1:$PORT/v1"
api_key_env = "FAKE_KEY"
[exec]
backend = "local"
CONF
out=$(cd $H/ws && env $ENVV FAKE_KEY=test-key-not-secret "$SEAGENT" run "say pong" 2>&1); rc=$?
case "$out" in *"pong from the fake model"*) res chat ok "seagent run -> fake model replied (exit $rc)" ;; *) res chat fail "exit $rc: $(echo "$out" | tail -3 | tr '\n' ' ' | cut -c1-200)" ;; esac

# ---- 7. the service account can run it (the way the unit does) ----------------------------------
if [ "$KIND" != tar ] && getent passwd seagent >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then AS="runuser -u seagent --"
    elif command -v setpriv >/dev/null 2>&1 && setpriv --help 2>&1 | grep -q reuid; then AS="setpriv --reuid=seagent --regid=seagent --clear-groups"
    elif command -v su >/dev/null 2>&1; then AS=su
    else AS=""; fi
    if [ -z "$AS" ]; then res as-service-user skip "no runuser/setpriv/su in this image"
    else
        if [ "$AS" = su ]; then o=$(su -s /bin/sh seagent -c "SEAGENT_HOME=/var/lib/seagent SEAGENT_OFFLINE=1 $SEAGENT --version" 2>&1); rc=$?
        else o=$(env SEAGENT_HOME=/var/lib/seagent SEAGENT_OFFLINE=1 $AS "$SEAGENT" --version 2>&1); rc=$?; fi
        [ $rc -eq 0 ] && res as-service-user ok "$o" || res as-service-user fail "$o"
    fi
fi

# ---- 8. removal keeps the data -------------------------------------------------------------------
if [ "$KIND" = deb ]; then dpkg -r seagent >/tmp/rm.log 2>&1 && rm_ok=1; fi
if [ "$KIND" = rpm ]; then rpm -e seagent >/tmp/rm.log 2>&1 && rm_ok=1; fi
if [ "$KIND" = pacman ]; then pacman -R --noconfirm seagent >/tmp/rm.log 2>&1 && rm_ok=1; fi
if [ "$KIND" = apk ]; then apk del seagent >/tmp/rm.log 2>&1 && rm_ok=1; fi
if [ "$KIND" != tar ]; then
    if [ "${rm_ok:-}" = 1 ] && [ ! -e /usr/bin/seagent ] && [ -d /var/lib/seagent ]; then res remove ok "binary gone, /var/lib/seagent kept"; else res remove fail "$(tail -2 /tmp/rm.log | tr '\n' ' ')"; fi
fi
exit $FAILED
