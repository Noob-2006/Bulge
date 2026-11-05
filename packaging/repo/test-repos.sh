#!/usr/bin/env bash
# End-to-end proof of the signed repositories (ent-027/028): throwaway key -> repos -> served on
# loopback -> a real apt client (debian:12) and a real dnf client (rockylinux:9) install ark with
# signature checking ON, and a tampered repository is refused. Needs podman|docker, gpg, python3,
# dpkg-deb (host) and a dist directory with the .deb/.rpm from packaging/nfpm/build-packages.sh.
#
#   test-repos.sh DIST_DIR
set -euo pipefail
PROG=$(basename "$0")
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DIST=$(cd "${1:?usage: $PROG DIST_DIR}" && pwd)
RT=$(command -v podman || command -v docker)
W=$(mktemp -d "${TMPDIR:-/tmp}/ark-repotest.XXXXXX")
G=$W/gnupg; mkdir -m 700 "$G"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    gpgconf --homedir "$G" --kill all 2>/dev/null || true
    "$RT" rm -f ark-test-pkg-repo-apt ark-test-pkg-repo-yum ark-test-pkg-repo-bad >/dev/null 2>&1 || true
    rm -rf "$W"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

gpg --homedir "$G" --batch --quiet --passphrase '' --quick-generate-key "ark test repo key <test@invalid>" ed25519 sign never 2>/dev/null
KID=$(gpg --homedir "$G" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
mkdir -p "$W/debs" "$W/rpms" "$W/www"
cp "$DIST"/*.deb "$W/debs/"; cp "$DIST"/*.rpm "$W/rpms/"

"$HERE/make-apt-repo.py" --debs "$W/debs" --out "$W/www/apt" --key-id "$KID" --gnupghome "$G" >/dev/null
"$HERE/make-yum-repo.sh" --rpms "$W/rpms" --out "$W/www/rpm" --key-id "$KID" --gnupghome "$G" --base-url "http://127.0.0.1:__PORT__/rpm" --container >/dev/null
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
sed -i "s/__PORT__/$PORT/" "$W/www/rpm/ark.repo"
( cd "$W/www" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) & PIDS+=($!)
sleep 1

echo "== apt client (debian:12), signed-by keyring"
"$RT" run --rm --name ark-test-pkg-repo-apt --network=host docker.io/library/debian:12 sh -ec "
  apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends wget ca-certificates >/dev/null
  mkdir -p /etc/apt/keyrings
  wget -qO /etc/apt/keyrings/ark.gpg http://127.0.0.1:$PORT/apt/ark-archive-keyring.gpg
  echo 'deb [signed-by=/etc/apt/keyrings/ark.gpg] http://127.0.0.1:$PORT/apt stable main' > /etc/apt/sources.list.d/ark.list
  apt-get update 2>&1 | grep -E '127.0.0.1' | head -3
  apt-get install -y --no-install-recommends ark-agent >/dev/null
  dpkg -S /usr/bin/ark | grep -q ark-agent
  ark --version
" || fail "apt install from the signed repository"

echo "== apt client refuses a repository signed by another key"
G2=$W/gnupg2; mkdir -m 700 "$G2"
gpg --homedir "$G2" --batch --quiet --passphrase '' --quick-generate-key "other <o@invalid>" ed25519 sign never 2>/dev/null
KID2=$(gpg --homedir "$G2" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
"$HERE/make-apt-repo.py" --debs "$W/debs" --out "$W/www/apt-bad" --key-id "$KID2" --gnupghome "$G2" >/dev/null
bad_out=$("$RT" run --rm --name ark-test-pkg-repo-bad --network=host docker.io/library/debian:12 sh -c "
  apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends wget ca-certificates >/dev/null
  mkdir -p /etc/apt/keyrings; wget -qO /etc/apt/keyrings/ark.gpg http://127.0.0.1:$PORT/apt/ark-archive-keyring.gpg
  test -s /etc/apt/keyrings/ark.gpg   # the trusted key IS installed; only the repository's signature differs
  echo 'deb [signed-by=/etc/apt/keyrings/ark.gpg] http://127.0.0.1:$PORT/apt-bad stable main' > /etc/apt/sources.list.d/ark.list
  apt-get update 2>&1 | grep -E 'ark|127.0.0.1|GPG|signed' ; if apt-get install -y ark-agent >/dev/null 2>&1; then echo INSTALLED-FROM-BAD-REPO; fi
" 2>&1) || true
echo "$bad_out" | tail -4
case "$bad_out" in *INSTALLED-FROM-BAD-REPO*) fail "an apt repository signed by a foreign key was accepted" ;; esac
echo "$bad_out" | grep -qiE 'not signed|NO_PUBKEY|signatures couldn' || fail "expected apt to complain about the signature"
echo "ok: refused"

echo "== dnf client (rockylinux:9), gpgcheck=1 repo_gpgcheck=1"
"$RT" run --rm --name ark-test-pkg-repo-yum --network=host docker.io/library/rockylinux:9 sh -ec "
  cp /dev/null /etc/yum.repos.d/ark.repo
  curl -fsS http://127.0.0.1:$PORT/rpm/ark.repo -o /etc/yum.repos.d/ark.repo
  sed -i 's|gpgkey=.*|gpgkey=http://127.0.0.1:$PORT/rpm/RPM-GPG-KEY-ark|' /etc/yum.repos.d/ark.repo
  dnf install -y --setopt=install_weak_deps=False ark-agent 2>&1 | tail -4
  ark --version
  rpm -q ark-agent
  rpm -qi ark-agent | grep -E '^Signature' 
" || fail "dnf install from the signed repository"
echo "OK: apt + dnf repositories verify and install; foreign signature refused"
