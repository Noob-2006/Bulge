# @se-agent/seagent

SE Agent (System Engineering Agent) through npm. Installing the package downloads the signed
static release binary for this machine (Linux x64 / arm64), verifies it against the release's
`SHA256SUMS`, and puts `seagent` on your PATH.

```bash
npm install -g @se-agent/seagent
seagent setup
```

Offline: `SEAGENT_NPM_TARBALL=/path/seagent-x86_64-unknown-linux-musl.tar.gz npm install -g @se-agent/seagent`.
A mirror: `SEAGENT_NPM_BASE_URL=https://mirror.example/seagent/v0.2.0-alpha`.

The npm package is a convenience wrapper; system services, audit and multi-user setups are
better served by the distribution packages (deb, rpm, pacman, apk). See
https://github.com/Noob-2006/SE-Agent/blob/main/docs/install.md.
