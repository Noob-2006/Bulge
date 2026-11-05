# SE Agent container

    docker build -t SE Agent .
    docker run -d --init --name seagent -v seagent-data:/data -v "$PWD":/work SE Agent
    docker exec -it SE Agent seagent chat

The default command (`seagent daemon run -w /work`) always starts: the daemon runs headless and the
app server is off, so the container opens no network port. `/usr/share/seagent` holds the bundled
skills, roles, catalogs and the VM/sandbox-browser build sources (`SEAGENT_SHARE_DIR`).

## Web / app API

The app server refuses a non-loopback bind unless every exposure layer is configured, so a plain
`-p 8640:8640` with `--set app.listen=0.0.0.0:8640` does not work (by design). Two supported ways:

1. **Proxy sidecar** — `compose.yml`: SE Agent listens on loopback inside the container, a Caddy
   container in the same network namespace terminates TLS and is the only thing published.
2. **Public bind** — mount `config.public.toml` as `/data/config/config.toml` (token, `self_hosted`
   auth, allowed origins, `behind_proxy = true`), and put a TLS proxy in front yourself.

`config.public.toml` is checked against the app server's start-up policy by a unit test.
