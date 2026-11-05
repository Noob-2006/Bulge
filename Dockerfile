# syntax=docker/dockerfile:1
# Build: docker build -t ark .
# Run:   docker run -d --init --name ark -v ark-data:/data -v "$PWD":/work ark
#        docker exec -it ark ark chat
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin ark

# debian-slim, not distroless: the agent runs real shell commands, git, node bridges.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates bash git curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 -s /bin/bash ark \
 && mkdir -p /data /work && chown ark:ark /data /work
COPY --from=builder /app/target/release/ark /usr/local/bin/ark
# Bundled skills, roles, plugin catalog, optional MCPs, VM image builder, sandbox-browser sources:
# ark finds /usr/share/ark at run time (ark_core::share), same layout as the release tarball.
COPY --from=builder /app/share/ /usr/share/ark/
COPY --from=builder /app/packaging/vm/build-image.sh /app/packaging/vm/README.md /usr/share/ark/vm/
COPY --from=builder /app/packaging/sandbox-browser/ /usr/share/ark/sandbox-browser/
ENV ARK_HOME=/data XDG_RUNTIME_DIR="" ARK_SHARE_DIR=/usr/share/ark
VOLUME ["/data", "/work"]
USER ark
WORKDIR /work
EXPOSE 8640
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD ["ark", "health"]
# tini reaps MCP servers / bridges the agent starts.
ENTRYPOINT ["/usr/bin/tini", "--", "ark"]
# Safe default that always starts: the daemon runs headless (talk to it with `docker exec -it
# <name> ark chat`, or through the chat channels in /data/config/config.toml). The app server
# stays off, so nothing listens on the network.
#
# To use the web/app API, pick one (details: packaging/docker/README.md):
#   1. loopback inside the container + a reverse proxy in the same network namespace
#      (packaging/docker/compose.yml): -e ARK_APP_ENABLED=1 -e ARK_APP_TOKEN=…
#   2. a public bind (0.0.0.0) is only accepted with every layer of A9 configured (token, strong
#      auth, allow_origins, TLS-terminating proxy): mount packaging/docker/config.public.toml
#      as /data/config/config.toml. A bare `--set app.listen=0.0.0.0:8640` is refused.
CMD ["daemon", "run", "-w", "/work"]
