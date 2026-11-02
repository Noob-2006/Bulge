# syntax=docker/dockerfile:1
# Build: docker build -t ark .
# Run:   docker run -d --init -p 127.0.0.1:8640:8640 -v ark-data:/data \
#          -e ARK_APP_TOKEN=… -v ./config.toml:/data/config/config.toml:ro ark
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
ENV ARK_HOME=/data XDG_RUNTIME_DIR="" ARK_APP_ENABLED=1
VOLUME ["/data", "/work"]
USER ark
WORKDIR /work
EXPOSE 8640
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD ["ark", "health"]
# tini reaps MCP servers / bridges the agent starts.
ENTRYPOINT ["/usr/bin/tini", "--", "ark"]
# Inside the container the app server must bind 0.0.0.0; publish it on 127.0.0.1 only.
# Without ARK_APP_TOKEN (or an [app] token) the daemon exits with an error saying so.
CMD ["daemon", "run", "-w", "/work", "--set", "app.listen=0.0.0.0:8640"]
