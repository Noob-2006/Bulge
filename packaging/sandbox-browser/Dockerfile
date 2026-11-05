# syntax=docker/dockerfile:1
# ark sandbox browser image: Chromium + Xvfb + x11vnc + noVNC behind an
# authenticated CDP relay (OpenClaw `scripts/docker/sandbox/Dockerfile.browser`, MIT).
#
# Build (podman works too):
#   docker build -t ark-sandbox-browser:trixie-slim packaging/sandbox-browser
#
# `crates/ark-browser` refuses to start a container whose image is missing (=stale)
# this contract label, so bump CONTRACT in crates/ark-browser/src/sandbox.rs and the
# label below together whenever the entrypoint's environment contract changes.
FROM debian:trixie-slim

LABEL org.ark.sandbox-browser.contract="2026-11-cdp-relay-auth"
LABEL org.opencontainers.image.title="ark sandbox browser"
LABEL org.opencontainers.image.description="Chromium in a container, CDP behind a Basic-auth relay, noVNC observer"
LABEL org.opencontainers.image.source="https://github.com/ark/ark/packaging/sandbox-browser"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    chromium \
    curl \
    dbus-x11 \
    fonts-liberation \
    novnc \
    python3 \
    websockify \
    x11vnc \
    xvfb \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/sandbox-browser-entrypoint.sh
RUN chmod 0755 /usr/local/bin/sandbox-browser-entrypoint.sh

# The entrypoint reads these defaults; ark overrides them per container (`docker run -e`).
ENV ARK_BROWSER_CDP_PORT=9222 \
    ARK_BROWSER_CHROME_CDP_PORT=9223 \
    ARK_BROWSER_VNC_PORT=5900 \
    ARK_BROWSER_NOVNC_PORT=6080 \
    ARK_BROWSER_ENABLE_NOVNC=1 \
    ARK_BROWSER_HEADLESS=0 \
    ARK_BROWSER_NO_SANDBOX=0 \
    ARK_BROWSER_AUTO_START_TIMEOUT_MS=12000 \
    ARK_BROWSER_PROFILE_DIR=/tmp/ark-browser-profile \
    HOME=/home/ark \
    DISPLAY=:1

# Non-root by default; Chromium's setuid sandbox helper from the Debian package still
# works (ark passes ARK_BROWSER_NO_SANDBOX=1 inside containers that lack user namespaces).
RUN useradd --create-home --uid 1000 --shell /bin/bash ark
USER ark
WORKDIR /home/ark

# 9222 = authenticated CDP relay, 6080 = noVNC websockify. 5900 (x11vnc) stays loopback-only.
EXPOSE 9222 6080

ENTRYPOINT ["/usr/local/bin/sandbox-browser-entrypoint.sh"]
