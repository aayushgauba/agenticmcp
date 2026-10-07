FROM rust:1.88-bookworm AS rust
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vendor ./vendor
RUN cargo build --locked --release --bin agentic-mcp

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
ARG COPILOT_VERSION=1.0.92
RUN npm install --global @github/copilot@${COPILOT_VERSION} && npm cache clean --force
COPY --from=rust /build/target/release/agentic-mcp /usr/local/bin/agentic-mcp
COPY tools/injection-sandbox /opt/harness
USER node
WORKDIR /tmp
ENTRYPOINT ["node", "/opt/harness/worker.mjs"]
