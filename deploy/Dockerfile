# Before a release, replace image tags with reviewed immutable image digests.
FROM rust:1.88.0-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin agentic-mcp

FROM debian:bookworm-slim
RUN groupadd --gid 10001 agentic && useradd --uid 10001 --gid 10001 --no-create-home agentic
COPY --from=builder /build/target/release/agentic-mcp /usr/local/bin/agentic-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/agentic-mcp"]
