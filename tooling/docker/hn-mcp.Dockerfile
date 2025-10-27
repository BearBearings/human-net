# syntax=docker/dockerfile:1.5

FROM rust:1.77-bullseye AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY cli/ cli/
COPY services/ services/
COPY planning/ planning/
COPY runtime/ runtime/
COPY samples/ samples/
COPY spec/ spec/
COPY tooling/ tooling/

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --bin hn --bin mcp

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENV HN_HOME=/var/lib/human-net
WORKDIR /opt/human-net
RUN mkdir -p /usr/local/bin /etc/human-net ${HN_HOME}

COPY --from=builder /src/target/release/hn /usr/local/bin/hn
COPY --from=builder /src/target/release/mcp /usr/local/bin/mcp

VOLUME ["/var/lib/human-net"]
EXPOSE 7733

ENTRYPOINT ["hn", "mcp", "serve"]
