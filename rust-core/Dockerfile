# NOTE: written for a standard Debian-based Rust image with a current
# toolchain. This project's OWN development sandbox only had rustc
# 1.75.0 available (see docs/dependency-rationale.md) and had no Docker
# daemon to test this file against — it has NOT been built or run in
# this session. It is provided as a best-effort starting point per the
# project brief's "Docker where practical" requirement; please verify it
# builds in your environment and adjust the base image tag if needed.
FROM rust:1.79-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin iod-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/iod-server /usr/local/bin/iod-server
ENV IOD_BIND_ADDR=0.0.0.0:8787
ENV IOD_DB_PATH=/data/iod_simulation.db
VOLUME ["/data"]
EXPOSE 8787
CMD ["iod-server"]
