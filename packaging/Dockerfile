# Pigeon, built from source and shipped without one.
#
# Two stages: the first has a compiler and the second does not. A mail server
# with a toolchain inside it is a mail server that can build whatever an
# attacker uploads.

FROM rust:1.88-bookworm AS build
WORKDIR /src

# Dependencies first, so a change to the source does not rebuild the world.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked --bin pigeond --bin pigeon

FROM debian:bookworm-slim
# ca-certificates for outbound STARTTLS trust roots — Pigeon does not verify MX
# certificates (see pigeon-smtp/src/tls.rs) but the submission path in
# Milestone 7 will.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# An unprivileged user, and a state directory it owns. Port 25 inside the
# container needs no privilege; publish it with `-p 25:25`.
RUN useradd --system --home /var/lib/pigeon --create-home pigeon
COPY --from=build /src/target/release/pigeond /usr/local/bin/pigeond
COPY --from=build /src/target/release/pigeon /usr/local/bin/pigeon

USER pigeon
WORKDIR /var/lib/pigeon
VOLUME /var/lib/pigeon
ENV PIGEON_CONFIG=/etc/pigeon/pigeon.toml

# No shell form: `pigeond` is PID 1 and receives SIGTERM directly, which is what
# its graceful shutdown is written against. A shell wrapper would swallow it.
ENTRYPOINT ["/usr/local/bin/pigeond"]
