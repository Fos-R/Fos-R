FROM rust:1.83.0

WORKDIR /usr/src/generation

# Install libs with apt cache mount
RUN --mount=type=cache,target=/var/cache/apt --mount=type=cache,target=/var/lib/apt \
    apt-get update && apt-get install -y libpcap-dev

COPY generation/Cargo.toml generation/Cargo.lock ./

# Cache the build of dependencies by faking an empty src/lib.rs
RUN mkdir src && touch src/lib.rs
RUN cargo build --release

COPY models ../models

COPY generation/src src
RUN cargo build --release

ENV RUST_LOG=trace

ENTRYPOINT ["./target/release/fosr"]
CMD ["online", "--interfaces", "eth0"]
