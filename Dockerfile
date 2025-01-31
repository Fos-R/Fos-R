FROM rust:1.83.0

WORKDIR /usr/src/generation

# Install libs with apt cache mount
RUN --mount=type=cache,target=/var/cache/apt --mount=type=cache,target=/var/lib/apt \
    apt-get update && apt-get install -y libpcap-dev iproute2 inetutils-ping tcpdump

COPY generation/Cargo.toml generation/Cargo.lock ./
RUN mkdir src && touch src/lib.rs
RUN cargo build --release

COPY models ../models

COPY generation/src src
RUN cargo build --release

CMD ["cargo", "run", "--release", "--", "online"]
