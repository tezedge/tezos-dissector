FROM ubuntu:19.10

RUN apt-get update && DEBIAN_FRONTEND='noninteractive' apt-get install -y \
    wget git pkg-config clang make wireshark-dev

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2020-07-12; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME;

WORKDIR /usr/local/tezos-dissector

COPY . .

RUN cargo build --release
