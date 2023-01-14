FROM rust:1.65.0-bullseye AS chef

RUN cargo install cargo-chef --locked --version 0.1.51

WORKDIR /workspace

FROM chef AS planner

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

RUN mkdir /output && cp recipe.json /output/

FROM chef AS builder

COPY --from=planner /output/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

RUN cargo build --release

RUN mkdir /output && mv target/release/gramine-cli /output/

FROM ubuntu:20.04

RUN sed -i 's/archive.ubuntu.com/mirrors.tencent.com/g' /etc/apt/sources.list &&\
  sed -i 's/security.ubuntu.com/mirrors.tencent.com/g' /etc/apt/sources.list

RUN apt update && apt install -y libssl-dev

COPY --from=builder /output/* /usr/bin/

ENTRYPOINT ["gramine-cli"]
