# build stage
FROM rust AS builder
WORKDIR /usr/src/dn42-roa-generator
RUN apt-get update
RUN apt-get -y install lld
# https://www.aloxaf.com/2018/09/reduce_rust_size/
RUN apt-get -y install binutils
RUN wget https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz
RUN tar -xf upx-4.2.4-amd64_linux.tar.xz

COPY ./src ./src
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

RUN cargo build --release
RUN strip target/release/dn42-roa-generator
RUN ./upx-4.2.4-amd64_linux/upx --best target/release/dn42-roa-generator

# production stage
FROM debian:stable-slim
RUN apt-get update
COPY --from=builder /usr/src/dn42-roa-generator/target/release/dn42-roa-generator /usr/local/bin/dn42-roa-generator
CMD ["dn42-roa-generator"]
