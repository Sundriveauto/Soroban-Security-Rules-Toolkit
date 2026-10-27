# Static stellar-guard binary in an empty image.
#   docker run --rm -v "$PWD:/src" ghcr.io/petermuazu/stellar-guard scan .
FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p stellar-guard \
    && strip target/release/stellar-guard

FROM scratch
LABEL org.opencontainers.image.title="stellar-guard" \
      org.opencontainers.image.description="Static security analysis for Soroban smart contracts" \
      org.opencontainers.image.source="https://github.com/petermuazu/Soroban-Security-Rules-Toolkit" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=build /build/target/release/stellar-guard /usr/local/bin/stellar-guard
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/stellar-guard"]
CMD ["scan", "."]
