FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        git \
        libegl1-mesa-dev \
        libgl1-mesa-dev \
        libssl-dev \
        libwayland-dev \
        libx11-dev \
        libxcb-render0-dev \
        libxcb-shape0-dev \
        libxcb-xfixes0-dev \
        libxcb1-dev \
        libxkbcommon-dev \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY assets ./assets
COPY src ./src

RUN cargo build --release --bin aiacs \
    && cargo build --release --bin aiacs_diagnostics

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libegl1 \
        libfontconfig1 \
        libfreetype6 \
        libgl1 \
        libssl3 \
        libvulkan1 \
        libwayland-client0 \
        libx11-6 \
        libxcb-render0 \
        libxcb-shape0 \
        libxcb-xfixes0 \
        libxcb1 \
        libxkbcommon0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p \
        /app/attacker_artifacts \
        /app/diagnostic_results \
        /app/recovery_artifacts \
        /app/report_exports \
        /app/keys

COPY --from=builder /app/target/release/aiacs /usr/local/bin/aiacs
COPY --from=builder /app/target/release/aiacs_diagnostics /usr/local/bin/aiacs_diagnostics

ENV RUST_LOG=info

# Validation examples:
# docker run --rm aiacs:final aiacs_diagnostics
# docker run --rm aiacs:final aiacs
CMD ["aiacs_diagnostics"]
