# ZHTP Network Node - Production Build
FROM rust:1.83-slim-bookworm AS builder

# Install only essential build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy dependency files first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY contracts/Cargo.toml ./contracts/

# Create dummy source files to build dependencies
RUN mkdir -p src contracts/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/network_service.rs && \
    echo "// dummy" > src/lib.rs && \
    echo "// dummy" > contracts/src/lib.rs

# Build dependencies first (this layer will be cached)
RUN cargo build --release --bin zhtp --bin zhtp-dev && \
    rm -rf src contracts/src target/release/deps/decentralized_network* target/release/deps/contracts*

# Copy actual source code and config
COPY src ./src
COPY contracts ./contracts

# Build the actual application
RUN cargo build --release --bin zhtp --bin zhtp-dev

# Minimal runtime image
FROM debian:bookworm-slim AS runtime

# Install only essential runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create zhtp user
RUN useradd -m -u 1000 zhtp
WORKDIR /home/zhtp

# Copy only the binaries we need
COPY --from=builder /app/target/release/zhtp ./bin/zhtp
COPY --from=builder /app/target/release/zhtp-dev ./bin/zhtp-dev

# Copy configuration files directly from host
COPY deploy/docker-config/ ./config/

# Set up directories and permissions
RUN mkdir -p data logs && chown -R zhtp:zhtp /home/zhtp
USER zhtp

# Expose ports
EXPOSE 8080 9080

# Set environment variables
ENV ZHTP_DATA_DIR=/home/zhtp/data
ENV ZHTP_LOG_DIR=/home/zhtp/logs
ENV ZHTP_CONFIG_DIR=/home/zhtp/config
ENV RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9080/health || exit 1

# Default command
CMD ["./bin/zhtp", "--config", "./config/full.json"]
