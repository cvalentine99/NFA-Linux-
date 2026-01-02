# NFA-Linux Multi-Stage Dockerfile
# Next-Generation Network Forensic Analyzer
# 
# Build: docker build -t nfa-linux:latest .
# Run:   docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host nfa-linux:latest

# ============================================================================
# Stage 1: Frontend Builder
# ============================================================================
FROM node:22-alpine AS frontend-builder

WORKDIR /app/frontend

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy package files first for better caching
COPY frontend/package.json frontend/pnpm-lock.yaml* ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy frontend source
COPY frontend/ ./

# Build frontend
RUN pnpm run build

# ============================================================================
# Stage 2: Go Builder
# ============================================================================
FROM golang:1.22-bookworm AS go-builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    pkg-config \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Copy built frontend from previous stage
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Build arguments for version info
ARG VERSION=0.1.0
ARG BUILD_TIME
ARG GIT_COMMIT

# Build the application
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.BuildTime=${BUILD_TIME}' -X 'main.GitCommit=${GIT_COMMIT}'" \
    -trimpath \
    -o /app/nfa-linux \
    ./main_app.go

# ============================================================================
# Stage 3: Production Runtime
# ============================================================================
FROM debian:bookworm-slim AS production

# Labels
LABEL maintainer="NFA-Linux Team <team@nfa-linux.io>"
LABEL org.opencontainers.image.title="NFA-Linux"
LABEL org.opencontainers.image.description="Next-Generation Network Forensic Analyzer for Linux"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/cvalentine99/nfa-linux"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd --system --gid 1000 nfa-linux \
    && useradd --system --uid 1000 --gid nfa-linux --home-dir /app --shell /sbin/nologin nfa-linux

# Create directories
RUN mkdir -p /app/data /app/output /app/logs /app/config \
    && chown -R nfa-linux:nfa-linux /app

WORKDIR /app

# Copy binary from builder
COPY --from=go-builder /app/nfa-linux /app/nfa-linux

# Copy default config
COPY --chown=nfa-linux:nfa-linux <<EOF /app/config/config.yaml
# NFA-Linux Docker Configuration
capture:
  interface: ""
  mode: "afpacket"
  snaplen: 65535
  promiscuous: true
  bpf_filter: ""
  ring_buffer_size: 67108864
  batch_size: 64
  num_workers: 0

reassembly:
  max_buffered_pages_per_connection: 4000
  max_buffered_pages_total: 150000
  max_connections: 100000
  flush_interval: "30s"

carver:
  output_dir: "/app/output/carved"
  max_file_size: 104857600
  enable_hashing: true
  hash_algorithm: "blake3"

evidence:
  output_dir: "/app/output/evidence"
  enable_timestamps: true

ml:
  enable: false
  sidecar_address: "nfa-ml:50051"

logging:
  level: "info"
  file: "/app/logs/nfa.log"
EOF

# Set capabilities (requires --cap-add at runtime)
# Note: setcap doesn't persist in Docker images, capabilities must be granted at runtime

# Expose ports (if needed for future web interface)
EXPOSE 8080

# Volumes for persistent data
VOLUME ["/app/data", "/app/output", "/app/logs", "/app/config"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/nfa-linux", "-version"]

# Default to headless mode
ENTRYPOINT ["/app/nfa-linux"]
CMD ["-headless", "-config", "/app/config/config.yaml"]

# ============================================================================
# Stage 4: Development Runtime (optional)
# ============================================================================
FROM production AS development

USER root

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    curl \
    wget \
    vim \
    less \
    procps \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

USER nfa-linux

# Override for development
CMD ["-headless", "-config", "/app/config/config.yaml", "-debug"]
