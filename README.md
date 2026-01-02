# NFA-Linux: Next-Generation Network Forensic Analyzer

![NFA-Linux Banner](https://i.imgur.com/your-banner.png) <!-- Replace with actual banner -->

**NFA-Linux** is a high-performance, forensically-sound network analysis tool built with Go and Wails. It's designed for security professionals, incident responders, and network administrators who need deep packet inspection, real-time analysis, and advanced forensic capabilities at 10Gbps+ speeds.

[![Build Status](https://github.com/cvalentine99/nfa-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/cvalentine99/nfa-linux/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cvalentine99/nfa-linux)](https://goreportcard.com/report/github.com/cvalentine99/nfa-linux)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Key Features

- **High-Speed Packet Capture**: Utilizes AF_XDP for zero-copy packet capture, with AF_PACKET fallback for broader compatibility.
- **Comprehensive Protocol Analysis**: Deep parsing of dozens of protocols, including TLS (JA3/JA4), QUIC/HTTP3, SMBv2/v3, and more.
- **Real-Time TCP Reassembly**: Memory-safe TCP stream reassembly with configurable limits to prevent memory exhaustion.
- **File Carving & Extraction**: Automatically carves and extracts over 40 file types from network traffic.
- **Forensic Integrity**: Employs BLAKE3 hashing for high-speed integrity checks and RFC 3161 for cryptographic timestamps.
- **AI/ML-Powered Threat Detection**: A hybrid architecture using Go-native ONNX Runtime for low-latency tasks and a Python gRPC sidecar for complex models (anomaly detection, traffic classification).
- **Modern Forensic Dashboard**: A Wails-based UI built with React and TailwindCSS, featuring virtualized tables for millions of rows, a 3D network topology graph, and real-time visualizations.
- **Flexible Deployment**: Supports a GUI mode, a powerful headless CLI mode, systemd service integration, and Docker containerization.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Wails Frontend                          │
│                    (React + TailwindCSS + WebGL)                │
└─────────────────────────────────────────────────────────────────┘
                                │
                          Wails Events
                                │
┌─────────────────────────────────────────────────────────────────┐
│                          Go Backend                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐  │
│  │  Capture  │  │ Reassembly│  │  Parsers  │  │   Analysis    │  │
│  │  Engine   │──│  Engine   │──│ (L3-L7)   │──│ (Carver, ML)  │  │
│  │ (AF_XDP)  │  │   (TCP)   │  └───────────┘  └───────────────┘  │
│  └───────────┘  └───────────┘                                   │
│         │                                                       │
│  ┌───────────┐                                                  │
│  │   eBPF    │                                                  │
│  │  Filters  │                                                  │
│  └───────────┘                                                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                           Kernel Space
                                │
┌─────────────────────────────────────────────────────────────────┐
│                        Network Interface                        │
└─────────────────────────────────────────────────────────────────┘
```

## Getting Started

### Installation

Download the latest `.deb` or `.tar.gz` from the [Releases page](https://github.com/cvalentine99/nfa-linux/releases) or use the one-line installer:

```bash
# This will install the binary, create a systemd service, and set necessary capabilities.
curl -sSL https://raw.githubusercontent.com/cvalentine99/nfa-linux/main/scripts/install.sh | sudo bash
```

### Docker

```bash
# Pull the latest image
docker pull ghcr.io/cvalentine99/nfa-linux:latest

# Run in headless mode, capturing on host's eth0
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host \
  ghcr.io/cvalentine99/nfa-linux:latest -headless -interface eth0
```

### Quick Start

- **GUI Mode**: `nfa-linux`
- **Headless Capture**: `sudo nfa-linux -headless -interface eth0`
- **Analyze PCAP**: `nfa-linux -headless -pcap capture.pcap`
- **Start Service**: `sudo systemctl start nfa-linux`

For detailed usage, see the [User Manual](./docs/USER_MANUAL.md).

## Building from Source

### Requirements

- Go 1.22+
- Wails v2.8+
- Node.js 22+ & pnpm 9+
- Linux Kernel 5.4+ (for AF_XDP)
- `build-essential`, `libpcap-dev`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`

### Build Steps

```bash
# Clone the repository
git clone https://github.com/cvalentine99/nfa-linux.git
cd nfa-linux

# Build the application (uses the Makefile)
make build

# Run the binary
sudo ./build/bin/nfa-linux
```

## Documentation

- [**User Manual**](./docs/USER_MANUAL.md): Detailed usage instructions for all modes.
- [**Deployment Guide**](./docs/DEPLOYMENT.md): Guides for Docker, systemd, and packaging.
- [**Development Guide**](./docs/DEVELOPMENT.md): How to build, test, and contribute.
- [**Testing Strategy**](./docs/TESTING_STRATEGY.md): Overview of our testing and QA process.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](./CONTRIBUTING.md) for more details on submitting PRs, reporting issues, and our code of conduct.

## License

NFA-Linux is licensed under the [MIT License](./LICENSE).
