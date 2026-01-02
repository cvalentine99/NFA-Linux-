# NFA-Linux Deployment Guide

This guide covers various methods for deploying NFA-Linux, from simple script-based installation to Docker and CI/CD.

## Table of Contents

1.  [Prerequisites](#prerequisites)
2.  [Installation Script](#installation-script)
3.  [Manual Installation](#manual-installation)
4.  [Docker Deployment](#docker-deployment)
5.  [Building Packages](#building-packages)
6.  [CI/CD Pipeline](#cicd-pipeline)

## Prerequisites

- **OS**: Ubuntu 22.04+ or Debian 11+ recommended.
- **Permissions**: Root or `sudo` access is required for installation and live capture.
- **Dependencies**: `libpcap`, `libcap2-bin`.

## Installation Script

This is the recommended method for most users. The script handles dependency checks, user creation, directory setup, binary installation, and systemd service creation.

```bash
curl -sSL https://raw.githubusercontent.com/cvalentine99/nfa-linux/main/scripts/install.sh | sudo bash
```

To uninstall, use the corresponding script:

```bash
curl -sSL https://raw.githubusercontent.com/cvalentine99/nfa-linux/main/scripts/uninstall.sh | sudo bash
```

## Manual Installation

1.  **Download Binary**: Get the latest `nfa-linux-linux-amd64.tar.gz` from the [Releases page](https://github.com/cvalentine99/nfa-linux/releases).
2.  **Extract and Install**:
    ```bash
    tar -xvf nfa-linux-*.tar.gz
    sudo mv nfa-linux /usr/local/bin/
    ```
3.  **Set Capabilities**:
    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/nfa-linux
    ```
4.  **Create Configuration**:
    ```bash
    sudo mkdir -p /etc/nfa-linux
    sudo cp config.yaml.example /etc/nfa-linux/config.yaml
    ```

## Docker Deployment

We provide a multi-stage Dockerfile and a `docker-compose.yml` for easy containerized deployment.

### Running with Docker

```bash
# Pull the image from GitHub Container Registry
docker pull ghcr.io/cvalentine99/nfa-linux:latest

# Run the container
docker run --rm -it \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network=host \
  ghcr.io/cvalentine99/nfa-linux:latest -headless -interface eth0
```

### Using Docker Compose

The `docker-compose.yml` file orchestrates the main application and the optional Python ML sidecar.

- **Start services**:
  ```bash
  docker-compose up -d
  ```
- **Start with ML sidecar**:
  ```bash
  docker-compose --profile ml up -d
  ```
- **View logs**:
  ```bash
  docker-compose logs -f nfa
  ```

## Building Packages

The `Makefile` provides targets for building DEB, RPM, and AppImage packages.

- **Build all packages**:
  ```bash
  make package
  ```
- **Build DEB package**:
  ```bash
  make deb
  ```

This requires `fpm` and other packaging tools to be installed.

## CI/CD Pipeline

Our GitHub Actions workflow (`.github/workflows/ci.yml`) automates the entire process:

- **On Push/PR**: Runs linting, security scans, and unit tests.
- **On Tag (`v*`)**: Builds binaries, creates packages, builds and pushes a Docker image, and creates a GitHub Release with all artifacts.
- **Weekly**: Runs performance benchmarks to track regressions.
