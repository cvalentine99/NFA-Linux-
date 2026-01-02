# NFA-Linux User Manual

This manual provides detailed instructions on how to use NFA-Linux, from basic setup to advanced analysis techniques.

## Table of Contents

1.  [Introduction](#introduction)
2.  [Installation](#installation)
3.  [GUI Mode](#gui-mode)
4.  [Headless (CLI) Mode](#headless-cli-mode)
5.  [Configuration](#configuration)
6.  [Troubleshooting](#troubleshooting)

## Introduction

NFA-Linux is a powerful network forensic analyzer designed for both real-time capture and post-mortem analysis of PCAP files. It offers a rich graphical user interface for interactive exploration and a robust command-line interface for automation and scripting.

## Installation

For detailed installation instructions, please refer to the [Deployment Guide](./DEPLOYMENT.md).

## GUI Mode

To start the graphical interface, simply run `nfa-linux` from your terminal or use the desktop application entry.

### Dashboard

The main dashboard provides a high-level overview of the network traffic, including:
- **Stats Cards**: Key metrics like total packets, flows, alerts, and carved files.
- **Protocol Chart**: A breakdown of traffic by protocol.
- **Traffic Timeline**: A time-series chart of network throughput.
- **Top Talkers**: Lists of top source/destination IPs and ports.
- **Recent Alerts**: A feed of the latest security alerts.

### Views

- **Packet View**: A virtualized table displaying individual packets. Supports filtering and searching.
- **Flow View**: A table of reconstructed network flows (TCP, UDP, etc.), showing metadata like JA4 fingerprints.
- **File View**: A list of all files carved from the network traffic.
- **Alert View**: A detailed list of all generated security alerts.
- **Topology View**: A 3D force-directed graph visualizing network connections.

## Headless (CLI) Mode

The headless mode is ideal for server environments, scripting, and automated analysis.

### Usage

```
nfa-linux -headless [options]
```

### Options

| Flag | Description | Example |
|---|---|---|
| `-interface <iface>` | Network interface for live capture. | `-interface eth0` |
| `-pcap <file>` | Path to a PCAP file for analysis. | `-pcap capture.pcap` |
| `-bpf <filter>` | BPF filter for packet capture. | `-bpf "port 443"` |
| `-duration <time>` | Duration for live capture. | `-duration 5m` |
| `-config <file>` | Path to a custom configuration file. | `-config /etc/nfa-linux/config.yaml` |
| `-output <format>` | Output format for results (json, case). | `-output json` |
| `-debug` | Enable debug logging. | `-debug` |
| `-version` | Print version information and exit. | `-version` |

### Examples

- **Capture for 10 minutes from `eth0` and save results as CASE/UCO JSON-LD:**
  ```bash
  sudo nfa-linux -headless -interface eth0 -duration 10m -output case
  ```

- **Analyze a PCAP file with a BPF filter:**
  ```bash
  nfa-linux -headless -pcap large.pcap -bpf "host 1.1.1.1"
  ```

## Configuration

NFA-Linux is configured via a YAML file, typically located at `/etc/nfa-linux/config.yaml`. The default configuration is well-commented and provides a good starting point. Key sections include `capture`, `reassembly`, `carver`, `evidence`, `ml`, and `logging`.

## Troubleshooting

- **Permission Denied**: Ensure you are running with `sudo` or have granted the necessary capabilities (`cap_net_raw`, `cap_net_admin`) to the binary.
- **No Packets Captured**: Check if the correct interface is specified and if there is traffic on it. Use `tcpdump` to verify.
- **High CPU Usage**: If using `afpacket` mode, consider switching to `afxdp` if your NIC supports it. You can also reduce the number of worker threads in the configuration.

For further assistance, please open an issue on our [GitHub repository](https://github.com/cvalentine99/nfa-linux/issues).
