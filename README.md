# iport

A fast, zero-configuration, dependency-free network probe and diagnostic tool.

`iport` is designed to be the ultimate "Do What I Mean" network scanner. Instead of requiring you to remember complex flags like `nmap` or `curl`, you simply point `iport` at a target, and it concurrently checks L3/L4 connectivity, TLS protocol support, and L7 application protocols (including HTTP/2 and HTTP/3).

## Features

- **L3/L4 Connectivity:** Concurrent ICMP Ping and TCP port checks.
- **TLS Version Scanning:** Automatically checks support for TLS 1.0, 1.1, 1.2, and 1.3, including cipher suites.
- **Advanced HTTP Protocols:** Negotiates HTTP/1.1 and HTTP/2 over ALPN, and checks for HTTP/3 (QUIC) support over UDP.
- **Zero Configuration:** Sane defaults give you a comprehensive report immediately.
- **Static Binary:** Built with Go, meaning it's a single binary with no external dependencies (no need for `nmap`, `openssl`, etc.).

## Installation

```bash
go install github.com/txdywy/iport/cmd/iport@latest
```

## Usage

```bash
# Basic usage (defaults to scanning ports 80 and 443)
iport example.com

# Specify custom ports
iport 192.168.1.100 -p 80,443,8080,8443

# Adjust timeout (in milliseconds)
iport example.com -timeout 5000
```
