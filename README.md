# VZOR - Port Scanner

![Version](https://img.shields.io/badge/version-0.4.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-brightgreen)
![Language](https://img.shields.io/badge/language-Zig-orange)

## Overview

**VZOR** is a cross-platform TCP scanner and lightweight network inventory tool written in Zig.

It is designed for practical operator workflows:

- quickly check which hosts in a range are alive
- map common services and exposed management ports
- classify hosts by likely role
- export results into machine-friendly or operator-friendly formats

VZOR sits between a minimal port checker and a heavier recon framework. It is especially useful for small and medium subnets where you want fast visibility without bringing in a larger scanning stack.

## Who It Is For

VZOR is primarily a practical tool for:

- DevOps / Platform Engineer
- Sysadmin
- Network Admin
- Infrastructure / SecOps engineer
- internal IT audit

It is most useful when you need to quickly understand:

- which hosts are alive
- which services are open
- where management access is exposed
- where web services, databases, file shares, and remote access are present
- how to export the result into a report or pipeline

## What It Does Well

- expands targets from a single IP, a dash range, or CIDR
- runs TCP discovery before full scanning
- optionally performs ICMP pre-discovery
- scans either presets or custom port lists
- records RTT metrics and retry behavior
- infers likely host roles from open ports
- enriches results with reverse DNS and HTTPS certificate metadata when available
- exports to `human`, `json`, `ndjson`, `csv`, and `html`
- supports config-file based runs and append-only audit logging

## Features

- **Cross-platform**
  - Windows
  - Linux
- **Target expansion**
  - `10.0.0.5`
  - `10.0.0.10-50`
  - `10.0.0.0/24`
- **Port selection**
  - presets: `fast`, `web`, `sys_admin`, `full`
  - custom specs such as `22,80,443,8000-8100`
- **Discovery**
  - TCP multi-probe discovery
  - optional ICMP sweep via `--icmp-discovery`
- **Noise control**
  - `--safe-mode`
  - `--exclude-hosts`
  - `--exclude-ports`
- **Reliability**
  - retries via `--retries`
  - latency metrics `p50/p95/p99`
  - prioritized critical ports
- **Enrichment**
  - reverse DNS lookup when available
  - TLS certificate subject/SAN enrichment for HTTPS services on Windows
  - host role estimation such as `web`, `database`, `app+db`, `storage`, `directory`, `mail-gateway`, `remote-access`, `container-platform`
- **Output**
  - `human`
  - `json`
  - `ndjson`
  - `csv`
  - `html`
- **Operational support**
  - config file via `--config`
  - audit trail via `--audit-log`
  - build and clean scripts for Windows and Unix-like shells

## Requirements

- **Zig**: `0.13.0+`
- **Windows 10+** or modern Linux
- network access to the target hosts you are scanning

## Quick Start

Build:

```bash
zig build
```

Run a fast scan against one host:

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1 --preset fast --timeout 400
```

Run a safer small-range sweep:

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1-20 --icmp-discovery --preset fast --threads 8 --timeout 300 --safe-mode
```

Write a JSON report:

```powershell
.\zig-out\bin\vzor.exe 192.168.14.0/24 --preset web --format json --output scan.json
```

## Build

### Standard build

```bash
zig build
```

Default artifacts:

- Windows: `zig-out/bin/vzor.exe`
- Linux: `zig-out/bin/vzor`

### Zig build steps

```bash
zig build run
zig build build-windows
zig build build-linux
zig build build-linux-arm64
zig build build-all
```

You can also still use explicit targets:

```bash
zig build -Dtarget=x86_64-windows
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
```

### Windows build helper

Use [build.bat](C:\Users\Windneiro\Desktop\vzor-main\vzor-ai-test\build.bat):

```bat
build.bat native ReleaseFast
build.bat windows Debug
build.bat linux ReleaseFast
build.bat linux-arm64 ReleaseFast
build.bat all ReleaseFast
```

### Unix-like build helper

Use [build.sh](C:\Users\Windneiro\Desktop\vzor-main\vzor-ai-test\build.sh):

```bash
./build.sh native ReleaseFast
./build.sh windows Debug
./build.sh linux ReleaseFast
./build.sh linux-arm64 ReleaseFast
./build.sh all ReleaseFast
```

### Supported build targets

- `native`
- `windows`
- `linux`
- `linux-arm64`
- `all`

### Supported optimize modes

- `Debug`
- `ReleaseSafe`
- `ReleaseFast`
- `ReleaseSmall`

## Cleaning Artifacts

Windows:

```bat
clean.bat
```

Unix-like shells:

```bash
./clean.sh
```

## CLI

Basic form:

```text
vzor [target|CIDR|range] [options]
```

Main options:

- `--preset <fast|web|sys_admin|full>`
- `--ports <spec>`
- `--threads <n>`
- `--timeout <ms>`
- `--retries <n>`
- `--banner`
- `--no-discovery`
- `--icmp-discovery`
- `--safe-mode`
- `--exclude-hosts <spec>`
- `--exclude-ports <spec>`
- `--format <human|json|ndjson|csv|html>`
- `--output <path>`
- `--config <path>`
- `--audit-log <path>`
- `--help`

## Example Workflows

### Fast single-host check

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1 --preset fast --timeout 400
```

### Full local-host scan without discovery

```powershell
.\zig-out\bin\vzor.exe 192.168.14.162 --no-discovery --preset full --format human
```

### Safer subnet sweep

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1-20 --icmp-discovery --preset fast --threads 8 --timeout 300 --safe-mode
```

### NDJSON for pipelines

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1 --preset fast --format ndjson
```

### HTML report for operators

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1 --preset fast --format html --output report.html
```

### Audit-logged structured run

```powershell
.\zig-out\bin\vzor.exe 192.168.14.1 --preset fast --audit-log audit.log --format json --output scan.json
```

## Config File

VZOR supports a simple `vzor.toml`-style config:

```toml
target = "192.168.14.1"
preset = "fast"
format = "json"
icmp_discovery = true
safe_mode = true
exclude_ports = "27017"
audit_log = "audit.log"
```

Run with config:

```powershell
.\zig-out\bin\vzor.exe --config vzor.toml --output scan.json
```

## Example Human Output

```text
=== VZOR v0.4.0 ===
[*] Scanning target spec: 192.168.14.1
[*] mode=preset-fast, threads=32, timeout=400ms, banner=false, retries=1, discovery=true
[*] icmp=false, safe_mode=false, format=human
----------------------------------------
[+] 192.168.14.1:   80 OPEN  svc=http  rtt=1ms  tries=1
----------------------------------------
[*] Hosts with at least one open port: 1/1
[*] Host 192.168.14.1: open=1, role=web
[*] Latency: p50=1ms p95=1ms p99=1ms
[*] Total open ports: 1

[OK] Scan completed in 4153 ms. Author: Windneiro
```

## Output Formats

- `human`
  - interactive console output for operators
- `json`
  - one complete report document
- `ndjson`
  - one JSON object per result, useful for pipelines
- `csv`
  - flat export for spreadsheets and quick filtering
- `html`
  - presentation-friendly local report

## Architecture

| Module | Purpose |
|--------|---------|
| `src/main.zig` | CLI parsing, filtering, reporting, config loading |
| `src/scanner.zig` | TCP scans, discovery, retries, progress, ICMP helpers, TLS enrichment |
| `src/config.zig` | constants, presets, UI strings |
| `src/targets.zig` | single/range/CIDR target expansion |
| `src/utils.zig` | console helpers and timestamps |

## Notes

- ICMP discovery uses the system `ping` command.
- Reverse DNS enrichment uses `nslookup` when available.
- TLS certificate enrichment currently uses a best-effort Windows PowerShell/.NET path for `443/8443`.
- `safe-mode` reduces concurrency and disables banner/fingerprint probing.
- Progress/ETA is effectively TTY-oriented and should not spam captured logs.
- HTML output is intended for local operator reporting, not for publishing untrusted raw scan data.

## Security Considerations

Only scan networks and hosts you own or are explicitly authorized to assess. Unauthorized scanning may violate policy, internal controls, or law.

## Roadmap

- additional graph/export formats
- richer protocol-aware fingerprinting
- more enrichment sources beyond reverse DNS and TLS summary

## License

MIT License. See `LICENSE`.
