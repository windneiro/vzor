# VZOR - Port Scanner

![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-brightgreen)
![Language](https://img.shields.io/badge/language-Zig-orange)

## Overview

**VZOR** is a high-performance, cross-platform port scanner written in Zig. It provides fast network reconnaissance with robust error handling for both Windows and Linux platforms. The tool is optimized for quick security audits with minimal system overhead.

### Key Features

- ✅ **Cross-platform Support**: Native Windows, Linux, and macOS binaries
- ✅ **Robust Error Handling**: Clear error messages instead of silent failures
- ✅ **Configurable Presets**: Fast, Web, and System Admin port profiles
- ✅ **Timeout Control**: Configurable socket timeout for responsive scanning
- ✅ **Performance Metrics**: Built-in timing and port count statistics
- ✅ **Clean Output**: Professional logging with separate stdout/stderr

## Requirements

- **Zig**: 0.13.0 or later ([Download](https://ziglang.org/download/))
- **Windows 10+** or **Linux kernel 3.10+**
- Network access to target systems

## Installation

### Building from Source

Clone the repository and build:

```bash
git clone <repository-url>
cd vzor
zig build
```

The binary will be available in `zig-out/bin/vzor` (or `vzor.exe` on Windows).

### Cross-compilation

Build for specific platforms:

```bash
# Build for Linux x86_64
zig build -Dtarget=x86_64-linux

# Build for Windows x86_64
zig build -Dtarget=x86_64-windows

# Build for Linux ARM64 (Raspberry Pi, etc.)
zig build -Dtarget=aarch64-linux

# Build all platforms at once
zig build build-all
```

The compiled binaries will be in `zig-out/bin/`.

## Usage

### Quick Start

```bash
zig build run
```

This scans localhost (127.0.0.1) against common ports

### Scanning a Specific Target

To scan the default target (localhost):

```bash
zig build run
```
To scan a specific target (e.g., your router or server):

```bash
zig build run -- 192.168.1.1
```
Note: The -- separator is required to tell zig build that the following arguments should be passed directly to the VZOR binary.

### Using Port Presets

Currently, the preset is selected in `src/main.zig`. To change the scanning profile, update the scanRangeParallel call:

#### 1. **Fast Preset** (Default)
Quick scan of critical ports:
```zig
&config.PortPresets.fast
```
Ports: `22, 80, 443, 3389, 5432, 27017`

#### 2. **Web Preset**
Web infrastructure ports:
```zig
&config.PortPresets.web
```
Ports: `80, 443, 8080, 8443, 3000, 5000`

#### 3. **System Admin Preset**
Administration and database ports:
```zig
&config.PortPresets.sys_admin
```
Ports: `21, 22, 23, 25, 53, 110, 143, 445, 3306, 5432, 6379`

### Example Output

```
=== VZOR v0.1.0-alpha ===
[*] Scanning target: 192.168.1.50...
----------------------------------------
[+]    22 : OPEN
[+]    80 : OPEN
[+]   443 : OPEN
----------------------------------------
[*] Found 3 open ports

[OK] Scan completed in 2041 ms. Author: Windneiro
```

## Configuration

Edit `src/config.zig` to customize behavior:

```zig
pub const DEFAULT_TIMEOUT_MS = 500;      // Socket timeout in milliseconds
pub const MAX_CONCURRENT_THREADS = 64;   // Maximum parallel connections
```

### Performance Tuning

- **Increase Timeout**: For slow/unreliable networks
  ```zig
  pub const DEFAULT_TIMEOUT_MS = 1000;  // 1 second
  ```

- **Adjust Thread Count**: For resource-constrained systems
  ```zig
  pub const MAX_CONCURRENT_THREADS = 16;  // Lower on embedded systems
  ```

## Architecture

### Module Structure

| Module | Purpose |
|--------|---------|
| `main.zig` | Application entry point, error handling, result aggregation |
| `scanner.zig` | Core scanning logic, socket operations, cross-platform implementation |
| `config.zig` | Configuration constants, UI messages, port presets |
| `utils.zig` | Platform-specific utilities (console, timestamps) |

### Platform-Specific Implementation

The codebase uses `builtin.os.tag` to handle platform differences:

```zig
if (builtin.os.tag == .windows) {
    // Windows-specific socket timeout
    _ = std.posix.setsockopt(...timeout_u32...);
} else {
    // Unix-like socket timeout
    _ = std.posix.setsockopt(...timeval...);
}
```

This ensures proper behavior on each OS without code duplication.

## Error Handling

VZOR implements comprehensive error handling:

- **Invalid IP Address**: Clear message without termination
- **Socket Creation Failure**: Logged with port information
- **Connection Timeout**: Gracefully marked as closed
- **Permission Issues**: Informative error messages

Example:

```
[!] Port 79: Socket creation failed on Windows
[!] Port 22: Permission denied
[+]    80 : OPEN
```

## Performance

Typical execution times using the Parallel Scanner (with default 500ms timeout):

| Scenario | Duration | Notes |
|----------|----------|-------|
|Fast preset (6 ports) | ~2000 ms | Reliable network / Localhost |
|Web preset (6 ports) | ~2000 ms | Includes web infrastructure |
|Sys admin preset (14 ports) | ~3500 ms | Comprehensive service |check |

Optimization Note: The duration is mainly driven by the `DEFAULT_TIMEOUT_MS`. Since ports are scanned in parallel, the total time is roughly `(Number of ports / Threads) * Timeout`. On local networks, you can decrease the timeout in `src/config.zig` to achieve sub-second results.

Resource Usage:
- Memory: ~2-4 MB (Extremely lightweight)
- CPU: Minimal (Event-driven socket operations)

## Building for Deployment

### Release Binary

Optimized for speed, removes debug symbols:
```bash
zig build -Doptimize=ReleaseFast
```

### Static Binary

Optimized for minimum file size:
```bash
zig build -Doptimize=ReleaseSmall
```

## Troubleshooting

### "Permission Denied" on Linux

On Linux, raw socket operations or scanning low-numbered ports (1-1024) may require elevated privileges:

```bash
sudo ./zig-out/bin/vzor-x86_64-linux
```

### Windows Execution Policy

If you can't run the binary, ensure you are executing it from a terminal with appropriate permissions:

```PowerShell
.\zig-out\bin\vzor-x86_64-windows.exe 127.0.0.1
```

### Timeout Issues

If targets are not responding:

1. Increase timeout in `src/config.zig`:
   ```zig
   pub const DEFAULT_TIMEOUT_MS = 2000;
   ```

2. Rebuild:
   ```bash
   zig build
   ```

### Network Issues

Ensure network connectivity:

```bash
ping 127.0.0.1  # Test connectivity
```

## Platform Notes

### Windows

- Requires Windows 10 or later
- Virtual terminal processing enabled for ANSI colors
- DWORD timeout values used for socket options

### Linux

- Works on kernel 3.10+
- Timeval-based socket timeouts
- Full ANSI escape code support

## Contributing

Improvements welcome! Areas for enhancement:

- UDP port scanning
- Banner grabbing
- Custom port ranges via CLI arguments
- Parallel batch scanning optimization

## Security Considerations

⚠️ **Important**: Only scan networks and systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

## License

MIT License - See LICENSE file for details


