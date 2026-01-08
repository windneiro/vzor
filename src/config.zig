const std = @import("std");

pub const APP_NAME = "VZOR";
pub const APP_VERSION = "0.1.0-alpha";
pub const AUTHOR = "Windneiro";

pub const DEFAULT_TIMEOUT_MS = 500;
pub const MAX_CONCURRENT_THREADS = 64;

pub const PortPresets = struct {
    pub const fast = [_]u16{ 22, 80, 443, 3389, 5432, 27017 };
    pub const web = [_]u16{ 80, 443, 8080, 8443, 3000, 5000 };
    pub const sys_admin = [_]u16{ 21, 22, 23, 25, 53, 110, 143, 445, 3306, 5432, 6379 };
};

pub const UI = struct {
    pub const welcome = "\n=== {s} v{s} ===\n";
    pub const scanning = "[*] Scanning target: {s}...\n";
    pub const result_open = "[+] {d: >5} : OPEN\n";
    pub const result_closed = "[-] {d: >5} : CLOSED\n";
    pub const error_msg = "[!] Error: {s}\n";
    pub const finish = "\n[OK] Scan completed in {d} ms. Author: {s}\n";
    pub const port_count = "[*] Found {d} open ports\n";
};
