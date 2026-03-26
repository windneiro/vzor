const std = @import("std");

pub const APP_NAME = "VZOR";
pub const APP_VERSION = "0.4.0";
pub const AUTHOR = "Windneiro";

pub const DEFAULT_TIMEOUT_MS: u32 = 500;
pub const MAX_CONCURRENT_THREADS: usize = 64;
pub const DEFAULT_THREADS: usize = 32;
pub const SAFE_MODE_THREADS: usize = 8;
pub const SAFE_MODE_TIMEOUT_MS: u32 = 1200;
pub const DEFAULT_DISCOVERY_PORTS = [_]u16{ 80, 443, 445, 22, 3389 };
pub const PRIORITY_PORTS = [_]u16{ 22, 53, 80, 88, 135, 139, 389, 443, 445, 3389, 5432, 6379, 6443 };

pub const PortPresets = struct {
    pub const fast = [_]u16{ 22, 80, 443, 3389, 5432, 27017 };
    pub const web = [_]u16{ 80, 443, 8080, 8443, 3000, 5000 };
    pub const sys_admin = [_]u16{ 21, 22, 23, 25, 53, 110, 143, 445, 3306, 5432, 6379 };
    pub const full_top = [_]u16{
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143,
        161, 162, 389, 443, 445, 465, 500, 514, 587, 631, 636, 873, 902, 989, 990, 993, 995,
        1080, 1194, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3306, 3389, 4444, 5000, 5060,
        5432, 5672, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 8000, 8080, 8081, 8443, 8888,
        9200, 9300, 11211, 27017,
    };
};

pub fn serviceName(port: u16) []const u8 {
    return switch (port) {
        20, 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25, 587 => "smtp",
        53 => "dns",
        67, 68 => "dhcp",
        80, 8080, 8081 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135, 445 => "smb/msrpc",
        137, 138, 139 => "netbios",
        143 => "imap",
        161, 162 => "snmp",
        389, 636 => "ldap",
        443, 8443 => "https",
        465 => "smtps",
        500 => "ipsec",
        514 => "syslog",
        631 => "ipp",
        873 => "rsync",
        902 => "vmware",
        989, 990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2375, 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        4444 => "metasploit",
        5000 => "upnp/http",
        5060 => "sip",
        5432 => "postgres",
        5672 => "amqp",
        5900 => "vnc",
        5985, 5986 => "winrm",
        6379 => "redis",
        6443 => "k8s-api",
        6667 => "irc",
        7001 => "weblogic",
        8000 => "http-alt",
        8888 => "http-proxy",
        9200, 9300 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        else => "unknown",
    };
}

pub const UI = struct {
    pub const welcome = "\n=== {s} v{s} ===\n";
    pub const scanning = "[*] Scanning target spec: {s}\n";
    pub const config_line = "[*] mode={s}, threads={d}, timeout={d}ms, banner={any}, retries={d}, discovery={any}\n";
    pub const feature_line = "[*] icmp={any}, safe_mode={any}, format={s}\n";
    pub const alive_hosts = "[*] Hosts with at least one open port: {d}/{d}\n";
    pub const result_open = "[+] {s}:{d: >5} OPEN  svc={s}  rtt={d}ms  tries={d}\n";
    pub const result_fingerprint = "    fingerprint: {s}\n";
    pub const result_banner = "    banner: {s}\n";
    pub const latency_summary = "[*] Latency: p50={d}ms p95={d}ms p99={d}ms\n";
    pub const error_msg = "[!] Error: {s}\n";
    pub const finish = "\n[OK] Scan completed in {d} ms. Author: {s}\n";
    pub const host_summary = "[*] Host {s}: open={d}, role={s}\n";
    pub const help =
        \\Usage:
        \\  vzor [target|CIDR|range] [options]
        \\
        \\Examples:
        \\  vzor 192.168.1.10
        \\  vzor 192.168.1.0/24 --preset web
        \\  vzor 10.0.0.10-25 --ports 22,80,443,8000-8100 --banner
        \\  vzor 172.16.0.0/24 --exclude-hosts 172.16.0.1,172.16.0.10-20 --exclude-ports 445,3389
        \\  vzor 192.168.1.0/24 --format json --output report.json
        \\
        \\Options:
        \\  --ports <spec>           Custom port list, e.g. 22,80,443,8000-8100
        \\  --preset <fast|web|sys_admin|full>
        \\  --threads <n>            Worker threads (default: 32)
        \\  --timeout <ms>           Connect timeout in milliseconds
        \\  --max-hosts <n>          Cap host expansion for ranges/CIDR
        \\  --retries <n>            Retries per port
        \\  --banner                 Read banners when possible
        \\  --no-discovery           Skip TCP host discovery phase
        \\  --icmp-discovery         Run ICMP ping sweep before TCP discovery
        \\  --safe-mode              Lower concurrency and gentler probing
        \\  --exclude-hosts <spec>   Comma-separated IP/CIDR/range list
        \\  --exclude-ports <spec>   Ports to skip
        \\  --format <human|json|ndjson|csv|html>
        \\  --output <path>          Write report to file instead of stdout
        \\  --config <path>          Load defaults from vzor.toml-style file
        \\  --audit-log <path>       Append scan metadata to audit log
        \\  --help                   Show this help
        \\
    ;
};
