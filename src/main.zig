const std = @import("std");
const utils = @import("utils.zig");
const config = @import("config.zig");
const scanner = @import("scanner.zig");
const targets = @import("targets.zig");

const OutputFormat = enum {
    human,
    json,
    ndjson,
    csv,
    html,
};

const HostSummary = struct {
    host: []const u8,
    hostname: ?[]const u8,
    mac: ?[]const u8,
    open_ports: usize,
    role: []const u8,
};

const ReportPort = struct {
    host: []const u8,
    port: u16,
    service: []const u8,
    latency_ms: i64,
    attempts: u8,
    fingerprint: ?[]const u8,
    tls_info: ?[]const u8,
    banner: ?[]const u8,
};

const LocalIpv4Network = struct {
    network: u32,
    mask: u32,
};

const CliOptions = struct {
    target_spec: []const u8 = "127.0.0.1",
    mode: []const u8 = "preset-fast",
    timeout_ms: u32 = config.DEFAULT_TIMEOUT_MS,
    threads: usize = config.DEFAULT_THREADS,
    banner_grab: bool = false,
    max_hosts: usize = 4096,
    retries: u8 = 1,
    discovery: bool = true,
    icmp_discovery: bool = false,
    safe_mode: bool = false,
    show_help: bool = false,
    output_format: OutputFormat = .human,
    output_path: ?[]const u8 = null,
    config_path: ?[]const u8 = null,
    audit_log_path: ?[]const u8 = null,
    ports_owned: ?[]u16 = null,
    exclude_ports_owned: ?[]u16 = null,
    exclude_hosts_owned: ?[][]const u8 = null,

    fn ports(self: CliOptions) []const u16 {
        return self.ports_owned orelse &config.PortPresets.fast;
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout_file = std.io.getStdOut();
    const stderr_file = std.io.getStdErr();
    const stdout = stdout_file.writer();
    const stderr = stderr_file.writer();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    utils.initConsole();

    var cli = parseCli(allocator, args) catch |err| {
        try stderr.print(config.UI.error_msg, .{@errorName(err)});
        try stdout.writeAll(config.UI.help);
        return;
    };
    defer freeCli(allocator, &cli);

    if (cli.config_path) |path| {
        try applyConfigFile(allocator, &cli, path);
    }

    if (cli.show_help) {
        try stdout.writeAll(config.UI.help);
        return;
    }

    if (cli.output_format == .human) {
        utils.clearScreen();
    }

    applySafeMode(&cli);

    const start_time = utils.getTimestampMs();

    const hosts_expanded = targets.expandTargetSpec(allocator, cli.target_spec, cli.max_hosts) catch |err| {
        try stderr.print(config.UI.error_msg, .{@errorName(err)});
        return;
    };
    defer freeHostList(allocator, hosts_expanded);

    const hosts = try filterExcludedHosts(allocator, hosts_expanded, cli.exclude_hosts_owned);
    defer allocator.free(hosts);

    const ports = try filterExcludedPorts(allocator, cli.ports(), cli.exclude_ports_owned);
    defer allocator.free(ports);
    const prioritized_ports = try prioritizePorts(allocator, ports);
    defer allocator.free(prioritized_ports);

    if (hosts.len == 0) {
        try stderr.print(config.UI.error_msg, .{"AllHostsExcluded"});
        return;
    }

    if (ports.len == 0) {
        try stderr.print(config.UI.error_msg, .{"AllPortsExcluded"});
        return;
    }

    if (cli.output_format == .human) {
        try stdout.print(config.UI.welcome, .{ config.APP_NAME, config.APP_VERSION });
        try stdout.print(config.UI.scanning, .{cli.target_spec});
        try stdout.print(config.UI.config_line, .{ cli.mode, cli.threads, cli.timeout_ms, cli.banner_grab, cli.retries, cli.discovery });
        try stdout.print(config.UI.feature_line, .{ cli.icmp_discovery, cli.safe_mode, formatName(cli.output_format) });
        utils.printSeparator();
    }

    const scan_opts = scanner.ScanOptions{
        .timeout_ms = cli.timeout_ms,
        .thread_count = @min(cli.threads, config.MAX_CONCURRENT_THREADS),
        .banner_grab = if (cli.safe_mode) false else cli.banner_grab,
        .retries = cli.retries,
        .protocol_fingerprint = !cli.safe_mode,
        .enrich_tls = !cli.safe_mode,
        .show_progress = cli.output_format == .human and stderr_file.isTty(),
    };

    const local_networks = try loadLocalIpv4Networks(allocator);
    defer allocator.free(local_networks);

    var pre_scan_arp_cache = try loadArpCache(allocator);
    defer freeArpCache(allocator, &pre_scan_arp_cache);

    const arp_seed_hosts = try filterHostsByArp(allocator, hosts, local_networks, &pre_scan_arp_cache);
    defer allocator.free(arp_seed_hosts);

    var discovery_candidates = if (hosts.len >= 64 and arp_seed_hosts.len > 0)
        try allocator.dupe([]const u8, arp_seed_hosts)
    else
        try allocator.dupe([]const u8, hosts);
    defer allocator.free(discovery_candidates);

    if (cli.icmp_discovery) {
        const icmp_hosts = try scanner.discoverIcmpAliveHosts(allocator, hosts, scan_opts);
        defer allocator.free(icmp_hosts);

        allocator.free(discovery_candidates);
        discovery_candidates = if (arp_seed_hosts.len > 0)
            try unionHostLists(allocator, arp_seed_hosts, icmp_hosts)
        else
            try allocator.dupe([]const u8, icmp_hosts);
    }

    const scan_hosts = if (cli.discovery)
        try scanner.discoverAliveHosts(allocator, discovery_candidates, scan_opts)
    else
        try allocator.dupe([]const u8, discovery_candidates);
    defer allocator.free(scan_hosts);

    const tasks = try scanner.buildTasks(allocator, scan_hosts, prioritized_ports);
    defer allocator.free(tasks);

    var final_scan_opts = scan_opts;
    final_scan_opts.enrich_tls = scan_hosts.len <= 32 and !cli.safe_mode;

    const results = try scanner.scanTasksParallel(allocator, tasks, final_scan_opts);
    defer {
        for (results) |res| {
            if (res.banner) |b| allocator.free(b);
            if (res.fingerprint) |fp| allocator.free(fp);
            if (res.tls_info) |tls| allocator.free(tls);
        }
        allocator.free(results);
    }

    var arp_cache = try loadArpCache(allocator);
    defer freeArpCache(allocator, &arp_cache);

    var latency_list = std.ArrayList(i64).init(allocator);
    defer latency_list.deinit();

    var open_ports = std.ArrayList(ReportPort).init(allocator);
    defer open_ports.deinit();

    var host_port_map = std.StringHashMap(std.ArrayList(u16)).init(allocator);
    defer {
        var it = host_port_map.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        host_port_map.deinit();
    }

    for (results) |res| {
        if (!res.is_open) continue;
        if (isOnLocalIpv4Network(res.host, local_networks) and !arp_cache.contains(res.host)) continue;

        try latency_list.append(res.latency_ms);
        try open_ports.append(.{
            .host = res.host,
            .port = res.port,
            .service = res.service,
            .latency_ms = res.latency_ms,
            .attempts = res.attempts,
            .fingerprint = res.fingerprint,
            .tls_info = res.tls_info,
            .banner = res.banner,
        });

        const gop = try host_port_map.getOrPut(res.host);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(u16).init(allocator);
        }
        try gop.value_ptr.append(res.port);
    }

    const host_summaries = try buildHostSummaries(allocator, &host_port_map, &arp_cache);
    defer freeHostSummaries(allocator, host_summaries);

    std.mem.sort(ReportPort, open_ports.items, {}, struct {
        fn lessThan(_: void, a: ReportPort, b: ReportPort) bool {
            const host_order = std.mem.order(u8, a.host, b.host);
            return if (host_order == .eq) a.port < b.port else host_order == .lt;
        }
    }.lessThan);

    if (latency_list.items.len > 0) {
        std.mem.sort(i64, latency_list.items, {}, std.sort.asc(i64));
    }

    const duration = utils.getTimestampMs() - start_time;

    if (cli.audit_log_path) |path| {
        try appendAuditLog(path, cli, hosts.len, scan_hosts.len, open_ports.items.len, duration);
    }

    switch (cli.output_format) {
        .human => try writeHumanReport(stdout, open_ports.items, host_summaries, hosts.len, latency_list.items, duration),
        .json => try writeStructuredReport(allocator, stdout, cli.output_path, .json, open_ports.items, host_summaries, hosts.len, scan_hosts.len, latency_list.items, duration),
        .ndjson => try writeStructuredReport(allocator, stdout, cli.output_path, .ndjson, open_ports.items, host_summaries, hosts.len, scan_hosts.len, latency_list.items, duration),
        .csv => try writeStructuredReport(allocator, stdout, cli.output_path, .csv, open_ports.items, host_summaries, hosts.len, scan_hosts.len, latency_list.items, duration),
        .html => try writeStructuredReport(allocator, stdout, cli.output_path, .html, open_ports.items, host_summaries, hosts.len, scan_hosts.len, latency_list.items, duration),
    }
}

fn freeCli(allocator: std.mem.Allocator, cli: *CliOptions) void {
    if (cli.ports_owned) |ports| allocator.free(ports);
    if (cli.exclude_ports_owned) |ports| allocator.free(ports);
    if (cli.exclude_hosts_owned) |hosts| {
        for (hosts) |host| allocator.free(host);
        allocator.free(hosts);
    }
}

fn freeHostSummaries(allocator: std.mem.Allocator, summaries: []HostSummary) void {
    for (summaries) |summary| {
        if (summary.hostname) |hostname| allocator.free(hostname);
        if (summary.mac) |mac| allocator.free(mac);
    }
    allocator.free(summaries);
}

fn freeHostList(allocator: std.mem.Allocator, hosts: [][]const u8) void {
    for (hosts) |host| allocator.free(host);
    allocator.free(hosts);
}

fn parseCli(allocator: std.mem.Allocator, args: []const []u8) !CliOptions {
    var out = CliOptions{};

    var seen_target = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help")) {
            out.show_help = true;
        } else if (std.mem.eql(u8, arg, "--ports")) {
            i += 1;
            if (i >= args.len) return error.MissingPortsArg;
            const value = args[i];
            out.ports_owned = try parsePortsSpec(allocator, value);
            out.mode = "custom-ports";
        } else if (std.mem.eql(u8, arg, "--preset")) {
            i += 1;
            if (i >= args.len) return error.MissingPresetArg;
            const preset = args[i];
            if (std.mem.eql(u8, preset, "fast")) {
                out.mode = "preset-fast";
                out.ports_owned = try allocator.dupe(u16, &config.PortPresets.fast);
            } else if (std.mem.eql(u8, preset, "web")) {
                out.mode = "preset-web";
                out.ports_owned = try allocator.dupe(u16, &config.PortPresets.web);
            } else if (std.mem.eql(u8, preset, "sys_admin")) {
                out.mode = "preset-sys_admin";
                out.ports_owned = try allocator.dupe(u16, &config.PortPresets.sys_admin);
            } else if (std.mem.eql(u8, preset, "full")) {
                out.mode = "preset-full-top";
                out.ports_owned = try allocator.dupe(u16, &config.PortPresets.full_top);
            } else return error.InvalidPreset;
        } else if (std.mem.eql(u8, arg, "--threads")) {
            i += 1;
            if (i >= args.len) return error.MissingThreadsArg;
            const value = args[i];
            out.threads = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            i += 1;
            if (i >= args.len) return error.MissingTimeoutArg;
            const value = args[i];
            out.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--max-hosts")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxHostsArg;
            const value = args[i];
            out.max_hosts = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--retries")) {
            i += 1;
            if (i >= args.len) return error.MissingRetriesArg;
            const value = args[i];
            out.retries = try std.fmt.parseInt(u8, value, 10);
        } else if (std.mem.eql(u8, arg, "--icmp-discovery")) {
            out.icmp_discovery = true;
        } else if (std.mem.eql(u8, arg, "--safe-mode")) {
            out.safe_mode = true;
        } else if (std.mem.eql(u8, arg, "--exclude-hosts")) {
            i += 1;
            if (i >= args.len) return error.MissingExcludeHostsArg;
            const value = args[i];
            out.exclude_hosts_owned = try parseHostListSpec(allocator, value, out.max_hosts);
        } else if (std.mem.eql(u8, arg, "--exclude-ports")) {
            i += 1;
            if (i >= args.len) return error.MissingExcludePortsArg;
            const value = args[i];
            out.exclude_ports_owned = try parsePortsSpec(allocator, value);
        } else if (std.mem.eql(u8, arg, "--format")) {
            i += 1;
            if (i >= args.len) return error.MissingFormatArg;
            const value = args[i];
            out.output_format = parseFormat(value) orelse return error.InvalidFormat;
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return error.MissingOutputArg;
            out.output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingConfigArg;
            out.config_path = args[i];
        } else if (std.mem.eql(u8, arg, "--audit-log")) {
            i += 1;
            if (i >= args.len) return error.MissingAuditLogArg;
            out.audit_log_path = args[i];
        } else if (std.mem.eql(u8, arg, "--no-discovery")) {
            out.discovery = false;
        } else if (std.mem.eql(u8, arg, "--banner")) {
            out.banner_grab = true;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return error.UnknownArg;
        } else if (!seen_target) {
            out.target_spec = arg;
            seen_target = true;
        }
    }

    return out;
}

fn parseFormat(value: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, value, "human")) return .human;
    if (std.mem.eql(u8, value, "json")) return .json;
    if (std.mem.eql(u8, value, "ndjson")) return .ndjson;
    if (std.mem.eql(u8, value, "csv")) return .csv;
    if (std.mem.eql(u8, value, "html")) return .html;
    return null;
}

fn formatName(format: OutputFormat) []const u8 {
    return switch (format) {
        .human => "human",
        .json => "json",
        .ndjson => "ndjson",
        .csv => "csv",
        .html => "html",
    };
}

fn parsePortsSpec(allocator: std.mem.Allocator, spec: []const u8) ![]u16 {
    var list = std.ArrayList(u16).init(allocator);
    errdefer list.deinit();

    var chunks = std.mem.splitScalar(u8, spec, ',');
    while (chunks.next()) |chunk_raw| {
        const chunk = std.mem.trim(u8, chunk_raw, " \t\n\r");
        if (chunk.len == 0) continue;

        if (std.mem.indexOfScalar(u8, chunk, '-')) |dash| {
            const start_txt = chunk[0..dash];
            const end_txt = chunk[dash + 1 ..];
            const start = try std.fmt.parseInt(u16, start_txt, 10);
            const end = try std.fmt.parseInt(u16, end_txt, 10);
            if (end < start) return error.InvalidPortRange;

            var p = start;
            while (p <= end) : (p += 1) {
                try list.append(p);
                if (p == std.math.maxInt(u16)) break;
            }
        } else {
            try list.append(try std.fmt.parseInt(u16, chunk, 10));
        }
    }

    std.mem.sort(u16, list.items, {}, std.sort.asc(u16));
    var unique = std.ArrayList(u16).init(allocator);
    errdefer unique.deinit();

    var last: ?u16 = null;
    for (list.items) |p| {
        if (last == null or last.? != p) {
            try unique.append(p);
            last = p;
        }
    }

    list.deinit();
    return unique.toOwnedSlice();
}

fn parseHostListSpec(allocator: std.mem.Allocator, spec: []const u8, max_hosts: usize) ![][]const u8 {
    var all = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (all.items) |host| allocator.free(host);
        all.deinit();
    }

    var unique = std.StringHashMap(void).init(allocator);
    defer unique.deinit();

    var chunks = std.mem.splitScalar(u8, spec, ',');
    while (chunks.next()) |chunk_raw| {
        const chunk = std.mem.trim(u8, chunk_raw, " \t\n\r");
        if (chunk.len == 0) continue;

        const expanded = try targets.expandTargetSpec(allocator, chunk, max_hosts);
        defer freeHostList(allocator, expanded);

        for (expanded) |host| {
            const gop = try unique.getOrPut(host);
            if (gop.found_existing) continue;
            gop.key_ptr.* = try allocator.dupe(u8, host);
            try all.append(gop.key_ptr.*);
        }
    }

    return all.toOwnedSlice();
}

fn filterExcludedHosts(allocator: std.mem.Allocator, hosts: [][]const u8, excluded: ?[][]const u8) ![][]const u8 {
    if (excluded == null or excluded.?.len == 0) {
        return allocator.dupe([]const u8, hosts);
    }

    var excluded_set = std.StringHashMap(void).init(allocator);
    defer excluded_set.deinit();

    for (excluded.?) |host| {
        try excluded_set.put(host, {});
    }

    var out = std.ArrayList([]const u8).init(allocator);
    errdefer out.deinit();

    for (hosts) |host| {
        if (!excluded_set.contains(host)) {
            try out.append(host);
        }
    }

    return out.toOwnedSlice();
}

fn filterExcludedPorts(allocator: std.mem.Allocator, ports: []const u16, excluded: ?[]u16) ![]u16 {
    if (excluded == null or excluded.?.len == 0) {
        return allocator.dupe(u16, ports);
    }

    var out = std.ArrayList(u16).init(allocator);
    errdefer out.deinit();

    for (ports) |port| {
        if (!containsPort(excluded.?, port)) {
            try out.append(port);
        }
    }

    return out.toOwnedSlice();
}

fn filterHostsByArp(
    allocator: std.mem.Allocator,
    hosts: [][]const u8,
    networks: []const LocalIpv4Network,
    arp_cache: *const std.StringHashMap([]const u8),
) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(allocator);
    errdefer out.deinit();

    for (hosts) |host| {
        if (isOnLocalIpv4Network(host, networks) and arp_cache.contains(host)) {
            try out.append(host);
        }
    }

    return out.toOwnedSlice();
}

fn unionHostLists(allocator: std.mem.Allocator, left: [][]const u8, right: [][]const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(allocator);
    errdefer out.deinit();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    for (left) |host| {
        const gop = try seen.getOrPut(host);
        if (!gop.found_existing) {
            try out.append(host);
        }
    }

    for (right) |host| {
        const gop = try seen.getOrPut(host);
        if (!gop.found_existing) {
            try out.append(host);
        }
    }

    return out.toOwnedSlice();
}

fn containsPort(ports: []const u16, value: u16) bool {
    return std.mem.indexOfScalar(u16, ports, value) != null;
}

fn prioritizePorts(allocator: std.mem.Allocator, ports: []const u16) ![]u16 {
    const ordered = try allocator.dupe(u16, ports);
    std.mem.sort(u16, ordered, {}, struct {
        fn lessThan(_: void, a: u16, b: u16) bool {
            const a_priority = portPriority(a);
            const b_priority = portPriority(b);
            return if (a_priority == b_priority) a < b else a_priority < b_priority;
        }
    }.lessThan);
    return ordered;
}

fn portPriority(port: u16) usize {
    if (std.mem.indexOfScalar(u16, &config.PRIORITY_PORTS, port)) |idx| return idx;
    return config.PRIORITY_PORTS.len + port;
}

fn applySafeMode(cli: *CliOptions) void {
    if (!cli.safe_mode) return;
    if (cli.threads > config.SAFE_MODE_THREADS) {
        cli.threads = config.SAFE_MODE_THREADS;
    }
    if (cli.timeout_ms < config.SAFE_MODE_TIMEOUT_MS) {
        cli.timeout_ms = config.SAFE_MODE_TIMEOUT_MS;
    }
}

fn applyConfigFile(allocator: std.mem.Allocator, cli: *CliOptions, path: []const u8) !void {
    const content = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value_raw = std.mem.trim(u8, line[eq + 1 ..], " \t");
        const value = trimQuotes(value_raw);

        if (std.mem.eql(u8, key, "target") and std.mem.eql(u8, cli.target_spec, "127.0.0.1")) {
            cli.target_spec = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "preset") and cli.ports_owned == null) {
            try applyPreset(allocator, cli, value);
        } else if (std.mem.eql(u8, key, "threads") and cli.threads == config.DEFAULT_THREADS) {
            cli.threads = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, key, "timeout_ms") and cli.timeout_ms == config.DEFAULT_TIMEOUT_MS) {
            cli.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, key, "retries") and cli.retries == 1) {
            cli.retries = try std.fmt.parseInt(u8, value, 10);
        } else if (std.mem.eql(u8, key, "banner") and !cli.banner_grab) {
            cli.banner_grab = parseBool(value) orelse false;
        } else if (std.mem.eql(u8, key, "discovery") and cli.discovery) {
            cli.discovery = parseBool(value) orelse cli.discovery;
        } else if (std.mem.eql(u8, key, "icmp_discovery") and !cli.icmp_discovery) {
            cli.icmp_discovery = parseBool(value) orelse false;
        } else if (std.mem.eql(u8, key, "safe_mode") and !cli.safe_mode) {
            cli.safe_mode = parseBool(value) orelse false;
        } else if (std.mem.eql(u8, key, "format") and cli.output_format == .human) {
            cli.output_format = parseFormat(value) orelse cli.output_format;
        } else if (std.mem.eql(u8, key, "audit_log") and cli.audit_log_path == null) {
            cli.audit_log_path = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "ports") and cli.ports_owned == null) {
            cli.ports_owned = try parsePortsSpec(allocator, value);
            cli.mode = "custom-ports";
        } else if (std.mem.eql(u8, key, "exclude_ports") and cli.exclude_ports_owned == null) {
            cli.exclude_ports_owned = try parsePortsSpec(allocator, value);
        } else if (std.mem.eql(u8, key, "exclude_hosts") and cli.exclude_hosts_owned == null) {
            cli.exclude_hosts_owned = try parseHostListSpec(allocator, value, cli.max_hosts);
        }
    }
}

fn trimQuotes(value: []const u8) []const u8 {
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        return value[1 .. value.len - 1];
    }
    return value;
}

fn parseBool(value: []const u8) ?bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return null;
}

fn applyPreset(allocator: std.mem.Allocator, cli: *CliOptions, preset: []const u8) !void {
    if (std.mem.eql(u8, preset, "fast")) {
        cli.mode = "preset-fast";
        cli.ports_owned = try allocator.dupe(u16, &config.PortPresets.fast);
    } else if (std.mem.eql(u8, preset, "web")) {
        cli.mode = "preset-web";
        cli.ports_owned = try allocator.dupe(u16, &config.PortPresets.web);
    } else if (std.mem.eql(u8, preset, "sys_admin")) {
        cli.mode = "preset-sys_admin";
        cli.ports_owned = try allocator.dupe(u16, &config.PortPresets.sys_admin);
    } else if (std.mem.eql(u8, preset, "full")) {
        cli.mode = "preset-full-top";
        cli.ports_owned = try allocator.dupe(u16, &config.PortPresets.full_top);
    } else return error.InvalidPreset;
}

fn buildHostSummaries(allocator: std.mem.Allocator, host_port_map: *std.StringHashMap(std.ArrayList(u16)), arp_cache: *const std.StringHashMap([]const u8)) ![]HostSummary {
    var out = std.ArrayList(HostSummary).init(allocator);
    errdefer out.deinit();

    var it = host_port_map.iterator();
    while (it.next()) |entry| {
        const hostname = try resolveHostName(allocator, entry.key_ptr.*, entry.value_ptr.items);
        const mac = if (arp_cache.get(entry.key_ptr.*)) |value| try allocator.dupe(u8, value) else null;
        try out.append(.{
            .host = entry.key_ptr.*,
            .hostname = hostname,
            .mac = mac,
            .open_ports = entry.value_ptr.items.len,
            .role = scanner.estimateHostRole(entry.value_ptr.items),
        });
    }

    std.mem.sort(HostSummary, out.items, {}, struct {
        fn lessThan(_: void, a: HostSummary, b: HostSummary) bool {
            return std.mem.order(u8, a.host, b.host) == .lt;
        }
    }.lessThan);

    return out.toOwnedSlice();
}

fn writeHumanReport(
    writer: anytype,
    open_ports: []const ReportPort,
    host_summaries: []const HostSummary,
    total_hosts: usize,
    latencies: []const i64,
    duration_ms: i64,
) !void {
    for (open_ports) |res| {
        try writer.print("{s}", .{roleColorByService(res.service)});
        try writer.print(config.UI.result_open, .{ res.host, res.port, res.service, res.latency_ms, res.attempts });
        try writer.writeAll("\x1b[0m");
        if (res.fingerprint) |fp| {
            try writer.print(config.UI.result_fingerprint, .{fp});
        }
        if (res.tls_info) |tls| {
            try writer.print("    tls: {s}\n", .{tls});
        }
        if (res.banner) |b| {
            try writer.print(config.UI.result_banner, .{b});
        }
    }

    utils.printSeparator();
    try writer.print(config.UI.alive_hosts, .{ host_summaries.len, total_hosts });

    for (host_summaries) |summary| {
        try writer.print("{s}", .{roleColor(summary.role)});
        try writer.print(config.UI.host_summary, .{ summary.host, summary.open_ports, summary.role });
        try writer.writeAll("\x1b[0m");
        if (summary.hostname) |hostname| {
            try writer.print("    hostname: {s}\n", .{hostname});
        }
        if (summary.mac) |mac| {
            try writer.print("    mac: {s}\n", .{mac});
        }
    }

    if (latencies.len > 0) {
        const p50 = scanner.percentile(latencies, 50);
        const p95 = scanner.percentile(latencies, 95);
        const p99 = scanner.percentile(latencies, 99);
        try writer.print(config.UI.latency_summary, .{ p50, p95, p99 });
    }

    try writer.print("[*] Total open ports: {d}\n", .{open_ports.len});
    try writer.print(config.UI.finish, .{ duration_ms, config.AUTHOR });
}

fn writeStructuredReport(
    allocator: std.mem.Allocator,
    stdout_writer: anytype,
    output_path: ?[]const u8,
    format: OutputFormat,
    open_ports: []const ReportPort,
    host_summaries: []const HostSummary,
    total_hosts: usize,
    discovered_hosts: usize,
    latencies: []const i64,
    duration_ms: i64,
) !void {
    if (output_path) |path| {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        const writer = file.writer();
        switch (format) {
            .json => try writeJsonReport(writer, open_ports, host_summaries, total_hosts, discovered_hosts, latencies, duration_ms),
            .ndjson => try writeNdjsonReport(writer, open_ports, host_summaries),
            .csv => try writeCsvReport(writer, open_ports),
            .html => try writeHtmlReport(writer, open_ports, host_summaries, total_hosts, discovered_hosts, latencies, duration_ms),
            else => unreachable,
        }
        try stdout_writer.print("[OK] Report written to {s}\n", .{path});
        return;
    }

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    const writer = buffer.writer();
    switch (format) {
        .json => try writeJsonReport(writer, open_ports, host_summaries, total_hosts, discovered_hosts, latencies, duration_ms),
        .ndjson => try writeNdjsonReport(writer, open_ports, host_summaries),
        .csv => try writeCsvReport(writer, open_ports),
        .html => try writeHtmlReport(writer, open_ports, host_summaries, total_hosts, discovered_hosts, latencies, duration_ms),
        else => unreachable,
    }
    try stdout_writer.writeAll(buffer.items);
}

fn writeJsonReport(
    writer: anytype,
    open_ports: []const ReportPort,
    host_summaries: []const HostSummary,
    total_hosts: usize,
    discovered_hosts: usize,
    latencies: []const i64,
    duration_ms: i64,
) !void {
    const p50 = scanner.percentile(latencies, 50);
    const p95 = scanner.percentile(latencies, 95);
    const p99 = scanner.percentile(latencies, 99);

    try writer.writeAll("{\n");
    try writer.print("  \"app\": \"{s}\",\n", .{config.APP_NAME});
    try writer.print("  \"version\": \"{s}\",\n", .{config.APP_VERSION});
    try writer.print("  \"duration_ms\": {d},\n", .{duration_ms});
    try writer.print("  \"total_hosts\": {d},\n", .{total_hosts});
    try writer.print("  \"discovered_hosts\": {d},\n", .{discovered_hosts});
    try writer.print("  \"alive_hosts\": {d},\n", .{host_summaries.len});
    try writer.print("  \"open_ports\": {d},\n", .{open_ports.len});
    try writer.print("  \"latency\": {{\"p50\": {d}, \"p95\": {d}, \"p99\": {d}}},\n", .{ p50, p95, p99 });
    try writer.writeAll("  \"hosts\": [\n");

    for (host_summaries, 0..) |summary, idx| {
        try writer.print("    {{\"host\": \"{s}\", \"hostname\": ", .{summary.host});
        if (summary.hostname) |hostname| {
            try writer.print("\"{s}\"", .{hostname});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(", \"mac\": ");
        if (summary.mac) |mac| {
            try writer.print("\"{s}\"", .{mac});
        } else {
            try writer.writeAll("null");
        }
        try writer.print(", \"open_ports\": {d}, \"role\": \"{s}\"}}", .{ summary.open_ports, summary.role });
        try writer.writeAll(if (idx + 1 == host_summaries.len) "\n" else ",\n");
    }

    try writer.writeAll("  ],\n");
    try writer.writeAll("  \"results\": [\n");
    for (open_ports, 0..) |res, idx| {
        try writer.print(
            "    {{\"host\": \"{s}\", \"port\": {d}, \"service\": \"{s}\", \"latency_ms\": {d}, \"attempts\": {d}, \"fingerprint\": ",
            .{ res.host, res.port, res.service, res.latency_ms, res.attempts },
        );
        if (res.fingerprint) |fp| {
            try writer.print("\"{s}\"", .{fp});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(", \"tls\": ");
        if (res.tls_info) |tls| {
            try writer.print("\"{s}\"", .{tls});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(", \"banner\": ");
        if (res.banner) |banner| {
            try writer.print("\"{s}\"", .{banner});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
        try writer.writeAll(if (idx + 1 == open_ports.len) "\n" else ",\n");
    }
    try writer.writeAll("  ]\n}\n");
}

fn writeCsvReport(writer: anytype, open_ports: []const ReportPort) !void {
    try writer.writeAll("host,port,service,latency_ms,attempts,fingerprint,tls,banner\n");
    for (open_ports) |res| {
        try writer.print(
            "{s},{d},{s},{d},{d},{s},{s},{s}\n",
            .{
                res.host,
                res.port,
                res.service,
                res.latency_ms,
                res.attempts,
                res.fingerprint orelse "",
                res.tls_info orelse "",
                res.banner orelse "",
            },
        );
    }
}

fn writeNdjsonReport(writer: anytype, open_ports: []const ReportPort, host_summaries: []const HostSummary) !void {
    for (open_ports) |res| {
        try writer.print("{{\"host\":\"{s}\",\"hostname\":", .{res.host});
        if (findHostSummary(host_summaries, res.host)) |summary| {
            if (summary.hostname) |hostname| {
                try writer.print("\"{s}\"", .{hostname});
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll(",\"mac\":");
            if (summary.mac) |mac| {
                try writer.print("\"{s}\"", .{mac});
            } else {
                try writer.writeAll("null");
            }
        } else {
            try writer.writeAll("null,\"mac\":null");
        }
        try writer.print(",\"port\":{d},\"service\":\"{s}\",\"latency_ms\":{d},\"attempts\":{d},\"fingerprint\":", .{
            res.port,
            res.service,
            res.latency_ms,
            res.attempts,
        });
        if (res.fingerprint) |fp| {
            try writer.print("\"{s}\"", .{fp});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"tls\":");
        if (res.tls_info) |tls| {
            try writer.print("\"{s}\"", .{tls});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"banner\":");
        if (res.banner) |banner| {
            try writer.print("\"{s}\"", .{banner});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}\n");
    }
}

fn writeHtmlReport(
    writer: anytype,
    open_ports: []const ReportPort,
    host_summaries: []const HostSummary,
    total_hosts: usize,
    discovered_hosts: usize,
    latencies: []const i64,
    duration_ms: i64,
) !void {
    const p50 = scanner.percentile(latencies, 50);
    const p95 = scanner.percentile(latencies, 95);
    const p99 = scanner.percentile(latencies, 99);

    try writer.writeAll(
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>VZOR Report</title>
        \\<style>
        \\:root{--bg:#f3efe6;--panel:#fffdf8;--ink:#1f2933;--muted:#5b6770;--line:#d8d2c4;--web:#0f766e;--db:#1d4ed8;--infra:#7c3aed;}
        \\body{margin:0;font-family:Georgia,serif;background:linear-gradient(135deg,#f3efe6,#e7f0f4);color:var(--ink);}
        \\main{max-width:1100px;margin:0 auto;padding:32px 20px 48px;}
        \\h1,h2{margin:0 0 12px;}
        \\.hero,.panel{background:rgba(255,253,248,.92);border:1px solid var(--line);border-radius:20px;box-shadow:0 12px 40px rgba(31,41,51,.08);}
        \\.hero{padding:24px;margin-bottom:20px;}
        \\.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:18px;}
        \\.card{padding:14px 16px;background:#fff;border-radius:14px;border:1px solid var(--line);}
        \\.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);}
        \\.value{font-size:26px;font-weight:700;margin-top:4px;}
        \\.panel{padding:20px;margin-top:20px;}
        \\table{width:100%;border-collapse:collapse;}
        \\th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top;}
        \\th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);}
        \\.role-web{color:var(--web);font-weight:700;}
        \\.role-database,.role-appdb{color:var(--db);font-weight:700;}
        \\.role-infrastructure{color:var(--infra);font-weight:700;}
        \\code{background:#f6f2e8;padding:2px 6px;border-radius:8px;}
        \\</style>
        \\</head>
        \\<body><main>
    );
    try writer.print("<section class=\"hero\"><h1>{s} v{s}</h1><p>Scan completed in {d} ms.</p>", .{ config.APP_NAME, config.APP_VERSION, duration_ms });
    try writer.print("<div class=\"grid\"><div class=\"card\"><div class=\"label\">Total Hosts</div><div class=\"value\">{d}</div></div>", .{total_hosts});
    try writer.print("<div class=\"card\"><div class=\"label\">Discovered</div><div class=\"value\">{d}</div></div>", .{discovered_hosts});
    try writer.print("<div class=\"card\"><div class=\"label\">Alive</div><div class=\"value\">{d}</div></div>", .{host_summaries.len});
    try writer.print("<div class=\"card\"><div class=\"label\">Open Ports</div><div class=\"value\">{d}</div></div>", .{open_ports.len});
    try writer.print("<div class=\"card\"><div class=\"label\">Latency</div><div class=\"value\">{d}/{d}/{d}</div></div></div></section>", .{ p50, p95, p99 });
    try writer.writeAll("<section class=\"panel\"><h2>Hosts</h2><table><thead><tr><th>Host</th><th>Hostname</th><th>MAC</th><th>Open Ports</th><th>Role</th></tr></thead><tbody>");
    for (host_summaries) |summary| {
        try writer.print("<tr><td><code>{s}</code></td><td>{s}</td><td><code>{s}</code></td><td>{d}</td><td class=\"{s}\">{s}</td></tr>", .{
            summary.host,
            summary.hostname orelse "",
            summary.mac orelse "",
            summary.open_ports,
            roleCssClass(summary.role),
            summary.role,
        });
    }
    try writer.writeAll("</tbody></table></section>");
    try writer.writeAll("<section class=\"panel\"><h2>Open Ports</h2><table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>RTT</th><th>Fingerprint</th><th>TLS</th><th>Banner</th></tr></thead><tbody>");
    for (open_ports) |res| {
        try writer.print("<tr><td><code>{s}</code></td><td>{d}</td><td>{s}</td><td>{d} ms</td><td>{s}</td><td>{s}</td><td>{s}</td></tr>", .{
            res.host,
            res.port,
            res.service,
            res.latency_ms,
            res.fingerprint orelse "",
            res.tls_info orelse "",
            res.banner orelse "",
        });
    }
    try writer.writeAll("</tbody></table></section></main></body></html>\n");
}

fn roleColor(role: []const u8) []const u8 {
    if (std.mem.eql(u8, role, "web")) return "\x1b[36m";
    if (std.mem.eql(u8, role, "database") or std.mem.eql(u8, role, "app+db")) return "\x1b[34m";
    if (std.mem.eql(u8, role, "infrastructure")) return "\x1b[35m";
    return "\x1b[0m";
}

fn roleColorByService(service: []const u8) []const u8 {
    if (std.mem.indexOf(u8, service, "http") != null) return "\x1b[36m";
    if (std.mem.indexOf(u8, service, "postgres") != null or std.mem.indexOf(u8, service, "mysql") != null or std.mem.indexOf(u8, service, "redis") != null) return "\x1b[34m";
    if (std.mem.indexOf(u8, service, "smb") != null or std.mem.indexOf(u8, service, "ssh") != null or std.mem.indexOf(u8, service, "rdp") != null) return "\x1b[35m";
    return "\x1b[0m";
}

fn roleCssClass(role: []const u8) []const u8 {
    if (std.mem.eql(u8, role, "web")) return "role-web";
    if (std.mem.eql(u8, role, "database")) return "role-database";
    if (std.mem.eql(u8, role, "app+db")) return "role-appdb";
    if (std.mem.eql(u8, role, "infrastructure")) return "role-infrastructure";
    return "";
}

fn reverseDnsLookup(allocator: std.mem.Allocator, host: []const u8) !?[]const u8 {
    const argv = [_][]const u8{ "nslookup", host };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?;
    const output = try stdout.readToEndAlloc(allocator, 16 * 1024);
    defer allocator.free(output);
    _ = try child.wait();

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.startsWith(u8, line, "Name:")) {
            const value = std.mem.trim(u8, line["Name:".len..], " \t");
            if (value.len > 0) {
                const hostname = try allocator.dupe(u8, value);
                return hostname;
            }
        }
    }
    return null;
}

fn findHostSummary(host_summaries: []const HostSummary, host: []const u8) ?HostSummary {
    for (host_summaries) |summary| {
        if (std.mem.eql(u8, summary.host, host)) return summary;
    }
    return null;
}

fn resolveHostName(allocator: std.mem.Allocator, host: []const u8, open_ports: []const u16) !?[]const u8 {
    if (try reverseDnsLookup(allocator, host)) |hostname| return hostname;
    if (shouldTryNetbios(open_ports)) {
        if (try netbiosLookup(allocator, host)) |hostname| return hostname;
    }
    return null;
}

fn shouldTryNetbios(open_ports: []const u16) bool {
    for (open_ports) |port| {
        switch (port) {
            135, 139, 445, 3389 => return true,
            else => {},
        }
    }
    return false;
}

fn netbiosLookup(allocator: std.mem.Allocator, host: []const u8) !?[]const u8 {
    if (@import("builtin").os.tag != .windows) return null;

    const argv = [_][]const u8{ "nbtstat", "-A", host };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?;
    const output = try stdout.readToEndAlloc(allocator, 16 * 1024);
    defer allocator.free(output);
    _ = try child.wait();

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        const tag = std.mem.indexOf(u8, line, "<00>") orelse continue;
        const name = std.mem.trim(u8, line[0..tag], " \t");
        if (name.len == 0) continue;
        return try allocator.dupe(u8, name);
    }
    return null;
}

fn loadLocalIpv4Networks(allocator: std.mem.Allocator) ![]LocalIpv4Network {
    if (@import("builtin").os.tag != .windows) return allocator.alloc(LocalIpv4Network, 0);

    const argv = [_][]const u8{
        "powershell",
        "-NoProfile",
        "-Command",
        "$ErrorActionPreference='SilentlyContinue'; Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.PrefixLength -gt 0 } | ForEach-Object { '{0}/{1}' -f $_.IPAddress, $_.PrefixLength }",
    };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?;
    const output = try stdout.readToEndAlloc(allocator, 16 * 1024);
    defer allocator.free(output);
    _ = try child.wait();

    var out = std.ArrayList(LocalIpv4Network).init(allocator);
    errdefer out.deinit();

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const slash = std.mem.indexOfScalar(u8, line, '/') orelse continue;
        const ip = line[0..slash];
        const prefix = std.fmt.parseInt(u8, line[slash + 1 ..], 10) catch continue;
        const ip_num = parseIpv4ToU32(ip) catch continue;
        const mask = prefixToMask(prefix);
        try out.append(.{ .network = ip_num & mask, .mask = mask });
    }

    return out.toOwnedSlice();
}

fn loadArpCache(allocator: std.mem.Allocator) !std.StringHashMap([]const u8) {
    var cache = std.StringHashMap([]const u8).init(allocator);
    errdefer freeArpCache(allocator, &cache);

    const argv = [_][]const u8{ "arp", "-a" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = child.stdout.?;
    const output = try stdout.readToEndAlloc(allocator, 32 * 1024);
    defer allocator.free(output);
    _ = try child.wait();

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const ip = fields.next() orelse continue;
        const mac = fields.next() orelse continue;
        _ = parseIpv4ToU32(ip) catch continue;

        const key = try allocator.dupe(u8, ip);
        const value = try allocator.dupe(u8, mac);
        try cache.put(key, value);
    }

    return cache;
}

fn freeArpCache(allocator: std.mem.Allocator, cache: *std.StringHashMap([]const u8)) void {
    var it = cache.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    cache.deinit();
}

fn isOnLocalIpv4Network(host: []const u8, networks: []const LocalIpv4Network) bool {
    const ip_num = parseIpv4ToU32(host) catch return false;
    for (networks) |network| {
        if ((ip_num & network.mask) == network.network) return true;
    }
    return false;
}

fn parseIpv4ToU32(host: []const u8) !u32 {
    var parts = std.mem.splitScalar(u8, host, '.');
    var octets: [4]u8 = undefined;
    for (0..4) |idx| {
        const part = parts.next() orelse return error.InvalidIp;
        octets[idx] = try std.fmt.parseInt(u8, part, 10);
    }
    if (parts.next() != null) return error.InvalidIp;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | octets[3];
}

fn prefixToMask(prefix: u8) u32 {
    if (prefix == 0) return 0;
    const shift: u5 = @intCast(32 - prefix);
    return ~(@as(u32, 0xffffffff) >> shift);
}

fn appendAuditLog(path: []const u8, cli: CliOptions, total_hosts: usize, discovered_hosts: usize, open_ports: usize, duration_ms: i64) !void {
    const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);
    const writer = file.writer();
    const now = std.time.timestamp();
    try writer.print(
        "{d}\ttarget={s}\tmode={s}\tformat={s}\ttotal_hosts={d}\tdiscovered_hosts={d}\topen_ports={d}\ttimeout_ms={d}\tthreads={d}\tretries={d}\tdiscovery={any}\ticmp={any}\tsafe_mode={any}\tduration_ms={d}\n",
        .{
            now,
            cli.target_spec,
            cli.mode,
            formatName(cli.output_format),
            total_hosts,
            discovered_hosts,
            open_ports,
            cli.timeout_ms,
            cli.threads,
            cli.retries,
            cli.discovery,
            cli.icmp_discovery,
            cli.safe_mode,
            duration_ms,
        },
    );
}
