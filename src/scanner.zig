const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const config = @import("config.zig");
const windows = std.os.windows;

pub const ScanOptions = struct {
    timeout_ms: u32 = config.DEFAULT_TIMEOUT_MS,
    thread_count: usize = config.DEFAULT_THREADS,
    banner_grab: bool = false,
    retries: u8 = 1,
    protocol_fingerprint: bool = true,
    enrich_tls: bool = true,
    show_progress: bool = false,
};

pub const ScanTask = struct {
    host: []const u8,
    port: u16,
};

pub const ScanResult = struct {
    host: []const u8,
    port: u16,
    is_open: bool,
    latency_ms: i64 = 0,
    service: []const u8 = "unknown",
    banner: ?[]const u8 = null,
    fingerprint: ?[]const u8 = null,
    tls_info: ?[]const u8 = null,
    attempts: u8 = 1,
    error_msg: ?[]const u8 = null,
};

pub fn scanPort(allocator: std.mem.Allocator, host: []const u8, port: u16, opts: ScanOptions) ScanResult {
    var attempt: u8 = 0;
    while (attempt < opts.retries) : (attempt += 1) {
        const result = scanPortOnce(allocator, host, port, opts, attempt + 1);
        if (result.is_open) return result;
    }

    return .{ .host = host, .port = port, .is_open = false, .service = config.serviceName(port), .attempts = opts.retries };
}

fn scanPortOnce(allocator: std.mem.Allocator, host: []const u8, port: u16, opts: ScanOptions, attempts: u8) ScanResult {
    const begin = std.time.milliTimestamp();

    const address = net.Address.parseIp4(host, port) catch {
        return .{ .host = host, .port = port, .is_open = false, .error_msg = "invalid-ip", .attempts = attempts };
    };

    const sockfd = openTcpSocket(address.any.family) orelse {
        return .{ .host = host, .port = port, .is_open = false, .error_msg = "socket-failed", .attempts = attempts };
    };
    defer closeSocket(sockfd);

    if (builtin.os.tag == .windows) {
        const timeout_u32: u32 = opts.timeout_ms;
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_u32)) catch {};
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout_u32)) catch {};
    } else {
        const timeout = std.posix.timeval{
            .tv_sec = @intCast(opts.timeout_ms / 1000),
            .tv_usec = @intCast((opts.timeout_ms % 1000) * 1000),
        };
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
    }

    const addr_ptr = @as(*const std.posix.sockaddr, @ptrCast(&address.any));
    if (!connectSocket(sockfd, addr_ptr, address.getOsSockLen(), opts.timeout_ms)) {
        return .{ .host = host, .port = port, .is_open = false, .service = config.serviceName(port), .attempts = attempts };
    }

    const latency = std.time.milliTimestamp() - begin;

    var banner: ?[]const u8 = null;
    if (opts.banner_grab) {
        banner = readBanner(allocator, sockfd);
    }

    var fp: ?[]const u8 = null;
    if (opts.protocol_fingerprint) {
        fp = fingerprintProtocol(allocator, sockfd, port);
    }

    var tls_info: ?[]const u8 = null;
    if (opts.enrich_tls and (port == 443 or port == 8443)) {
        tls_info = fetchTlsSummary(allocator, host, port);
    }

    return .{
        .host = host,
        .port = port,
        .is_open = true,
        .latency_ms = latency,
        .service = config.serviceName(port),
        .banner = banner,
        .fingerprint = fp,
        .tls_info = tls_info,
        .attempts = attempts,
    };
}

fn openTcpSocket(family: u16) ?std.posix.socket_t {
    if (builtin.os.tag == .windows) {
        windows.callWSAStartup() catch return null;
        const sock = windows.ws2_32.WSASocketW(family, windows.ws2_32.SOCK.STREAM, windows.ws2_32.IPPROTO.TCP, null, 0, windows.ws2_32.WSA_FLAG_OVERLAPPED);
        return if (sock == windows.ws2_32.INVALID_SOCKET) null else sock;
    }
    return std.posix.socket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch null;
}

fn closeSocket(sockfd: std.posix.socket_t) void {
    if (builtin.os.tag == .windows) {
        _ = windows.ws2_32.closesocket(sockfd);
        return;
    }
    std.posix.close(sockfd);
}

fn readBanner(allocator: std.mem.Allocator, sockfd: std.posix.socket_t) ?[]const u8 {
    var buf: [192]u8 = undefined;
    const n = std.posix.recv(sockfd, &buf, 0) catch 0;
    if (n <= 0) return null;
    const trimmed = std.mem.trim(u8, buf[0..@as(usize, @intCast(n))], "\r\n\t ");
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

fn fingerprintProtocol(allocator: std.mem.Allocator, sockfd: std.posix.socket_t, port: u16) ?[]const u8 {
    if (port == 80 or port == 8080 or port == 8000 or port == 443 or port == 8443) {
        const req = "HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n";
        _ = std.posix.send(sockfd, req, 0) catch return null;
        var buf: [256]u8 = undefined;
        const n = std.posix.recv(sockfd, &buf, 0) catch return null;
        if (n <= 0) return null;
        const view = buf[0..@as(usize, @intCast(n))];
        if (std.mem.indexOf(u8, view, "HTTP/")) |_| {
            return allocator.dupe(u8, "http-response") catch null;
        }
    } else if (port == 6379) {
        const ping = "*1\r\n$4\r\nPING\r\n";
        _ = std.posix.send(sockfd, ping, 0) catch return null;
        var buf: [64]u8 = undefined;
        const n = std.posix.recv(sockfd, &buf, 0) catch return null;
        if (n > 0 and std.mem.indexOf(u8, buf[0..@as(usize, @intCast(n))], "+PONG" ) != null) {
            return allocator.dupe(u8, "redis-pong") catch null;
        }
    } else if (port == 22) {
        var buf: [128]u8 = undefined;
        const n = std.posix.recv(sockfd, &buf, 0) catch return null;
        if (n > 0 and std.mem.indexOf(u8, buf[0..@as(usize, @intCast(n))], "SSH-") != null) {
            return allocator.dupe(u8, "ssh-banner") catch null;
        }
    }
    return null;
}

pub fn buildTasks(allocator: std.mem.Allocator, hosts: [][]const u8, ports: []const u16) ![]ScanTask {
    const total = hosts.len * ports.len;
    const tasks = try allocator.alloc(ScanTask, total);

    var i: usize = 0;
    for (hosts) |h| {
        for (ports) |p| {
            tasks[i] = .{ .host = h, .port = p };
            i += 1;
        }
    }
    return tasks;
}

pub fn scanTasksParallel(allocator: std.mem.Allocator, tasks: []const ScanTask, opts: ScanOptions) ![]ScanResult {
    const results = try allocator.alloc(ScanResult, tasks.len);

    var next_index = std.atomic.Value(usize).init(0);
    var completed = std.atomic.Value(usize).init(0);
    const workers_count = @min(@max(@as(usize, 1), opts.thread_count), @max(@as(usize, 1), tasks.len));
    const threads = try allocator.alloc(std.Thread, workers_count);
    defer allocator.free(threads);
    const started_at = std.time.milliTimestamp();

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn worker(alloc: std.mem.Allocator, tks: []const ScanTask, out: []ScanResult, idx: *std.atomic.Value(usize), done: *std.atomic.Value(usize), options: ScanOptions) void {
                while (true) {
                    const current = idx.fetchAdd(1, .monotonic);
                    if (current >= tks.len) break;
                    const task = tks[current];
                    out[current] = scanPort(alloc, task.host, task.port, options);
                    _ = done.fetchAdd(1, .monotonic);
                }
            }
        }.worker, .{ allocator, tasks, results, &next_index, &completed, opts });
    }

    if (opts.show_progress and tasks.len > 0) {
        const stderr = std.io.getStdErr().writer();
        while (completed.load(.monotonic) < tasks.len) {
            try printProgress(stderr, completed.load(.monotonic), tasks.len, started_at);
            std.time.sleep(250 * std.time.ns_per_ms);
        }
        try printProgress(stderr, tasks.len, tasks.len, started_at);
        try stderr.writeByte('\n');
    }

    for (threads) |t| t.join();
    return results;
}

fn printProgress(writer: anytype, done: usize, total: usize, started_at: i64) !void {
    const width: usize = 24;
    const filled = if (total == 0) width else (done * width) / total;
    const hashes = "########################";
    const dashes = "------------------------";

    const elapsed_ms = std.time.milliTimestamp() - started_at;
    const rate = if (elapsed_ms <= 0 or done == 0) 0.0 else @as(f64, @floatFromInt(done)) / (@as(f64, @floatFromInt(elapsed_ms)) / 1000.0);
    const remaining = total - done;
    const eta_ms: i64 = if (rate <= 0.0) 0 else @intFromFloat((@as(f64, @floatFromInt(remaining)) / rate) * 1000.0);
    try writer.print("\r[*] Progress [{s}{s}] {d}/{d} eta={d}s", .{ hashes[0..filled], dashes[filled..width], done, total, @divTrunc(eta_ms, 1000) });
}

pub fn discoverAliveHosts(allocator: std.mem.Allocator, hosts: [][]const u8, opts: ScanOptions) ![][]const u8 {
    if (hosts.len == 0) return allocator.alloc([]const u8, 0);

    const discovery_thread_count = if (hosts.len >= 64)
        config.MAX_CONCURRENT_THREADS
    else
        opts.thread_count;
    const discover_opts = ScanOptions{
        .timeout_ms = opts.timeout_ms,
        .thread_count = discovery_thread_count,
        .banner_grab = false,
        .retries = 1,
        .protocol_fingerprint = false,
        .enrich_tls = false,
        .show_progress = false,
    };
    const alive_flags = try allocator.alloc(bool, hosts.len);
    defer allocator.free(alive_flags);
    @memset(alive_flags, false);

    var next_index = std.atomic.Value(usize).init(0);
    var completed = std.atomic.Value(usize).init(0);
    const workers_count = @min(@max(@as(usize, 1), discover_opts.thread_count), @max(@as(usize, 1), hosts.len));
    const threads = try allocator.alloc(std.Thread, workers_count);
    defer allocator.free(threads);
    const started_at = std.time.milliTimestamp();

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn worker(hs: [][]const u8, alive: []bool, idx: *std.atomic.Value(usize), done: *std.atomic.Value(usize), options: ScanOptions) void {
                while (true) {
                    const current = idx.fetchAdd(1, .monotonic);
                    if (current >= hs.len) break;

                    const host = hs[current];
                    for (config.DEFAULT_DISCOVERY_PORTS) |port| {
                        const result = scanPort(std.heap.page_allocator, host, port, options);
                        if (result.is_open) {
                            alive[current] = true;
                            break;
                        }
                    }

                    _ = done.fetchAdd(1, .monotonic);
                }
            }
        }.worker, .{ hosts, alive_flags, &next_index, &completed, discover_opts });
    }

    if (opts.show_progress) {
        const stderr = std.io.getStdErr().writer();
        while (completed.load(.monotonic) < hosts.len) {
            try printProgress(stderr, completed.load(.monotonic), hosts.len, started_at);
            std.time.sleep(250 * std.time.ns_per_ms);
        }
        try printProgress(stderr, hosts.len, hosts.len, started_at);
        try stderr.writeByte('\n');
    }

    for (threads) |t| t.join();

    var out = std.ArrayList([]const u8).init(allocator);
    errdefer out.deinit();

    for (hosts, 0..) |host, idx| {
        if (alive_flags[idx]) {
            try out.append(host);
        }
    }

    return out.toOwnedSlice();
}

fn connectSocket(sockfd: std.posix.socket_t, addr_ptr: *const std.posix.sockaddr, len: std.posix.socklen_t, timeout_ms: u32) bool {
    if (!setSocketNonBlocking(sockfd, true)) return false;
    errdefer _ = setSocketNonBlocking(sockfd, false);

    if (builtin.os.tag == .windows) {
        if (windows.ws2_32.connect(sockfd, addr_ptr, @intCast(len)) == 0) {
            return setSocketNonBlocking(sockfd, false);
        }

        const err = windows.ws2_32.WSAGetLastError();
        if (err != .WSAEWOULDBLOCK and err != .WSAEINPROGRESS and err != .WSAEINVAL)
        {
            return false;
        }

        var poll_fd = [1]windows.ws2_32.WSAPOLLFD{.{
            .fd = sockfd,
            .events = windows.ws2_32.POLL.OUT,
            .revents = 0,
        }};
        const poll_rc = windows.poll(&poll_fd, 1, @intCast(timeout_ms));
        if (poll_rc <= 0) return false;
        const revents = poll_fd[0].revents;
        if ((revents & windows.ws2_32.POLL.OUT) == 0) {
            return false;
        }
        if ((revents & (windows.ws2_32.POLL.ERR | windows.ws2_32.POLL.HUP | windows.ws2_32.POLL.NVAL)) != 0) {
            return false;
        }
        if (!socketHasNoPendingError(sockfd)) return false;
        if (!socketLooksConnected(sockfd)) return false;
        return setSocketNonBlocking(sockfd, false);
    }

    std.posix.connect(sockfd, addr_ptr, len) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => return false,
    };

    var poll_fd = [1]std.posix.pollfd{.{
        .fd = sockfd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const poll_rc = std.posix.poll(&poll_fd, @intCast(timeout_ms)) catch return false;
    if (poll_rc == 0) return false;
    const revents = poll_fd[0].revents;
    if ((revents & std.posix.POLL.OUT) == 0) {
        return false;
    }
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
        return false;
    }
    if (!socketHasNoPendingError(sockfd)) return false;
    if (!socketLooksConnected(sockfd)) return false;
    return setSocketNonBlocking(sockfd, false);
}

fn setSocketNonBlocking(sockfd: std.posix.socket_t, enabled: bool) bool {
    if (builtin.os.tag == .windows) {
        var mode: windows.ULONG = if (enabled) 1 else 0;
        return windows.ws2_32.ioctlsocket(sockfd, windows.ws2_32.FIONBIO, &mode) != windows.ws2_32.SOCKET_ERROR;
    }

    var flags = std.posix.fcntl(sockfd, std.posix.F.GETFL, 0) catch return false;
    const nonblock_flag: usize = 1 << @bitOffsetOf(std.posix.O, "NONBLOCK");
    if (enabled) {
        flags |= nonblock_flag;
    } else {
        flags &= ~nonblock_flag;
    }
    _ = std.posix.fcntl(sockfd, std.posix.F.SETFL, flags) catch return false;
    return true;
}

fn socketHasNoPendingError(sockfd: std.posix.socket_t) bool {
    if (builtin.os.tag == .windows) {
        var err_code: i32 = 0;
        var size: i32 = @sizeOf(i32);
        const rc = windows.ws2_32.getsockopt(sockfd, windows.ws2_32.SOL.SOCKET, windows.ws2_32.SO.ERROR, @ptrCast(&err_code), &size);
        return rc == 0 and err_code == 0;
    }

    std.posix.getsockoptError(sockfd) catch return false;
    return true;
}

fn socketLooksConnected(sockfd: std.posix.socket_t) bool {
    var addr: std.posix.sockaddr = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    std.posix.getpeername(sockfd, &addr, &len) catch return false;
    return true;
}

pub fn discoverIcmpAliveHosts(allocator: std.mem.Allocator, hosts: [][]const u8, opts: ScanOptions) ![][]const u8 {
    if (hosts.len == 0) return allocator.alloc([]const u8, 0);

    const icmp_thread_count = if (hosts.len >= 64)
        config.MAX_CONCURRENT_THREADS
    else
        opts.thread_count;
    const alive_flags = try allocator.alloc(bool, hosts.len);
    defer allocator.free(alive_flags);
    @memset(alive_flags, false);

    var next_index = std.atomic.Value(usize).init(0);
    var completed = std.atomic.Value(usize).init(0);
    const workers_count = @min(@max(@as(usize, 1), icmp_thread_count), @max(@as(usize, 1), hosts.len));
    const threads = try allocator.alloc(std.Thread, workers_count);
    defer allocator.free(threads);
    const started_at = std.time.milliTimestamp();

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn worker(hs: [][]const u8, alive: []bool, idx: *std.atomic.Value(usize), done: *std.atomic.Value(usize), timeout_ms: u32) void {
                while (true) {
                    const current = idx.fetchAdd(1, .monotonic);
                    if (current >= hs.len) break;
                    alive[current] = pingHost(std.heap.page_allocator, hs[current], timeout_ms) catch false;
                    _ = done.fetchAdd(1, .monotonic);
                }
            }
        }.worker, .{ hosts, alive_flags, &next_index, &completed, opts.timeout_ms });
    }

    if (opts.show_progress) {
        const stderr = std.io.getStdErr().writer();
        while (completed.load(.monotonic) < hosts.len) {
            try printProgress(stderr, completed.load(.monotonic), hosts.len, started_at);
            std.time.sleep(250 * std.time.ns_per_ms);
        }
        try printProgress(stderr, hosts.len, hosts.len, started_at);
        try stderr.writeByte('\n');
    }

    for (threads) |t| t.join();

    var alive = std.ArrayList([]const u8).init(allocator);
    errdefer alive.deinit();

    for (hosts, 0..) |host, idx| {
        if (alive_flags[idx]) {
            try alive.append(host);
        }
    }

    return alive.toOwnedSlice();
}

fn pingHost(allocator: std.mem.Allocator, host: []const u8, requested_timeout_ms: u32) !bool {
    const timeout_ms = @max(@as(u32, 200), requested_timeout_ms);
    const timeout_arg = if (builtin.os.tag == .windows)
        try std.fmt.allocPrint(allocator, "{d}", .{timeout_ms})
    else
        try std.fmt.allocPrint(allocator, "{d}", .{@max(@as(u32, 1), (timeout_ms + 999) / 1000)});
    defer allocator.free(timeout_arg);

    const argv = if (builtin.os.tag == .windows)
        [_][]const u8{ "ping", "-n", "1", "-w", timeout_arg, host }
    else
        [_][]const u8{ "ping", "-c", "1", "-W", timeout_arg, host };

    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = if (builtin.os.tag == .windows) .Pipe else .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    if (builtin.os.tag == .windows) {
        const stdout = child.stdout.?;
        const output = try stdout.readToEndAlloc(allocator, 8 * 1024);
        defer allocator.free(output);
        const term = try child.wait();
        return switch (term) {
            .Exited => |code| code == 0 and (std.ascii.indexOfIgnoreCase(output, "TTL=") != null or std.ascii.indexOfIgnoreCase(output, "TTL ") != null),
            else => false,
        };
    }

    const term = try child.wait();
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn fetchTlsSummary(allocator: std.mem.Allocator, host: []const u8, port: u16) ?[]const u8 {
    if (builtin.os.tag == .windows) {
        return fetchTlsSummaryWindows(allocator, host, port);
    }
    return null;
}

fn fetchTlsSummaryWindows(allocator: std.mem.Allocator, host: []const u8, port: u16) ?[]const u8 {
    const script = std.fmt.allocPrint(
        allocator,
        "$ErrorActionPreference='Stop'; $tcp=New-Object Net.Sockets.TcpClient('{s}',{d}); try {{ $ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,({{$true}})); $ssl.AuthenticateAsClient('{s}'); $cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate; $dns=''; foreach($ext in $cert.Extensions) {{ if($ext.Oid.Value -eq '2.5.29.17') {{ $dns=$ext.Format($true).Replace(\"`r\",' ').Replace(\"`n\",'; '); }} }} Write-Output ($cert.Subject + ' | SAN=' + $dns) }} finally {{ if($ssl) {{$ssl.Dispose()}}; $tcp.Dispose() }}",
        .{ host, port, host },
    ) catch return null;
    defer allocator.free(script);

    const argv = [_][]const u8{ "powershell", "-NoProfile", "-Command", script };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return null;

    const stdout = child.stdout.?;
    const output = stdout.readToEndAlloc(allocator, 32 * 1024) catch {
        _ = child.kill() catch {};
        return null;
    };
    defer allocator.free(output);
    _ = child.wait() catch return null;

    const trimmed = std.mem.trim(u8, output, " \t\r\n");
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

pub fn estimateHostRole(open_ports: []const u16) []const u8 {
    var has_web = false;
    var has_db = false;
    var has_remote = false;
    var has_fileshare = false;
    var has_directory = false;
    var has_mail = false;
    var has_dns = false;
    var has_k8s = false;
    var has_ci = false;
    var has_virtualization = false;

    for (open_ports) |p| {
        switch (p) {
            80, 443, 8080, 8443, 3000, 5000, 7001, 8000, 8888 => has_web = true,
            3306, 5432, 6379, 27017, 9200, 9300, 11211, 1433, 1521 => has_db = true,
            22, 3389, 5985, 5986, 5900 => has_remote = true,
            139, 445, 2049, 873 => has_fileshare = true,
            53 => has_dns = true,
            88, 389, 636 => has_directory = true,
            25, 110, 143, 465, 587, 993, 995 => has_mail = true,
            2375, 2376, 6443 => has_k8s = true,
            8081 => has_ci = true,
            902 => has_virtualization = true,
            else => {},
        }
    }

    if (has_directory and has_fileshare and has_dns) return "directory";
    if (has_k8s and has_remote) return "k8s-control-plane";
    if (has_k8s) return "container-platform";
    if (has_ci and has_web) return "ci-cd";
    if (has_mail) return "mail-gateway";
    if (has_fileshare and has_remote) return "file-server";
    if (has_fileshare) return "storage";
    if (has_db and has_web) return "app+db";
    if (has_db) return "database";
    if (has_web) return "web";
    if (has_directory) return "directory-services";
    if (has_dns) return "dns";
    if (has_virtualization) return "virtualization";
    if (has_remote) return "remote-access";
    return "unknown";
}

pub fn percentile(sorted: []const i64, pct: u8) i64 {
    if (sorted.len == 0) return 0;
    const idx = (@as(usize, pct) * (sorted.len - 1)) / 100;
    return sorted[idx];
}
