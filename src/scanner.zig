const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const config = @import("config.zig");

pub const ScanError = error{
    InvalidAddress,
    SocketCreationFailed,
    TimeoutConfigurationFailed,
    ConnectionFailed,
};

pub const ScanResult = struct {
    port: u16,
    is_open: bool,
    error_msg: ?[]const u8 = null,
};

pub fn scanPort(allocator: std.mem.Allocator, ip: []const u8, port: u16, timeout_ms: u32) !ScanResult {
    const address = net.Address.parseIp4(ip, port) catch {
        const err_msg = try allocator.dupe(u8, "Invalid IP address format");
        return ScanResult{ .port = port, .is_open = false, .error_msg = err_msg };
    };

    const sockfd = std.posix.socket(address.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch {
        const err_msg = try allocator.dupe(u8, "Failed to create socket");
        return ScanResult{ .port = port, .is_open = false, .error_msg = err_msg };
    };
    defer std.posix.close(sockfd);

    if (builtin.os.tag == .windows) {
        const timeout_u32: u32 = timeout_ms;
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_u32)) catch |err| {
            if (builtin.mode == .Debug) {
                std.debug.print("Warning: Failed to set Windows receive timeout: {}\n", .{err});
            }
        };
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout_u32)) catch |err| {
            if (builtin.mode == .Debug) {
                std.debug.print("Warning: Failed to set Windows send timeout: {}\n", .{err});
            }
        };
    } else {
        const timeout = std.posix.timeval{
            .tv_sec = @intCast(timeout_ms / 1000),
            .tv_usec = @intCast((timeout_ms % 1000) * 1000),
        };
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            if (builtin.mode == .Debug) {
                std.debug.print("Warning: Failed to set Unix receive timeout: {}\n", .{err});
            }
        };
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            if (builtin.mode == .Debug) {
                std.debug.print("Warning: Failed to set Unix send timeout: {}\n", .{err});
            }
        };
    }

    const addr_ptr = @as(*const std.posix.sockaddr, @ptrCast(&address.any));
    _ = std.posix.connect(sockfd, addr_ptr, address.getOsSockLen()) catch {
        return ScanResult{ .port = port, .is_open = false };
    };

    return ScanResult{ .port = port, .is_open = true };
}

pub fn scanRangeParallel(allocator: std.mem.Allocator, ip: []const u8, ports: []const u16) ![]ScanResult {
    const results = try allocator.alloc(ScanResult, ports.len);
    // Initialize results with default values
    for (results) |*r| {
        r.* = .{ .port = 0, .is_open = false };
    }

    var threads = try allocator.alloc(std.Thread, ports.len);
    defer allocator.free(threads);

    for (ports, 0..) |port, i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn worker(alloc: std.mem.Allocator, ip_addr: []const u8, p: u16, res_ptr: *ScanResult) void {
                // We write the result directly into memory using the pointer
                res_ptr.* = scanPort(alloc, ip_addr, p, config.DEFAULT_TIMEOUT_MS) catch |err| {
                    res_ptr.* = .{ .port = p, .is_open = false, .error_msg = @errorName(err) };
                    return; // We just leave without returning anything
                };
            }
        }.worker, .{ allocator, ip, port, &results[i] });
    }

    for (threads) |t| t.join();

    return results;
}
