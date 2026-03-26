const std = @import("std");

pub fn expandTargetSpec(allocator: std.mem.Allocator, spec: []const u8, max_hosts: usize) ![][]const u8 {
    if (std.mem.indexOfScalar(u8, spec, '/')) |_| {
        return expandCidr(allocator, spec, max_hosts);
    }
    if (std.mem.indexOfScalar(u8, spec, '-')) |_| {
        return expandDashRange(allocator, spec, max_hosts);
    }

    const single = try allocator.alloc([]const u8, 1);
    single[0] = try allocator.dupe(u8, spec);
    return single;
}

fn expandDashRange(allocator: std.mem.Allocator, spec: []const u8, max_hosts: usize) ![][]const u8 {
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return error.InvalidRange;
    const left = spec[0..dash];
    const right = spec[dash + 1 ..];

    const last_dot = std.mem.lastIndexOfScalar(u8, left, '.') orelse return error.InvalidRange;
    const prefix = left[0 .. last_dot + 1];
    const start_octet_txt = left[last_dot + 1 ..];

    const start_octet = try std.fmt.parseInt(u8, start_octet_txt, 10);
    const end_octet = try std.fmt.parseInt(u8, right, 10);
    if (end_octet < start_octet) return error.InvalidRange;

    const count: usize = @intCast(end_octet - start_octet + 1);
    if (count > max_hosts) return error.TooManyHosts;

    const out = try allocator.alloc([]const u8, count);
    for (out, 0..) |*slot, i| {
        const octet: u8 = start_octet + @as(u8, @intCast(i));
        slot.* = try std.fmt.allocPrint(allocator, "{s}{d}", .{ prefix, octet });
    }
    return out;
}

fn expandCidr(allocator: std.mem.Allocator, spec: []const u8, max_hosts: usize) ![][]const u8 {
    var parts = std.mem.splitScalar(u8, spec, '/');
    const ip_txt = parts.next() orelse return error.InvalidCIDR;
    const prefix_txt = parts.next() orelse return error.InvalidCIDR;
    const prefix = try std.fmt.parseInt(u8, prefix_txt, 10);
    if (prefix > 32) return error.InvalidCIDR;

    var octets: [4]u8 = undefined;
    var ip_parts = std.mem.splitScalar(u8, ip_txt, '.');
    for (0..4) |i| {
        const p = ip_parts.next() orelse return error.InvalidCIDR;
        octets[i] = try std.fmt.parseInt(u8, p, 10);
    }

    const base: u32 = (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | octets[3];
    const host_bits: u6 = @intCast(32 - prefix);
    const hosts_total_u64: u64 = @as(u64, 1) << host_bits;
    if (hosts_total_u64 == 0 or hosts_total_u64 > max_hosts) return error.TooManyHosts;

    const shift: u5 = @intCast(prefix);
    const mask: u32 = if (prefix == 0) 0 else ~(@as(u32, 0xffffffff) >> shift);
    const network = base & mask;
    const count: usize = @intCast(hosts_total_u64);

    const out = try allocator.alloc([]const u8, count);
    for (0..count) |i| {
        const ip_num = network + @as(u32, @intCast(i));
        const a: u8 = @intCast((ip_num >> 24) & 0xff);
        const b: u8 = @intCast((ip_num >> 16) & 0xff);
        const c: u8 = @intCast((ip_num >> 8) & 0xff);
        const d: u8 = @intCast(ip_num & 0xff);
        out[i] = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
    }
    return out;
}
