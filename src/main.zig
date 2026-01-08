const std = @import("std");
const builtin = @import("builtin");
const utils = @import("utils.zig");
const config = @import("config.zig");
const scanner = @import("scanner.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var stderr = std.io.getStdErr().writer();

    utils.initConsole();
    utils.clearScreen();

    const stdout = std.io.getStdOut().writer();
    const start_time = utils.getTimestampMs();
    // Getting command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip the name of the program itself (first argument)
    _ = args.next();

    // If an argument is passed — use it, otherwise default
    const target = args.next() orelse "127.0.0.1";

    try stdout.print(config.UI.welcome, .{ config.APP_NAME, config.APP_VERSION });
    try stdout.print(config.UI.scanning, .{target});
    utils.printSeparator();

    const results = scanner.scanRangeParallel(allocator, target, &config.PortPresets.fast) catch |err| {
        try stderr.print(config.UI.error_msg, .{@errorName(err)});
        return;
    };
    defer allocator.free(results);

    var open_count: usize = 0;
    for (results) |res| {
        if (res.is_open) {
            try stdout.print(config.UI.result_open, .{res.port});
            open_count += 1;
        } else if (res.error_msg != null) {
            try stderr.print("[!] Port {d}: {s}\n", .{ res.port, res.error_msg.? });
        }
    }

    utils.printSeparator();
    const duration = utils.getTimestampMs() - start_time;
    try stdout.print("[*] Found {d} open ports\n", .{open_count});
    try stdout.print(config.UI.finish, .{ duration, config.AUTHOR });
}
