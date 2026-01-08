const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

pub fn initConsole() void {
    if (builtin.os.tag == .windows) {
        const stdout_handle = std.io.getStdOut().handle;
        var mode: windows.DWORD = 0;
        _ = windows.kernel32.GetConsoleMode(stdout_handle, &mode);
        mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        _ = windows.kernel32.SetConsoleMode(stdout_handle, mode);
    }
}

pub fn isPrivileged() bool {
    if (builtin.os.tag == .windows) {
        return true;
    } else {
        return std.posix.getuid() == 0;
    }
}

pub fn getTimestampMs() i64 {
    return std.time.milliTimestamp();
}

pub fn clearScreen() void {
    const stdout = std.io.getStdOut().writer();
    _ = stdout.write("\x1B[2J\x1B[H") catch {};
}

pub fn printSeparator() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("-" ** 40 ++ "\n", .{}) catch {};
}
