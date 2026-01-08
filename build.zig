const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options for the current system (when just doing zig build run)
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable file
    const exe = b.addExecutable(.{
        .name = "vzor",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);

    // Command to run (zig build run)
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // --- Cross-compilation (Build All) ---
    const build_all_step = b.step("build-all", "Build for all platforms");

    // List of targets
    const targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux },
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
    };

    for (targets) |t| {
        const cross_exe = b.addExecutable(.{
            .name = b.fmt("vzor-{s}-{s}", .{ @tagName(t.cpu_arch.?), @tagName(t.os_tag.?) }),
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(t),
            .optimize = optimize,
        });

        const install_cross = b.addInstallArtifact(cross_exe, .{});
        build_all_step.dependOn(&install_cross.step);
    }
}
