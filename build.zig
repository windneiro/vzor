const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "vzor",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const build_windows_step = b.step("build-windows", "Build Windows x86_64 binary");
    const build_linux_step = b.step("build-linux", "Build Linux x86_64 binary");
    const build_linux_arm64_step = b.step("build-linux-arm64", "Build Linux aarch64 binary");
    const build_all_step = b.step("build-all", "Build for all platforms");

    addCrossTarget(b, optimize, .{ .cpu_arch = .x86_64, .os_tag = .windows }, build_windows_step, build_all_step);
    addCrossTarget(b, optimize, .{ .cpu_arch = .x86_64, .os_tag = .linux }, build_linux_step, build_all_step);
    addCrossTarget(b, optimize, .{ .cpu_arch = .aarch64, .os_tag = .linux }, build_linux_arm64_step, build_all_step);
}

fn addCrossTarget(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    query: std.Target.Query,
    platform_step: *std.Build.Step,
    build_all_step: *std.Build.Step,
) void {
    const cross_exe = b.addExecutable(.{
        .name = b.fmt("vzor-{s}-{s}", .{ @tagName(query.cpu_arch.?), @tagName(query.os_tag.?) }),
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(query),
        .optimize = optimize,
        .link_libc = true,
    });

    const install_cross = b.addInstallArtifact(cross_exe, .{});
    platform_step.dependOn(&install_cross.step);
    build_all_step.dependOn(&install_cross.step);
}
