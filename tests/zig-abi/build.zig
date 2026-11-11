const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib_path = b.option([]const u8, "voidnet-lib", "path to libvoidnet_ffi.a") orelse
        "../../target/x86_64-pc-windows-gnu/release/libvoidnet_ffi.a";

    const mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addObjectFile(b.path(lib_path));

    const exe = b.addExecutable(.{ .name = "abi_check", .root_module = mod });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    b.step("run", "run the ABI check (exit code 0 = ok)").dependOn(&run.step);
}
