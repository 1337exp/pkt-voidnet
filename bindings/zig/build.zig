const std = @import("std");

// zig build test -Dvoidnet-lib=../../target/x86_64-pc-windows-gnu/release/libvoidnet_ffi.a -Dtarget=x86_64-windows-gnu
// The library is built with:
//   cargo build -p voidnet-ffi --release --features abi --target x86_64-pc-windows-gnu
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib_path = b.option([]const u8, "voidnet-lib", "path to libvoidnet_ffi.a") orelse
        "../../target/x86_64-pc-windows-gnu/release/libvoidnet_ffi.a";

    const mod = b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addObjectFile(b.path(lib_path));

    const tests = b.addTest(.{ .root_module = mod });
    const run = b.addRunArtifact(tests);
    b.step("test", "run the binding tests against the real library").dependOn(&run.step);
}
