// =============================================================================
// Kernel Zxyphor v0.0.2 "Xceon" — Build System
// =============================================================================
// Advanced build configuration for the Zxyphor kernel targeting x86_64.
// Zig 0.15.2 module-based build API. Supports freestanding compilation
// and optional Rust FFI integration via static library linkage.
// =============================================================================

const std = @import("std");
const Target = std.Target;

pub fn build(b: *std.Build) void {
    // -------------------------------------------------------------------------
    // Target: x86_64 freestanding, no OS ABI
    // SSE2 is kept (mandatory x86_64 ISA); AVX/AVX2 disabled for kernel mode.
    // SSE state is saved/restored across context switches and interrupts.
    // -------------------------------------------------------------------------
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_sub = Target.x86.featureSet(&.{
            .avx,
            .avx2,
        }),
    });

    const optimize = b.standardOptimizeOption(.{});

    // -------------------------------------------------------------------------
    // Kernel root module (Zig 0.15.2 module-based API)
    // -------------------------------------------------------------------------
    const kernel_module = b.createModule(.{
        .root_source_file = b.path("kernel/src/main.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .kernel,
        .red_zone = false,
        .stack_protector = false,
        .strip = if (optimize != .Debug) true else null,
        .single_threaded = false,
        .pic = false,
    });

    // -------------------------------------------------------------------------
    // Kernel executable
    // -------------------------------------------------------------------------
    const kernel = b.addExecutable(.{
        .name = "zxyphor",
        .root_module = kernel_module,
    });

    // Use custom linker script for kernel memory layout
    kernel.setLinkerScript(b.path("linker.ld"));

    // Optionally link the Rust static library if the build directory exists
    const rust_lib_path = b.path("rust/target/x86_64-unknown-none/release");
    if (std.fs.cwd().access("rust/target/x86_64-unknown-none/release/libzxyphor_rust.a", .{})) |_| {
        kernel.addLibraryPath(rust_lib_path);
        kernel.linkSystemLibrary("zxyphor_rust");
    } else |_| {
        // Rust library not built yet — kernel can still compile without it
    }

    // -------------------------------------------------------------------------
    // Build steps
    // -------------------------------------------------------------------------
    b.installArtifact(kernel);

    // Run in QEMU step
    const run_step = b.step("run", "Run the kernel in QEMU");
    const qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/zxyphor",
        "-serial",
        "stdio",
        "-m",
        "512M",
        "-smp",
        "4",
        "-no-reboot",
        "-no-shutdown",
    });
    qemu_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&qemu_cmd.step);

    // Debug with QEMU + GDB step
    const debug_step = b.step("debug", "Run kernel in QEMU with GDB server");
    const debug_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/zxyphor",
        "-serial",
        "stdio",
        "-m",
        "512M",
        "-smp",
        "4",
        "-no-reboot",
        "-no-shutdown",
        "-s",
        "-S",
    });
    debug_cmd.step.dependOn(b.getInstallStep());
    debug_step.dependOn(&debug_cmd.step);

    // Create bootable ISO image step
    const iso_step = b.step("iso", "Build a bootable ISO image");
    const iso_cmd = b.addSystemCommand(&.{
        "grub-mkrescue",
        "-o",
        "zxyphor.iso",
        "isodir",
    });
    iso_cmd.step.dependOn(b.getInstallStep());
    iso_step.dependOn(&iso_cmd.step);
}
