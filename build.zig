// =============================================================================
// Kernel Zxyphor - Build System
// =============================================================================
// Build configuration for the Zxyphor microkernel targeting x86_64.
// Supports both freestanding Zig compilation and Rust FFI integration.
// =============================================================================

const std = @import("std");
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;

pub fn build(b: *std.Build) void {
    // -------------------------------------------------------------------------
    // Target: x86_64 freestanding with no OS, soft-float (no SSE in kernel)
    // -------------------------------------------------------------------------
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_sub = Target.x86.featureSet(&.{
            .sse,
            .sse2,
            .avx,
            .avx2,
        }),
    });

    const optimize = b.standardOptimizeOption(.{});

    // -------------------------------------------------------------------------
    // Kernel executable
    // -------------------------------------------------------------------------
    const kernel = b.addExecutable(.{
        .name = "zxyphor",
        .root_source_file = b.path("kernel/src/main.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .kernel,
    });

    // Use custom linker script for kernel layout
    kernel.setLinkerScript(b.path("linker.ld"));

    // Red zone must be disabled in kernel code — interrupts can corrupt it
    kernel.root_module.red_zone = false;

    // Stack protector is not available in freestanding environment
    kernel.root_module.stack_protector = false;

    // Link the Rust static library if it exists
    kernel.addLibraryPath(b.path("rust/target/x86_64-unknown-none/release"));
    kernel.linkSystemLibrary("zxyphor_rust");

    // -------------------------------------------------------------------------
    // Build steps
    // -------------------------------------------------------------------------
    b.installArtifact(kernel);

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

    // Unit tests (run in hosted environment for testing kernel logic)
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("kernel/src/main.zig"),
        .target = b.host,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run kernel unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
