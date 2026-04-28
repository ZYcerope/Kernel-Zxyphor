# Kernel-Zxyphor Runtime Testing

Use this skill when validating Kernel-Zxyphor kernel boot/runtime behavior.

## Devin Secrets Needed

- None for local build and QEMU/GRUB bootability testing.

## Tooling

- Use Zig 0.15.2 from `/home/ubuntu/.local/zig/zig-x86_64-linux-0.15.2`.
- Useful boot test tools: `qemu-system-x86_64`, `grub-file`, `grub-mkrescue`, `xorriso`, `mtools`.
- Keep Zig caches outside the repo to avoid dirtying tracked artifacts:

```bash
export PATH=/home/ubuntu/.local/zig/zig-x86_64-linux-0.15.2:$PATH
export ZIG_LOCAL_CACHE_DIR=/home/ubuntu/.cache/zig/Kernel-Zxyphor/local
export ZIG_GLOBAL_CACHE_DIR=/home/ubuntu/.cache/zig/Kernel-Zxyphor/global
```

## Build Check

From the repo root:

```bash
zig version
zig build
ls -l zig-out/bin/zxyphor
```

After local builds, restore the tracked binary artifact before leaving the repo if it becomes modified:

```bash
git show HEAD:zig-out/bin/zxyphor > zig-out/bin/zxyphor && chmod 644 zig-out/bin/zxyphor
```

## Bootability Checks

The README/build system may advertise both direct QEMU and Multiboot2/GRUB boot paths. Validate both explicitly before claiming runtime behavior was tested.

Direct QEMU path:

```bash
timeout --foreground --signal=TERM --kill-after=5s 20s zig build run
```

If QEMU reports `Error loading uncompressed kernel without PVH ELF Note`, the kernel did not execute. Treat this as a bootability failure, not a runtime test pass.

Multiboot2/GRUB viability:

```bash
grub-file --is-x86-multiboot2 zig-out/bin/zxyphor && echo MULTIBOOT2_OK || echo MULTIBOOT2_NOT_OK
readelf -S zig-out/bin/zxyphor | rg '\.(multiboot|bootstrap|boot_page_tables)|Name|\[Nr\]' || true
readelf -h zig-out/bin/zxyphor | rg 'Entry|Type|Machine'
nm -n zig-out/bin/zxyphor | rg ' _start| kmain|multiboot_header' || true
```

A healthy Multiboot2 artifact should be recognized by `grub-file`, include the expected early boot sections, and have a nonzero entry point. If `kernel/src/boot/multiboot.zig` defines a header but the built artifact is `MULTIBOOT2_NOT_OK`, check whether the root Zig module imports the boot module so the exported header is linked.

Optional GRUB ISO smoke test:

```bash
rm -rf /home/ubuntu/test-artifacts/Kernel-Zxyphor/iso_root
mkdir -p /home/ubuntu/test-artifacts/Kernel-Zxyphor/iso_root/boot/grub
cp zig-out/bin/zxyphor /home/ubuntu/test-artifacts/Kernel-Zxyphor/iso_root/boot/zxyphor
cat > /home/ubuntu/test-artifacts/Kernel-Zxyphor/iso_root/boot/grub/grub.cfg <<'EOF'
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console
set timeout=0
set default=0
menuentry "Zxyphor Kernel" {
    multiboot2 /boot/zxyphor
    boot
}
EOF
grub-mkrescue -o /home/ubuntu/test-artifacts/Kernel-Zxyphor/zxyphor-test.iso /home/ubuntu/test-artifacts/Kernel-Zxyphor/iso_root
qemu-system-x86_64 -cdrom /home/ubuntu/test-artifacts/Kernel-Zxyphor/zxyphor-test.iso -serial stdio -display none -m 512M -smp 4 -no-reboot -no-shutdown
```

## Runtime Assertions

Only mark runtime behavior as verified if a boot path reaches kernel output. For the v0.0.4 hardware profile, look for exact serial/VGA strings such as:

- `Zxyphor Kernel v0.0.4 "Xceon III"`
- `EEVDF scheduler: Earliest Eligible Virtual Deadline First`
- `Adaptive quantum:`
- `Memory tier policy:`
- `I/O queue budget:`
- `Security posture:`
- `Super profile capability score:`
- `Hardware accelerators:`
- `Recommended CPU lanes:`
- `NUMA/CXL tiers:`
- `Super profile ON`

`strings zig-out/bin/zxyphor` can confirm the text is compiled into the binary, but it is not a substitute for runtime boot verification.
