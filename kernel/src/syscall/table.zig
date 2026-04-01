// =============================================================================
// Kernel Zxyphor - System Call Implementation Table
// =============================================================================
// Contains the actual implementations of each system call. Each function
// receives pre-validated arguments from the syscall handler and interacts
// with the appropriate kernel subsystem.
// =============================================================================

const main = @import("../main.zig");
const handler = @import("handler.zig");

// =============================================================================
// Uname structure (matches Linux utsname)
// =============================================================================
const UTS_LEN: usize = 65;
const Utsname = extern struct {
    sysname: [UTS_LEN]u8,
    nodename: [UTS_LEN]u8,
    release: [UTS_LEN]u8,
    version: [UTS_LEN]u8,
    machine: [UTS_LEN]u8,
    domainname: [UTS_LEN]u8,
};

// =============================================================================
// Timespec (for nanosleep, clock_gettime)
// =============================================================================
const Timespec = extern struct {
    tv_sec: i64,
    tv_nsec: i64,
};

// =============================================================================
// File operations
// =============================================================================

/// read(fd, buf, count) -> bytes_read or error
pub fn sysRead(fd: u64, buf_addr: u64, count: u64) i64 {
    if (!validateUserPointer(buf_addr, count)) return handler.EFAULT;
    const buffer = userSlice(buf_addr, count) orelse return handler.EFAULT;

    const result = main.vfs.read(@intCast(fd), buffer) catch |err| {
        return vfsErrorToErrno(err);
    };

    return @intCast(result);
}

/// write(fd, buf, count) -> bytes_written or error
pub fn sysWrite(fd: u64, buf_addr: u64, count: u64) i64 {
    if (!validateUserPointer(buf_addr, count)) return handler.EFAULT;
    const data = userSliceConst(buf_addr, count) orelse return handler.EFAULT;

    // Special case: stdout (fd 1) and stderr (fd 2) go to console
    if (fd == 1 or fd == 2) {
        main.vga.writeString(data);
        main.serial.writeString(data);
        return @intCast(data.len);
    }

    const result = main.vfs.write(@intCast(fd), data) catch |err| {
        return vfsErrorToErrno(err);
    };

    return @intCast(result);
}

/// open(path, flags, mode) -> fd or error
pub fn sysOpen(path_addr: u64, flags: u64, mode: u64) i64 {
    const path = userString(path_addr) orelse return handler.EFAULT;
    _ = mode;

    const result = main.vfs.open(path, @truncate(flags)) catch |err| {
        return vfsErrorToErrno(err);
    };

    return @intCast(result);
}

/// close(fd) -> 0 or error
pub fn sysClose(fd: u64) i64 {
    main.vfs.close(@intCast(fd)) catch |err| {
        return vfsErrorToErrno(err);
    };
    return 0;
}

/// lseek(fd, offset, whence) -> new_offset or error
pub fn sysLseek(fd: u64, offset: i64, whence: u32) i64 {
    const result = main.vfs.seek(@intCast(fd), offset, whence) catch |err| {
        return vfsErrorToErrno(err);
    };
    return @intCast(result);
}

// =============================================================================
// Memory management
// =============================================================================

/// brk(addr) -> new_brk or error
pub fn sysBrk(addr: u64) i64 {
    const current = main.process.getCurrent() orelse return handler.ENOMEM;

    if (addr == 0) {
        return @intCast(current.heap_break);
    }

    if (addr >= current.heap_break) {
        // Expand heap — allocate pages for the new region
        current.heap_break = addr;
    } else {
        // Shrink heap — free pages
        current.heap_break = addr;
    }

    return @intCast(current.heap_break);
}

// =============================================================================
// Process management
// =============================================================================

/// getpid() -> pid
pub fn sysGetpid() i64 {
    if (main.process.getCurrent()) |proc| {
        return @intCast(proc.pid);
    }
    return 0;
}

/// fork() -> pid (0 in child, child pid in parent)
pub fn sysFork() i64 {
    // TODO: implement full fork with COW pages
    return handler.ENOSYS;
}

/// exit(status) -> never returns
pub fn sysExit(status: u32) i64 {
    main.process.exitCurrent(status);
    return 0; // Never reached
}

/// wait4(pid, status, options) -> pid or error
pub fn sysWait4(pid: i64, status_addr: u64, options: u32) i64 {
    _ = pid;
    _ = status_addr;
    _ = options;
    return handler.ENOSYS; // TODO
}

/// kill(pid, sig) -> 0 or error
pub fn sysKill(pid: i64, sig: u32) i64 {
    _ = sig;
    if (pid <= 0) return handler.EINVAL;

    if (main.process.findByPid(@intCast(pid))) |proc| {
        main.process.killProcess(proc);
        return 0;
    }

    return handler.ESRCH;
}

// =============================================================================
// System information
// =============================================================================

/// uname(buf) -> 0 or error
pub fn sysUname(buf_addr: u64) i64 {
    if (!validateUserPointer(buf_addr, @sizeOf(Utsname))) return handler.EFAULT;

    const buf: *Utsname = @ptrFromInt(buf_addr);
    @memset(&buf.sysname, 0);
    @memset(&buf.nodename, 0);
    @memset(&buf.release, 0);
    @memset(&buf.version, 0);
    @memset(&buf.machine, 0);
    @memset(&buf.domainname, 0);

    copyString(&buf.sysname, "Zxyphor");
    copyString(&buf.nodename, "zxyphor");
    copyString(&buf.release, "1.0.0-genesis");
    copyString(&buf.version, "#1 SMP 2026");
    copyString(&buf.machine, "x86_64");
    copyString(&buf.domainname, "(none)");

    return 0;
}

// =============================================================================
// Directory operations
// =============================================================================

/// mkdir(path, mode) -> 0 or error
pub fn sysMkdir(path_addr: u64, mode: u16) i64 {
    const path = userString(path_addr) orelse return handler.EFAULT;
    _ = main.vfs.mkdir(path, mode) catch |err| return vfsErrorToErrno(err);
    return 0;
}

/// rmdir(path) -> 0 or error
pub fn sysRmdir(path_addr: u64) i64 {
    const path = userString(path_addr) orelse return handler.EFAULT;
    main.vfs.rmdir(path) catch |err| return vfsErrorToErrno(err);
    return 0;
}

/// unlink(path) -> 0 or error
pub fn sysUnlink(path_addr: u64) i64 {
    const path = userString(path_addr) orelse return handler.EFAULT;
    main.vfs.unlink(path) catch |err| return vfsErrorToErrno(err);
    return 0;
}

/// rename(old, new) -> 0 or error
pub fn sysRename(old_addr: u64, new_addr: u64) i64 {
    const old_path = userString(old_addr) orelse return handler.EFAULT;
    const new_path = userString(new_addr) orelse return handler.EFAULT;
    main.vfs.rename(old_path, new_path) catch |err| return vfsErrorToErrno(err);
    return 0;
}

/// chdir(path) -> 0 or error
pub fn sysChdir(path_addr: u64) i64 {
    const path = userString(path_addr) orelse return handler.EFAULT;
    _ = main.vfs.resolvePath(path) orelse return handler.ENOENT;

    if (main.process.getCurrent()) |proc| {
        const len = @min(path.len, proc.cwd.len);
        @memcpy(proc.cwd[0..len], path[0..len]);
        if (len < proc.cwd.len) proc.cwd[len] = 0;
    }

    return 0;
}

/// getcwd(buf, size) -> 0 or error
pub fn sysGetcwd(buf_addr: u64, size: u64) i64 {
    if (!validateUserPointer(buf_addr, size)) return handler.EFAULT;
    const buffer = userSlice(buf_addr, size) orelse return handler.EFAULT;

    if (main.process.getCurrent()) |proc| {
        // Find CWD length
        var cwd_len: usize = 0;
        for (proc.cwd) |c| {
            if (c == 0) break;
            cwd_len += 1;
        }

        if (cwd_len + 1 > buffer.len) return handler.EINVAL;
        @memcpy(buffer[0..cwd_len], proc.cwd[0..cwd_len]);
        buffer[cwd_len] = 0;
        return @intCast(buf_addr);
    }

    return handler.ENOENT;
}

// =============================================================================
// User/group IDs
// =============================================================================

pub fn sysGetuid() i64 {
    if (main.process.getCurrent()) |proc| return @intCast(proc.uid);
    return 0;
}

pub fn sysGetgid() i64 {
    if (main.process.getCurrent()) |proc| return @intCast(proc.gid);
    return 0;
}

pub fn sysGeteuid() i64 {
    if (main.process.getCurrent()) |proc| return @intCast(proc.euid);
    return 0;
}

pub fn sysGetegid() i64 {
    if (main.process.getCurrent()) |proc| return @intCast(proc.egid);
    return 0;
}

// =============================================================================
// Scheduling
// =============================================================================

/// sched_yield() -> 0
pub fn sysSchedYield() i64 {
    main.scheduler.yield();
    return 0;
}

/// nanosleep(req, rem) -> 0 or error
pub fn sysNanosleep(req_addr: u64, rem_addr: u64) i64 {
    _ = rem_addr;
    if (!validateUserPointer(req_addr, @sizeOf(Timespec))) return handler.EFAULT;

    const req: *const Timespec = @ptrFromInt(req_addr);
    const ms = @as(u64, @intCast(req.tv_sec)) * 1000 + @as(u64, @intCast(req.tv_nsec)) / 1000000;

    main.timer.sleepMs(ms);
    return 0;
}

/// clock_gettime(clock_id, tp) -> 0 or error
pub fn sysClockGettime(clock_id: u32, tp_addr: u64) i64 {
    if (!validateUserPointer(tp_addr, @sizeOf(Timespec))) return handler.EFAULT;

    const tp: *Timespec = @ptrFromInt(tp_addr);

    switch (clock_id) {
        0 => { // CLOCK_REALTIME
            const unix = main.timer.getUnixTimestamp();
            tp.tv_sec = @intCast(unix);
            tp.tv_nsec = 0;
        },
        1 => { // CLOCK_MONOTONIC
            const ms = main.timer.getUptimeMs();
            tp.tv_sec = @intCast(ms / 1000);
            tp.tv_nsec = @intCast((ms % 1000) * 1000000);
        },
        else => return handler.EINVAL,
    }

    return 0;
}

// =============================================================================
// IPC
// =============================================================================

/// pipe(fds) -> 0 or error
pub fn sysPipe(fds_addr: u64) i64 {
    _ = fds_addr;
    return handler.ENOSYS; // TODO: delegate to main.pipe module
}

// =============================================================================
// System control
// =============================================================================

/// reboot(magic1, magic2, cmd) -> 0 or error
pub fn sysReboot(magic1: u32, magic2: u32, cmd: u32) i64 {
    // Check magic numbers (Linux-compatible)
    if (magic1 != 0xfee1dead) return handler.EINVAL;
    if (magic2 != 0x28121969 and magic2 != 0x05121996) return handler.EINVAL;

    // Must be root
    if (main.process.getCurrent()) |proc| {
        if (proc.euid != 0) return handler.EPERM;
    }

    switch (cmd) {
        0x01234567 => { // RESTART
            main.cpu.reboot();
        },
        0xCDEF0123 => { // HALT
            main.cpu.shutdown();
        },
        0x4321FEDC => { // POWER_OFF
            main.cpu.shutdown();
        },
        else => return handler.EINVAL,
    }

    return 0;
}

// =============================================================================
// Networking stubs
// =============================================================================

pub fn sysSocket(domain: u32, sock_type: u32, protocol: u32) i64 {
    _ = domain;
    _ = sock_type;
    _ = protocol;
    return handler.ENOSYS;
}

pub fn sysBind(fd: u64, addr: u64, len: u32) i64 {
    _ = fd;
    _ = addr;
    _ = len;
    return handler.ENOSYS;
}

pub fn sysListen(fd: u64, backlog: u32) i64 {
    _ = fd;
    _ = backlog;
    return handler.ENOSYS;
}

pub fn sysAccept(fd: u64, addr: u64, len: u64) i64 {
    _ = fd;
    _ = addr;
    _ = len;
    return handler.ENOSYS;
}

pub fn sysConnect(fd: u64, addr: u64, len: u32) i64 {
    _ = fd;
    _ = addr;
    _ = len;
    return handler.ENOSYS;
}

pub fn sysSend(fd: u64, buf: u64, len: u64, flags: u32) i64 {
    _ = fd;
    _ = buf;
    _ = len;
    _ = flags;
    return handler.ENOSYS;
}

pub fn sysRecv(fd: u64, buf: u64, len: u64, flags: u32) i64 {
    _ = fd;
    _ = buf;
    _ = len;
    _ = flags;
    return handler.ENOSYS;
}

// =============================================================================
// User pointer validation
// =============================================================================

/// Validate that a user-space pointer range is accessible
fn validateUserPointer(addr: u64, size: u64) bool {
    if (addr == 0) return false;
    if (size == 0) return true;

    // User space is below 0x0000800000000000 on x86_64
    const end = addr +| size;
    if (end < addr) return false; // Overflow
    if (end > 0x0000800000000000) return false;

    return true;
}

fn userSlice(addr: u64, len: u64) ?[]u8 {
    if (!validateUserPointer(addr, len)) return null;
    const ptr: [*]u8 = @ptrFromInt(addr);
    return ptr[0..@intCast(len)];
}

fn userSliceConst(addr: u64, len: u64) ?[]const u8 {
    if (!validateUserPointer(addr, len)) return null;
    const ptr: [*]const u8 = @ptrFromInt(addr);
    return ptr[0..@intCast(len)];
}

fn userString(addr: u64) ?[]const u8 {
    if (addr == 0) return null;
    if (addr >= 0x0000800000000000) return null;

    const ptr: [*]const u8 = @ptrFromInt(addr);
    var len: usize = 0;
    while (len < 4096) : (len += 1) {
        if (ptr[len] == 0) break;
    }
    if (len >= 4096) return null;
    return ptr[0..len];
}

// =============================================================================
// Error conversion
// =============================================================================
fn vfsErrorToErrno(err: main.vfs.VfsError) i64 {
    return switch (err) {
        main.vfs.VfsError.NotFound => handler.ENOENT,
        main.vfs.VfsError.AlreadyExists => handler.EEXIST,
        main.vfs.VfsError.NotADirectory => handler.ENOTDIR,
        main.vfs.VfsError.IsADirectory => handler.EISDIR,
        main.vfs.VfsError.PermissionDenied => handler.EACCES,
        main.vfs.VfsError.NoSpace => handler.ENOSPC,
        main.vfs.VfsError.ReadOnly => handler.EROFS,
        main.vfs.VfsError.InvalidArgument => handler.EINVAL,
        main.vfs.VfsError.NotEmpty => handler.ENOTEMPTY,
        main.vfs.VfsError.IoError => handler.EIO,
        main.vfs.VfsError.NotSupported => handler.ENOSYS,
        main.vfs.VfsError.BrokenPipe => handler.EPIPE,
        main.vfs.VfsError.BadFileDescriptor => handler.EBADF,
        main.vfs.VfsError.TooManyOpenFiles => handler.EMFILE,
        main.vfs.VfsError.NameTooLong => handler.EINVAL,
        else => handler.EIO,
    };
}

fn copyString(dest: []u8, src: []const u8) void {
    const len = @min(src.len, dest.len - 1);
    @memcpy(dest[0..len], src[0..len]);
    dest[len] = 0;
}
