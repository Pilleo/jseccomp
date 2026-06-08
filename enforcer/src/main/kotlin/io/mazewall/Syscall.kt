package io.mazewall

/**
 * High-level syscall identifiers. Each variant resolves to an architecture-specific
 * syscall number via [Arch]. Syscalls unavailable on a given architecture (e.g. [OPEN]
 * on aarch64) are represented as -1 and silently skipped during filter construction.
 */
enum class Syscall {
    FORK,
    VFORK,
    CLONE,
    CLONE3,
    EXECVE,
    EXECVEAT,
    CONNECT,
    BIND,
    LISTEN,
    ACCEPT,
    ACCEPT4,
    SENDTO,
    SENDMSG,
    SENDMMSG,
    RECVMMSG,
    OPEN,
    OPENAT,
    OPENAT2,
    MMAP,
    MPROTECT,
    MADVISE,
    PTRACE,
    SOCKET,
    INIT_MODULE,
    FINIT_MODULE,
    MEMFD_CREATE,
    IO_URING_SETUP,
    IO_URING_ENTER,
    BPF,
    PROCESS_VM_WRITEV,
    PROCESS_VM_READV,
    USERFAULTFD,
    UNSHARE,
    SETNS,
    MOUNT,
    UMOUNT2,
    PIVOT_ROOT,
    CHROOT,
    IOCTL,
    PRCTL,
    READ,
    WRITE,
    CLOSE,
    FSTAT,
    LSEEK,
    MUNMAP,
    BRK,
    RT_SIGACTION,
    RT_SIGPROCMASK,
    RT_SIGRETURN,
    PREAD64,
    PWRITE64,
    FCNTL,
    FUTEX,
    SCHED_YIELD,
    GETRANDOM,
    CLOCK_GETTIME,
    EXIT,
    EXIT_GROUP,

    // Harmless/Utility syscalls for fine-grained control and testing
    GETPID,
    GETPPID,
    GETUID,
    GETEUID,
    GETGID,
    GETEGID,
    GETTID,
    GETCWD,
    UMASK,
    CHOWN,
    LCHOWN,
    FCHOWN,
    FCHOWNAT,
    UTIME,
    UTIMES,
    UTIMENSAT,
    MKDIR,
    MKDIRAT,
    RMDIR,
    RENAME,
    RENAMEAT,
    RENAMEAT2,
    LINK,
    LINKAT,
    UNLINK,
    UNLINKAT,
    SYMLINK,
    SYMLINKAT,
    READLINK,
    READLINKAT,
    CHMOD,
    FCHMOD,
    FCHMODAT,
    FSTATAT,
    STATX,
    FSYNC,
    FDATASYNC,
    TRUNCATE,
    FTRUNCATE,
    PAUSE,
    NANOSLEEP,
    ;

    /** Returns the syscall number for the given [arch], or -1 if not available. */
    fun numberFor(arch: Arch): Int = SyscallMapper.numberFor(this, arch)
}

/**
 * Internal helper for mapping [Syscall] to architecture-specific numbers.
 */
internal object SyscallMapper {
    fun numberFor(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.FORK, Syscall.VFORK, Syscall.CLONE, Syscall.CLONE3, Syscall.EXECVE, Syscall.EXECVEAT, Syscall.EXIT, Syscall.EXIT_GROUP,
            Syscall.GETTID, Syscall.GETPID, Syscall.GETPPID, Syscall.GETUID, Syscall.GETEUID, Syscall.GETGID, Syscall.GETEGID, Syscall.PTRACE,
            ->
                ProcessSyscallMapper.numberFor(syscall, arch)

            Syscall.CONNECT, Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SENDMMSG, Syscall.RECVMMSG, Syscall.SOCKET ->
                NetworkSyscallMapper.numberFor(syscall, arch)

            Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2, Syscall.READ, Syscall.WRITE, Syscall.CLOSE, Syscall.FSTAT, Syscall.LSEEK,
            Syscall.PREAD64, Syscall.PWRITE64, Syscall.FCNTL, Syscall.FSYNC, Syscall.FDATASYNC,
            ->
                FsSyscallMapper.numberForBasic(syscall, arch)

            Syscall.TRUNCATE, Syscall.FTRUNCATE, Syscall.GETCWD, Syscall.UMASK, Syscall.CHOWN, Syscall.LCHOWN, Syscall.FCHOWN, Syscall.FCHOWNAT,
            Syscall.UTIME, Syscall.UTIMES, Syscall.UTIMENSAT, Syscall.MKDIR, Syscall.MKDIRAT, Syscall.RMDIR,
            ->
                FsSyscallMapper.numberForAttr(syscall, arch)

            Syscall.RENAME, Syscall.RENAMEAT, Syscall.RENAMEAT2, Syscall.LINK, Syscall.LINKAT, Syscall.UNLINK, Syscall.UNLINKAT,
            Syscall.SYMLINK, Syscall.SYMLINKAT, Syscall.READLINK, Syscall.READLINKAT, Syscall.CHMOD, Syscall.FCHMOD, Syscall.FCHMODAT,
            Syscall.FSTATAT, Syscall.STATX,
            ->
                FsSyscallMapper.numberForOps(syscall, arch)

            Syscall.MMAP, Syscall.MPROTECT, Syscall.MADVISE, Syscall.MEMFD_CREATE, Syscall.MUNMAP, Syscall.BRK ->
                MemorySyscallMapper.numberFor(syscall, arch)

            else -> OtherSyscallMapper.numberFor(syscall, arch)
        }
}

internal object ProcessSyscallMapper {
    fun numberFor(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.FORK, Syscall.VFORK, Syscall.CLONE, Syscall.CLONE3 -> numberForLifecycle(syscall, arch)
            Syscall.EXECVE, Syscall.EXECVEAT, Syscall.EXIT, Syscall.EXIT_GROUP -> numberForExecution(syscall, arch)
            else -> numberForIdentity(syscall, arch)
        }

    private fun numberForLifecycle(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.FORK -> arch.fork
            Syscall.VFORK -> arch.vfork
            Syscall.CLONE -> arch.clone
            Syscall.CLONE3 -> arch.clone3
            else -> -1
        }

    private fun numberForExecution(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.EXECVE -> arch.execve
            Syscall.EXECVEAT -> arch.execveat
            Syscall.EXIT -> arch.exit
            Syscall.EXIT_GROUP -> arch.exit_group
            else -> -1
        }

    private fun numberForIdentity(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.GETTID -> arch.gettid
            Syscall.GETPID -> arch.getpid
            Syscall.GETPPID -> arch.getppid
            Syscall.GETUID -> arch.getuid
            Syscall.GETEUID -> arch.geteuid
            Syscall.GETGID -> arch.getgid
            Syscall.GETEGID -> arch.getegid
            Syscall.PTRACE -> arch.ptrace
            else -> -1
        }
}

internal object NetworkSyscallMapper {
    fun numberFor(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.CONNECT -> arch.connect
            Syscall.BIND -> arch.bind
            Syscall.LISTEN -> arch.listen
            Syscall.ACCEPT -> arch.accept
            Syscall.ACCEPT4 -> arch.accept4
            Syscall.SENDTO -> arch.sendto
            Syscall.SENDMSG -> arch.sendmsg
            Syscall.SENDMMSG -> arch.sendmmsg
            Syscall.RECVMMSG -> arch.recvmmsg
            Syscall.SOCKET -> arch.socket
            else -> -1
        }
}

internal object FsSyscallMapper {
    fun numberForBasic(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2 -> numberForOpen(syscall, arch)
            Syscall.READ, Syscall.WRITE, Syscall.CLOSE, Syscall.FSTAT, Syscall.LSEEK -> numberForIO(syscall, arch)
            else -> numberForMisc(syscall, arch)
        }

    private fun numberForOpen(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.OPEN -> arch.open
            Syscall.OPENAT -> arch.openat
            Syscall.OPENAT2 -> arch.openat2
            else -> -1
        }

    private fun numberForIO(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.READ -> arch.read
            Syscall.WRITE -> arch.write
            Syscall.CLOSE -> arch.close
            Syscall.FSTAT -> arch.fstat
            Syscall.LSEEK -> arch.lseek
            else -> -1
        }

    private fun numberForMisc(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.PREAD64 -> arch.pread64
            Syscall.PWRITE64 -> arch.pwrite64
            Syscall.FCNTL -> arch.fcntl
            Syscall.FSYNC -> arch.fsync
            Syscall.FDATASYNC -> arch.fdatasync
            Syscall.MUNMAP -> arch.munmap
            Syscall.BRK -> arch.brk
            else -> -1
        }

    fun numberForAttr(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.TRUNCATE, Syscall.FTRUNCATE, Syscall.GETCWD, Syscall.UMASK -> numberForAttrBasic(syscall, arch)
            else -> numberForAttrAdvanced(syscall, arch)
        }

    private fun numberForAttrBasic(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.TRUNCATE -> arch.truncate
            Syscall.FTRUNCATE -> arch.ftruncate
            Syscall.GETCWD -> arch.getcwd
            Syscall.UMASK -> arch.umask
            else -> -1
        }

    private fun numberForAttrAdvanced(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.CHOWN -> arch.chown
            Syscall.LCHOWN -> arch.lchown
            Syscall.FCHOWN -> arch.fchown
            Syscall.FCHOWNAT -> arch.fchownat
            Syscall.UTIME -> arch.utime
            Syscall.UTIMES -> arch.utimes
            Syscall.UTIMENSAT -> arch.utimensat
            Syscall.MKDIR -> arch.mkdir
            Syscall.MKDIRAT -> arch.mkdirat
            Syscall.RMDIR -> arch.rmdir
            else -> -1
        }

    fun numberForOps(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.RENAME, Syscall.RENAMEAT, Syscall.RENAMEAT2, Syscall.LINK, Syscall.LINKAT, Syscall.UNLINK, Syscall.UNLINKAT -> numberForPath(
                syscall,
                arch,
            )

            else -> numberForMetadata(syscall, arch)
        }

    private fun numberForPath(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.RENAME -> arch.rename
            Syscall.RENAMEAT -> arch.renameat
            Syscall.RENAMEAT2 -> arch.renameat2
            Syscall.LINK -> arch.link
            Syscall.LINKAT -> arch.linkat
            Syscall.UNLINK -> arch.unlink
            Syscall.UNLINKAT -> arch.unlinkat
            else -> -1
        }

    private fun numberForMetadata(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.SYMLINK -> arch.symlink
            Syscall.SYMLINKAT -> arch.symlinkat
            Syscall.READLINK -> arch.readlink
            Syscall.READLINKAT -> arch.readlinkat
            Syscall.CHMOD -> arch.chmod
            Syscall.FCHMOD -> arch.fchmod
            Syscall.FCHMODAT -> arch.fchmodat
            Syscall.FSTATAT -> arch.fstatat
            Syscall.STATX -> arch.statx
            else -> -1
        }
}

internal object MemorySyscallMapper {
    fun numberFor(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.MMAP -> arch.mmap
            Syscall.MPROTECT -> arch.mprotect
            Syscall.MADVISE -> arch.madvise
            Syscall.MUNMAP -> arch.munmap
            Syscall.BRK -> arch.brk
            Syscall.MEMFD_CREATE -> arch.memfdCreate
            else -> -1
        }
}

internal object OtherSyscallMapper {
    fun numberFor(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER, Syscall.BPF -> numberForAdvancedIO(syscall, arch)
            Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV, Syscall.USERFAULTFD -> numberForInterProcess(
                syscall,
                arch,
            )

            else -> numberForSystem(syscall, arch)
        }

    private fun numberForAdvancedIO(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.IO_URING_SETUP -> arch.ioUringSetup
            Syscall.IO_URING_ENTER -> arch.ioUringEnter
            Syscall.BPF -> arch.bpf
            else -> -1
        }

    private fun numberForInterProcess(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.PROCESS_VM_WRITEV -> arch.processVmWritev
            Syscall.PROCESS_VM_READV -> arch.processVmReadv
            Syscall.USERFAULTFD -> arch.userfaultfd
            else -> -1
        }

    private fun numberForSystem(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.UNSHARE, Syscall.SETNS, Syscall.MOUNT, Syscall.UMOUNT2 -> numberForResource(syscall, arch)
            Syscall.RT_SIGACTION, Syscall.RT_SIGPROCMASK, Syscall.RT_SIGRETURN -> numberForSignal(syscall, arch)
            else -> numberForSystemMisc(syscall, arch)
        }

    private fun numberForResource(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.UNSHARE -> arch.unshare
            Syscall.SETNS -> arch.setns
            Syscall.MOUNT -> arch.mount
            Syscall.UMOUNT2 -> arch.umount2
            else -> -1
        }

    private fun numberForSignal(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.RT_SIGACTION -> arch.rt_sigaction
            Syscall.RT_SIGPROCMASK -> arch.rt_sigprocmask
            Syscall.RT_SIGRETURN -> arch.rt_sigreturn
            else -> -1
        }

    private fun numberForSystemMisc(
        syscall: Syscall,
        arch: Arch,
    ): Int =
        when (syscall) {
            Syscall.PIVOT_ROOT -> arch.pivotRoot
            Syscall.CHROOT -> arch.chroot
            Syscall.IOCTL -> arch.ioctl
            Syscall.PRCTL -> arch.prctl
            Syscall.FUTEX -> arch.futex
            Syscall.SCHED_YIELD -> arch.sched_yield
            Syscall.GETRANDOM -> arch.getrandom
            Syscall.CLOCK_GETTIME -> arch.clock_gettime
            Syscall.PAUSE -> arch.pause
            Syscall.NANOSLEEP -> arch.nanosleep
            Syscall.INIT_MODULE -> arch.initModule
            Syscall.FINIT_MODULE -> arch.finitModule
            else -> -1
        }
}
