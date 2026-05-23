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
    NANOSLEEP;

    /** Returns the syscall number for the given [arch], or -1 if not available. */
    fun numberFor(arch: Arch): Int = when (this) {
        FORK -> arch.fork
        VFORK -> arch.vfork
        CLONE -> arch.clone
        CLONE3 -> arch.clone3
        EXECVE -> arch.execve
        EXECVEAT -> arch.execveat
        CONNECT -> arch.connect
        BIND -> arch.bind
        LISTEN -> arch.listen
        ACCEPT -> arch.accept
        ACCEPT4 -> arch.accept4
        SENDTO -> arch.sendto
        SENDMSG -> arch.sendmsg
        OPEN -> arch.open
        OPENAT -> arch.openat
        OPENAT2 -> arch.openat2
        MMAP -> arch.mmap
        MPROTECT -> arch.mprotect
        MADVISE -> arch.madvise
        PTRACE -> arch.ptrace
        SOCKET -> arch.socket
        INIT_MODULE -> arch.initModule
        FINIT_MODULE -> arch.finitModule
        MEMFD_CREATE -> arch.memfdCreate
        IO_URING_SETUP -> arch.ioUringSetup
        IO_URING_ENTER -> arch.ioUringEnter
        BPF -> arch.bpf
        PROCESS_VM_WRITEV -> arch.processVmWritev
        PROCESS_VM_READV -> arch.processVmReadv
        USERFAULTFD -> arch.userfaultfd
        UNSHARE -> arch.unshare
        SETNS -> arch.setns
        MOUNT -> arch.mount
        UMOUNT2 -> arch.umount2
        PIVOT_ROOT -> arch.pivotRoot
        CHROOT -> arch.chroot
        IOCTL -> arch.ioctl
        PRCTL -> arch.prctl
        READ -> arch.read
        WRITE -> arch.write
        CLOSE -> arch.close
        FSTAT -> arch.fstat
        LSEEK -> arch.lseek
        MUNMAP -> arch.munmap
        BRK -> arch.brk
        RT_SIGACTION -> arch.rt_sigaction
        RT_SIGPROCMASK -> arch.rt_sigprocmask
        RT_SIGRETURN -> arch.rt_sigreturn
        PREAD64 -> arch.pread64
        PWRITE64 -> arch.pwrite64
        FCNTL -> arch.fcntl
        FUTEX -> arch.futex
        SCHED_YIELD -> arch.sched_yield
        GETRANDOM -> arch.getrandom
        CLOCK_GETTIME -> arch.clock_gettime
        EXIT -> arch.exit
        EXIT_GROUP -> arch.exit_group

        GETPID -> arch.getpid
        GETPPID -> arch.getppid
        GETUID -> arch.getuid
        GETEUID -> arch.geteuid
        GETGID -> arch.getgid
        GETEGID -> arch.getegid
        GETTID -> arch.gettid
        GETCWD -> arch.getcwd
        UMASK -> arch.umask
        CHOWN -> arch.chown
        LCHOWN -> arch.lchown
        FCHOWN -> arch.fchown
        FCHOWNAT -> arch.fchownat
        UTIME -> arch.utime
        UTIMES -> arch.utimes
        UTIMENSAT -> arch.utimensat
        MKDIR -> arch.mkdir
        MKDIRAT -> arch.mkdirat
        RMDIR -> arch.rmdir
        RENAME -> arch.rename
        RENAMEAT -> arch.renameat
        RENAMEAT2 -> arch.renameat2
        LINK -> arch.link
        LINKAT -> arch.linkat
        UNLINK -> arch.unlink
        UNLINKAT -> arch.unlinkat
        SYMLINK -> arch.symlink
        SYMLINKAT -> arch.symlinkat
        READLINK -> arch.readlink
        READLINKAT -> arch.readlinkat
        CHMOD -> arch.chmod
        FCHMOD -> arch.fchmod
        FCHMODAT -> arch.fchmodat
        FSTATAT -> arch.fstatat
        STATX -> arch.statx
        FSYNC -> arch.fsync
        FDATASYNC -> arch.fdatasync
        TRUNCATE -> arch.truncate
        FTRUNCATE -> arch.ftruncate
        PAUSE -> arch.pause
        NANOSLEEP -> arch.nanosleep
    }
}
