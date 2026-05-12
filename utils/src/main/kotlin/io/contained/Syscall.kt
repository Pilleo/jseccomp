package io.contained

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
    PTRACE,
    SOCKET,
    INIT_MODULE,
    FINIT_MODULE,
    MEMFD_CREATE,
    IO_URING_SETUP,
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
    PRCTL;

    /** Returns the syscall number for the given [arch], or -1 if not available. */
    fun numberFor(arch: Arch): Int = when (this) {
        FORK         -> arch.fork
        VFORK        -> arch.vfork
        CLONE        -> arch.clone
        CLONE3       -> arch.clone3
        EXECVE       -> arch.execve
        EXECVEAT     -> arch.execveat
        CONNECT      -> arch.connect
        BIND         -> arch.bind
        LISTEN       -> arch.listen
        ACCEPT       -> arch.accept
        ACCEPT4      -> arch.accept4
        SENDTO       -> arch.sendto
        SENDMSG      -> arch.sendmsg
        OPEN         -> arch.open
        OPENAT       -> arch.openat
        OPENAT2      -> arch.openat2
        MMAP         -> arch.mmap
        PTRACE       -> arch.ptrace
        SOCKET       -> arch.socket
        INIT_MODULE -> arch.initModule
        FINIT_MODULE -> arch.finitModule
        MEMFD_CREATE -> arch.memfdCreate
        IO_URING_SETUP -> arch.ioUringSetup
        BPF           -> arch.bpf
        PROCESS_VM_WRITEV -> arch.processVmWritev
        PROCESS_VM_READV -> arch.processVmReadv
        USERFAULTFD  -> arch.userfaultfd
        UNSHARE      -> arch.unshare
        SETNS        -> arch.setns
        MOUNT        -> arch.mount
        UMOUNT2      -> arch.umount2
        PIVOT_ROOT   -> arch.pivotRoot
        CHROOT       -> arch.chroot
        IOCTL        -> arch.ioctl
        PRCTL        -> arch.prctl
    }
}
