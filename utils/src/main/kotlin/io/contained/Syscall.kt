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
    SENDTO,
    SENDMSG,
    OPEN,
    OPENAT,
    MMAP,
    PTRACE,
    SOCKET,
    INIT_MODULE,
    FINIT_MODULE;

    /** Returns the syscall number for the given [arch], or -1 if not available. */
    fun numberFor(arch: Arch): Int = when (this) {
        FORK         -> arch.fork
        VFORK        -> arch.vfork
        CLONE        -> arch.clone
        CLONE3       -> arch.clone3
        EXECVE       -> arch.execve
        EXECVEAT     -> arch.execveat
        CONNECT      -> arch.connect
        SENDTO       -> arch.sendto
        SENDMSG      -> arch.sendmsg
        OPEN         -> arch.open
        OPENAT       -> arch.openat
        MMAP         -> arch.mmap
        PTRACE       -> arch.ptrace
        SOCKET       -> arch.socket
        INIT_MODULE  -> arch.initModule
        FINIT_MODULE -> arch.finitModule
    }
}
