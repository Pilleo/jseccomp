package io.contained

/**
 * Defines which syscalls to block. Create via [builder] or use the built-in presets.
 *
 * Policies can be combined with [combine]:
 * ```kotlin
 * val p = Policy.combine(Policy.NO_NETWORK, Policy.NO_EXEC)
 * ```
 */
class Policy private constructor(internal val blocked: Set<Syscall>) {

    /** Returns the concrete syscall numbers to block for the given [arch]. */
    fun blockedSyscalls(arch: Arch): IntArray =
        blocked
            .map { it.numberFor(arch) }
            .filter { it >= 0 } // -1 means "not available on this arch"
            .sorted()
            .toIntArray()

    companion object {
        /** Blocks all network I/O, process execution, and file opens. Suitable for pure computation tasks. */
        val PURE_COMPUTE: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2)
            .block(Syscall.MEMFD_CREATE, Syscall.PTRACE)
            .block(Syscall.IO_URING_SETUP, Syscall.BPF)
            .block(Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV)
            .block(Syscall.USERFAULTFD, Syscall.UNSHARE, Syscall.SETNS)
            .block(Syscall.MOUNT, Syscall.UMOUNT2, Syscall.PIVOT_ROOT, Syscall.CHROOT)
            .block(Syscall.IOCTL, Syscall.PRCTL)
            .build()

        /** Blocks outbound network syscalls only. */
        val NO_NETWORK: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
            .build()

        /** Blocks process execution syscalls only. */
        val NO_EXEC: Policy = builder()
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.FORK, Syscall.VFORK)
            .build()

        fun builder(): Builder = Builder()

        /** Returns a new Policy that is the union of all blocked syscalls in the given [policies]. */
        fun combine(vararg policies: Policy): Policy {
            val union = policies.flatMap { it.blocked }.toSet()
            return Policy(union)
        }
    }

    class Builder {
        private val blocked = mutableSetOf<Syscall>()

        fun block(vararg syscalls: Syscall): Builder {
            blocked.addAll(syscalls)
            return this
        }

        fun build(): Policy = Policy(blocked.toSet())
    }
}
