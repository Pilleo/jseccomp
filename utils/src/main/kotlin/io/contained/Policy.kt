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
            .toIntArray()

    companion object {
        /** Blocks all network I/O, process execution, and file opens. Suitable for pure computation tasks. */
        val PURE_COMPUTE: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.OPEN, Syscall.OPENAT)
            .build()

        /** Blocks outbound network syscalls only. */
        val NO_NETWORK: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
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
