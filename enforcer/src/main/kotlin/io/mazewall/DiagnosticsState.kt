package io.mazewall

/**
 * Seccomp status mode of the JVM process.
 */
sealed interface SeccompMode {
    /** Seccomp is disabled or not configured. */
    data object Disabled : SeccompMode

    /** Seccomp strict mode is active. */
    data object Strict : SeccompMode

    /** Seccomp filter mode (mode 2) is active and running user-defined filters. */
    data object Filter : SeccompMode

    /** Failed to query or retrieve the Seccomp mode. */
    data class Error(
        val errno: Int,
    ) : SeccompMode
}

/**
 * Yama ptrace_scope status.
 */
sealed interface YamaPtraceScope {
    /** Classic ptrace permissions (0). */
    data object Classic : YamaPtraceScope

    /** Restricted ptrace permissions to parent/descendants (1). */
    data object Restricted : YamaPtraceScope

    /** Admin-only ptrace attach (CAP_SYS_PTRACE required) (2). */
    data object AdminOnly : YamaPtraceScope

    /** Ptrace disabled entirely (3). */
    data object Disabled : YamaPtraceScope

    /** Unknown raw ptrace scope value. */
    data class Unknown(
        val rawValue: Int,
    ) : YamaPtraceScope

    /** Yama security module is not loaded or ptrace_scope file is unavailable. */
    data object Unavailable : YamaPtraceScope
}
