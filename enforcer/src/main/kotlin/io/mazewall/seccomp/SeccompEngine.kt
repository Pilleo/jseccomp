package io.mazewall.seccomp

import io.mazewall.Policy

/**
 * Common interface for seccomp installation mechanisms.
 */
interface SeccompEngine {
    /**
     * Installs the given [policy] onto the calling thread.
     * Throws [IllegalStateException] if installation fails.
     */
    fun install(policy: Policy<*>)

    /**
     * Installs the given [policy] globally on the entire process (all threads).
     * This uses SECCOMP_FILTER_FLAG_TSYNC on Linux.
     * Throws [IllegalStateException] if installation fails or is not supported.
     */
    fun installOnProcess(policy: Policy<*>): Unit = throw UnsupportedOperationException("Global process containment is not supported by this engine.")

    /**
     * Returns true if this engine is supported on the current system.
     */
    val isSupported: Boolean
}
