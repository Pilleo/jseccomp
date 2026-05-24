package io.mazewall.seccomp

import io.mazewall.*
import java.lang.foreign.Arena

/**
 * Pure Java implementation of the seccomp engine.
 * Generates BPF filters manually and installs them using Downcalls.
 */
object PureJavaBpfEngine : SeccompEngine {
    override val isSupported: Boolean
        get() = Platform.isSupported()

    override fun install(policy: Policy) {
        installInternal(policy, useTsync = false)
    }

    override fun installOnProcess(policy: Policy) {
        installInternal(policy, useTsync = true)
    }

    private fun installInternal(
        policy: Policy,
        useTsync: Boolean,
    ) {
        setNoNewPrivs()

        val arch = Arch.current()
        val filters = BpfFilter.build(arch, policy)

        Arena.ofConfined().use { arena ->
            val prog = LinuxNative.newSockFProg(arena, filters)
            installFilter(arch, prog, useTsync)
        }

        verifyInstallation(policy)
    }

    private fun setNoNewPrivs() {
        // Step 1: Set no_new_privs (mandatory for non-root seccomp)
        val r1 = LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if (r1.returnValue != 0L) {
            throw IllegalStateException("prctl(PR_SET_NO_NEW_PRIVS) failed with errno ${r1.errno}")
        }
    }

    private fun installFilter(
        arch: Arch,
        prog: java.lang.foreign.MemorySegment,
        useTsync: Boolean,
    ) {
        // Try modern seccomp(2) syscall first
        val flags = if (useTsync) LinuxNative.SECCOMP_FILTER_FLAG_TSYNC.toLong() else 0L
        val r3 =
            LinuxNative.syscall(
                arch.seccompSyscallNumber.toLong(),
                LinuxNative.SECCOMP_SET_MODE_FILTER.toLong(),
                flags,
                prog,
            )

        if (r3.returnValue != 0L) {
            // Fall back to prctl for older kernels
            val errno1 = r3.errno

            // Note: prctl SECCOMP_MODE_FILTER does not support TSYNC directly in the same way.
            // If the user requested TSYNC and seccomp(2) failed, we must fail rather than
            // silently falling back to thread-local behavior.
            if (useTsync) {
                throw IllegalStateException(
                    "Process-wide seccomp installation (TSYNC) failed: seccomp(2) failed with errno $errno1. Your kernel may be too old to support SECCOMP_FILTER_FLAG_TSYNC.",
                )
            }

            val r4 =
                LinuxNative.prctl(
                    LinuxNative.PR_SET_SECCOMP,
                    LinuxNative.SECCOMP_MODE_FILTER.toLong(),
                    prog,
                    0,
                    0,
                )

            if (r4.returnValue != 0L) {
                throw IllegalStateException(
                    "seccomp installation failed: seccomp(2) errno=$errno1, prctl errno=${r4.errno}",
                )
            }
        }
    }

    private fun verifyInstallation(policy: Policy) {
        val canVerify =
            if (policy.mode == Policy.Mode.DENY_LIST) {
                !policy.syscalls.contains(Syscall.PRCTL)
            } else {
                policy.syscalls.contains(Syscall.PRCTL)
            }

        if (!canVerify) {
            return // Cannot verify because prctl itself is restricted
        }

        // Verify filter is actually installed
        val r5 = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
        if (r5.returnValue != 2L) {
            throw IllegalStateException(
                "Seccomp filter verification failed: expected mode 2, got ${r5.returnValue}",
            )
        }
    }
}
