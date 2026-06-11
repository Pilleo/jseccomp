package io.mazewall.seccomp

import io.mazewall.BpfFilter
import io.mazewall.LinuxNative
import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.ffi.NativeConstants
import java.lang.foreign.Arena

/**
 * Pure Java implementation of the seccomp engine.
 * Generates BPF filters manually and installs them using Downcalls.
 */
object PureJavaBpfEngine : SeccompEngine {
    private val threadState = ThreadLocal.withInitial<SeccompInstallationState> { SeccompInstallationState.Uninitialized }

    internal val state: SeccompInstallationState
        get() = threadState.get()

    override val isSupported: Boolean
        get() = Platform.isSupported()

    override fun install(policy: Policy<*>) {
        installInternal(policy, useTsync = false)
    }

    override fun installOnProcess(policy: Policy<*>) {
        installInternal(policy, useTsync = true)
    }

    @Suppress("TooGenericExceptionCaught")
    private fun installInternal(
        policy: Policy<*>,
        useTsync: Boolean,
    ) {
        threadState.set(SeccompInstallationState.Uninitialized)
        try {
            setNoNewPrivs()
            threadState.set(SeccompInstallationState.PrivilegesLocked)

            val arch = Arch.current()
            val filters = BpfFilter.build(arch, policy)

            Arena.ofConfined().use { arena ->
                val prog = LinuxNative.getMemory().newSockFProg(arena, filters)
                threadState.set(SeccompInstallationState.FilterBuilt(prog))
                installFilter(arch, prog, useTsync)
            }

            verifyInstallation(policy)
        } catch (e: Throwable) {
            val stepName = when (val current = threadState.get()) {
                is SeccompInstallationState.FilterBuilt -> "installFilter"
                is SeccompInstallationState.SystemCallApplied, is SeccompInstallationState.FallbackPrctlApplied -> "verifyInstallation"
                is SeccompInstallationState.PrivilegesLocked -> "buildFilter"
                is SeccompInstallationState.Uninitialized -> "setNoNewPrivs"
                else -> current.javaClass.simpleName
            }
            val errno = when {
                e.message?.contains("errno") == true -> {
                    val match = Regex("errno\\s*=?\\s*(-?\\d+)").find(e.message ?: "")
                    match?.groupValues?.get(1)?.toIntOrNull() ?: -1
                }
                else -> -1
            }
            threadState.set(SeccompInstallationState.Failed(stepName, errno, e))
            throw e
        }
    }

    private fun setNoNewPrivs() {
        // Step 1: Set no_new_privs (mandatory for non-root seccomp)
        val r1 = LinuxNative.getProcess().prctl(NativeConstants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
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
        val flags = if (useTsync) NativeConstants.SECCOMP_FILTER_FLAG_TSYNC.toLong() else 0L
        val r3 =
            LinuxNative.syscall(
                arch.seccompSyscallNumber.toLong(),
                NativeConstants.SECCOMP_SET_MODE_FILTER.toLong(),
                flags,
                prog,
            )

        if (r3.returnValue != 0L) {
            // Fall back to prctl for older kernels
            val errno1 = r3.errno

            if (useTsync) {
                val detail = if (errno1 == 13) {
                    "failed with EACCES (Permission denied). This typically occurs because some pre-existing sibling threads (e.g. GC, JIT, or VM helper threads spawned during JVM startup) do not have the 'no_new_privs' flag enabled. To fix this, ensure the JVM process is started with privilege escalation disabled (e.g., OCI/Kubernetes 'allowPrivilegeEscalation: false', or running under a wrapper launcher that sets the flag before calling execve)."
                } else {
                    "failed with errno $errno1. Your kernel may be too old to support SECCOMP_FILTER_FLAG_TSYNC or the parameters are invalid."
                }
                throw IllegalStateException("Process-wide seccomp installation (TSYNC) failed: $detail")
            }

            val r4 =
                LinuxNative.getProcess().prctl(
                    NativeConstants.PR_SET_SECCOMP,
                    NativeConstants.SECCOMP_MODE_FILTER.toLong(),
                    prog,
                    0,
                    0,
                )

            if (r4.returnValue != 0L) {
                throw IllegalStateException(
                    "seccomp installation failed: seccomp(2) errno=$errno1, prctl errno=${r4.errno}",
                )
            } else {
                threadState.set(SeccompInstallationState.FallbackPrctlApplied)
            }
        } else {
            threadState.set(SeccompInstallationState.SystemCallApplied)
        }
    }

    private fun verifyInstallation(policy: Policy<*>) {
        val prctlAction = policy.syscallActions[Syscall.PRCTL] ?: policy.defaultAction
        val canVerify = prctlAction == SeccompAction.ACT_ALLOW

        if (!canVerify) {
            threadState.set(SeccompInstallationState.Verified)
            return // Cannot verify because prctl itself is restricted
        }

        // Verify filter is actually installed
        val r5 = LinuxNative.getProcess().prctl(NativeConstants.PR_GET_SECCOMP, 0, 0, 0, 0)
        if (r5.returnValue != 2L) {
            throw IllegalStateException(
                "Seccomp filter verification failed: expected mode 2, got ${r5.returnValue}",
            )
        }
        threadState.set(SeccompInstallationState.Verified)
    }
}
