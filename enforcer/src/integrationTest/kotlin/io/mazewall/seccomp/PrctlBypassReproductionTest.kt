package io.mazewall.seccomp

import io.mazewall.BaseIntegrationTest
import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.fail

class PrctlBypassReproductionTest : BaseIntegrationTest() {
    @Test
    @EnabledIfLinuxAndSupported
    fun `reproduce prctl PR_SET_PDEATHSIG bypass`() {
        val executor = Executors.newSingleThreadExecutor()
        // Strict policy should block everything except whitelisted prctl options
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            val res = safeExecutor
                .submit(
                    Callable {
                        // PR_SET_PDEATHSIG is 1. Signal 15 is SIGTERM.
                        // 15 is also the value of PR_SET_NAME (whitelisted).
                        // If the filter is broken, it might allow this!
                        LinuxNative.prctl(1, 15, 0, 0, 0)
                    },
                ).get()

            when (res) {
                is LinuxNative.SyscallResult.Success -> {
                    // VULNERABILITY CONFIRMED: prctl(1, 15) was allowed!
                    throw IllegalStateException("SECURITY BYPASS: prctl(PR_SET_PDEATHSIG, SIGTERM) was allowed")
                }

                is LinuxNative.SyscallResult.Error -> {
                    if (res.errno != 1) {
                        throw IllegalStateException("SECURITY BYPASS: prctl(PR_SET_PDEATHSIG) reached kernel (errno ${res.errno} instead of EPERM)")
                    }
                    res.throwErrno("prctl(PR_SET_PDEATHSIG)")
                }
            }
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause is ContainmentViolationException) {
                // Correctly blocked!
                return
            }
            if (cause is IllegalStateException && cause.message?.contains("SECURITY BYPASS") == true) {
                fail(cause.message)
            }
            throw e
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    @Suppress("ThrowsCount")
    fun `reproduce prctl PR_CAP_AMBIENT_RAISE bypass`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            val res = safeExecutor
                .submit(
                    Callable {
                        // PR_CAP_AMBIENT is 47. Op 2 is PR_CAP_AMBIENT_RAISE.
                        // If we pass 15 as the 3rd or 4th arg, does it bypass?
                        LinuxNative.prctl(47, 2, 15, 0, 0)
                    },
                ).get()

            when (res) {
                is LinuxNative.SyscallResult.Success -> {
                    throw IllegalStateException("CRITICAL SECURITY BYPASS: prctl(PR_CAP_AMBIENT) succeeded")
                }

                is LinuxNative.SyscallResult.Error -> {
                    if (res.errno == 22) { // EINVAL
                        throw IllegalStateException("SECURITY BYPASS: prctl(PR_CAP_AMBIENT) reached kernel (EINVAL instead of EPERM)")
                    }
                    if (res.errno != 1) {
                        throw IllegalStateException("SECURITY BYPASS: prctl(PR_CAP_AMBIENT) reached kernel (errno ${res.errno} instead of EPERM)")
                    }
                    res.throwErrno("prctl(PR_CAP_AMBIENT)")
                }
            }
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause is ContainmentViolationException) {
                return
            }
            if (cause is IllegalStateException && cause.message?.contains("BYPASS") == true) {
                fail(cause.message)
            }
            throw e
        } finally {
            executor.shutdown()
        }
    }
}
