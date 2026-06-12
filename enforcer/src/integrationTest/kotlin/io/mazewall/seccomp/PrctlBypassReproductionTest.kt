package io.mazewall.seccomp
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

class PrctlBypassReproductionTest {
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

            println("prctl(1, 15) returned ${res.returnValue}, errno ${res.errno}")

            if (res.returnValue == 0L) {
                // VULNERABILITY CONFIRMED: prctl(1, 15) was allowed!
                throw IllegalStateException("SECURITY BYPASS: prctl(PR_SET_PDEATHSIG, SIGTERM) was allowed")
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

            if (res.returnValue == 0L || res.errno != 1) { // 1 is EPERM
                 // On a standard restricted thread, this should fail with EPERM from seccomp.
                 // If it fails with EINVAL (22), it means it reached the kernel, which is also a bypass
                 // of our seccomp barrier (we want EPERM).
                 if (res.errno == 22) {
                     throw IllegalStateException("SECURITY BYPASS: prctl(PR_CAP_AMBIENT) reached kernel (EINVAL instead of EPERM)")
                 }
                 // If it actually returns 0, it's a critical bypass
                 if (res.returnValue == 0L) {
                     throw IllegalStateException("CRITICAL SECURITY BYPASS: prctl(PR_CAP_AMBIENT) succeeded")
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
