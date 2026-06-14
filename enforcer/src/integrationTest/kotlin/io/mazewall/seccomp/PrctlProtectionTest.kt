package io.mazewall.seccomp

import io.mazewall.BaseIntegrationTest
import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Integration tests verifying that [BpfFilter] correctly performs argument inspection on the
 * `prctl` system call to preserve thread-naming diagnostics while blocking hazardous process-control options.
 *
 * Safe whitelisted options:
 * - 15 (PR_SET_NAME)
 * - 16 (PR_GET_NAME)
 * - 21 (PR_GET_SECCOMP)
 * - 22 (PR_SET_SECCOMP)
 * - 38 (PR_SET_NO_NEW_PRIVS)
 * - 39 (PR_GET_NO_NEW_PRIVS)
 */
class PrctlProtectionTest : BaseIntegrationTest() {
    @Test
    @EnabledIfLinuxAndSupported
    fun `prctl PR_SET_NAME is allowed under default strict policy`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            safeExecutor
                .submit {
                    Arena.ofConfined().use { arena ->
                        val nameSeg = arena.allocateFrom("test-thread-name")
                        val res = LinuxNative.prctl(15, nameSeg.address(), 0, 0, 0).getOrThrow("prctl(PR_SET_NAME)")
                        assertEquals(0, res)
                    }
                }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `prctl PR_GET_NAME is allowed under default strict policy`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            safeExecutor
                .submit {
                    Arena.ofConfined().use { arena ->
                        val nameBuffer = arena.allocate(16)
                        val res = LinuxNative.prctl(16, nameBuffer.address(), 0, 0, 0).getOrThrow("prctl(PR_GET_NAME)")
                        assertEquals(0, res)

                        val name = nameBuffer.getString(0)
                        assertTrue(name.isNotEmpty(), "Expected non-empty thread name")
                    }
                }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `unsafe prctl options are blocked by default strict policy`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor
                    .submit {
                        // Option 25 is PR_SET_MM (hazardous process memory manipulation), which is blocked
                        LinuxNative.prctl(25, 0, 0, 0, 0).getOrThrow("prctl(PR_SET_MM)")
                    }.get()
            }.let { e ->
                assertTrue(
                    e.cause is ContainmentViolationException,
                    "Expected ContainmentViolationException as cause, but got ${e.cause}",
                )
            }
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `unsafe prctl options are allowed when allowUnsafePrctl is explicitly set`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().allowUnsafePrctl().build())

        try {
            safeExecutor
                .submit {
                    // Option 25 is PR_SET_MM. Without BPF blocking, it will not be blocked by seccomp
                    // (though the kernel might return EINVAL/EPERM based on standard kernel capabilities,
                    // it won't be blocked by seccomp BPF with EPERM, so it won't trigger ContainmentViolationException).
                    val res = LinuxNative.prctl(25, 0, 0, 0, 0)
                    // If seccomp BPF had blocked it, res would be Error(errno=1).
                    // When seccomp does not block it, it usually returns Error(errno=22) (EINVAL) because the arguments are invalid.
                    assertTrue(
                        res is LinuxNative.SyscallResult.Error && res.errno != 1,
                        "Expected prctl(25) to not be blocked by seccomp (errno != EPERM, got $res)",
                    )
                }.get()
        } finally {
            executor.shutdown()
        }
    }
}
