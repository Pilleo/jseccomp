package io.contained

import io.contained.enforcer.ContainedExecutors
import io.contained.enforcer.ContainmentViolationException
import java.lang.foreign.Arena
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.assertEquals

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
class PrctlProtectionTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `prctl PR_SET_NAME is allowed under default strict policy`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            safeExecutor.submit {
                Arena.ofConfined().use { arena ->
                    val nameSeg = arena.allocateFrom("test-thread-name")
                    val res = LinuxNative.prctl(15, nameSeg.address(), 0, 0, 0)
                    assertEquals(0, res.returnValue, "prctl(PR_SET_NAME) failed with errno ${res.errno}")
                }
            }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `prctl PR_GET_NAME is allowed under default strict policy`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            safeExecutor.submit {
                Arena.ofConfined().use { arena ->
                    val nameBuffer = arena.allocate(16)
                    val res = LinuxNative.prctl(16, nameBuffer.address(), 0, 0, 0)
                    assertEquals(0, res.returnValue, "prctl(PR_GET_NAME) failed with errno ${res.errno}")
                    
                    val name = nameBuffer.getString(0)
                    assertTrue(name.isNotEmpty(), "Expected non-empty thread name")
                }
            }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `unsafe prctl options are blocked by default strict policy`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor.submit {
                    // Option 25 is PR_SET_MM (hazardous process memory manipulation), which is blocked
                    val res = LinuxNative.prctl(25, 0, 0, 0, 0)
                    if (res.returnValue != 0L) {
                        throw java.io.IOException("Operation not permitted")
                    }
                }.get()
            }.let { e ->
                assertTrue(e.cause is ContainmentViolationException, "Expected ContainmentViolationException as cause, but got ${e.cause}")
            }
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `unsafe prctl options are allowed when allowUnsafePrctl is explicitly set`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().allowUnsafePrctl().build())

        try {
            safeExecutor.submit {
                // Option 25 is PR_SET_MM. Without BPF blocking, it will not be blocked by seccomp
                // (though the kernel might return EINVAL/EPERM based on standard kernel capabilities, 
                // it won't be blocked by seccomp BPF with EPERM, so it won't trigger ContainmentViolationException).
                val res = LinuxNative.prctl(25, 0, 0, 0, 0)
                // If seccomp BPF had blocked it, res.returnValue would have been -1 and res.errno would be EPERM (1).
                // When seccomp does not block it, it usually returns -1 with EINVAL (22) because the arguments are invalid.
                assertTrue(res.errno != 1, "Expected prctl(25) to not be blocked by seccomp (errno != EPERM, got ${res.errno})")
            }.get()
        } finally {
            executor.shutdown()
        }
    }
}
