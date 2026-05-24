package io.mazewall.enforcer

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ContainedExecutorsTest {
    @Test
    @EnabledIfLinuxAndSupported
    fun `test containment wrapper blocks execve`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        val future =
            safeExecutor.submit {
                // Attempt to spawn a process
                ProcessBuilder("echo", "hello").start()
            }

        val ex =
            assertFailsWith<ExecutionException> {
                future.get()
            }

        assertTrue(ex.cause is ContainmentViolationException, "Expected ContainmentViolationException, got ${ex.cause}")

        executor.shutdown()
    }

    @Test
    fun `test graceful degradation fallback`() {
        val osName = System.getProperty("os.name")
        if (osName.equals("Linux", ignoreCase = true)) return // Only test fallback logic on non-Linux

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        // Should not throw since it degrades gracefully on Mac/Windows
        val future =
            safeExecutor.submit {
                "success"
            }

        assertTrue(future.get() == "success")
        executor.shutdown()
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test per-thread isolation (TSYNC bug fix)`() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        // 1. Run a task on the safe executor to install the seccomp filter on that specific thread
        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    "installed"
                },
            )
        assertEquals("installed", future.get())

        // 2. Now the main thread (uncontained) should still be able to exec!
        // If SECCOMP_FILTER_FLAG_TSYNC was used, the main thread would be permanently blocked here.
        val process = ProcessBuilder("echo", "uncontained").start()
        process.waitFor()
        assertEquals(0, process.exitValue())

        executor.shutdown()
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `invokeAll applies containment to all tasks`() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val tasks =
                listOf(
                    java.util.concurrent.Callable { ProcessBuilder("echo", "1").start() },
                    java.util.concurrent.Callable { ProcessBuilder("echo", "2").start() },
                )

            val futures = safeExecutor.invokeAll(tasks)
            for (future in futures) {
                val ex =
                    assertFailsWith<ExecutionException> {
                        future.get()
                    }
                assertTrue(ex.cause is ContainmentViolationException)
            }
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `invokeAny applies containment`() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val tasks =
                listOf(
                    java.util.concurrent.Callable {
                        Runtime.getRuntime().exec(arrayOf("echo", "fail"))
                        "should not reach here"
                    },
                )

            assertFailsWith<ExecutionException> {
                safeExecutor.invokeAny(tasks)
            }
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `test wrap() executor invokeAll and invokeAny with timeouts`() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        val tasks =
            listOf(
                java.util.concurrent.Callable { "task1" },
                java.util.concurrent.Callable { "task2" },
            )

        val results = safeExecutor.invokeAll(tasks, 5, TimeUnit.SECONDS)
        assertEquals(2, results.size)
        assertEquals("task1", results[0].get())

        val any = safeExecutor.invokeAny(tasks, 5, TimeUnit.SECONDS)
        assertTrue(any == "task1" || any == "task2")

        executor.shutdown()
    }

    @Test
    fun `isContainmentViolation handles nested exceptions with error code`() {
        // error=1 is EPERM
        val root = java.io.IOException("something went wrong (error=1)")
        val nested = RuntimeException("wrapper", root)
        val deeplyNested = RuntimeException("outer", nested)

        assertTrue(
            ContainedExecutors.isContainmentViolation(deeplyNested),
            "Should find violation in nested exception chain",
        )
    }

    @Test
    fun `isContainmentViolation handles suppressed exceptions with error code`() {
        // error: 13 is EACCES
        val root = java.io.IOException("failed (error: 13)")
        val main = RuntimeException("main")
        main.addSuppressed(root)

        assertTrue(ContainedExecutors.isContainmentViolation(main), "Should find violation in suppressed exceptions")
    }

    @Test
    fun `installOnProcess rejects policies with io_uring due to landlock requirement`() {
        val policy =
            Policy
                .builder()
                .base(Policy.PURE_COMPUTE)
                .unblock(Syscall.IO_URING_SETUP)
                .build()

        // Unblocking IO_URING_SETUP triggers needsLandlock = true.
        // installOnProcess does not support Landlock, so it should throw.
        val ex =
            assertFailsWith<UnsupportedOperationException> {
                ContainedExecutors.installOnProcess(policy)
            }
        assertTrue(ex.message!!.contains("does not support Landlock filesystem rules"))
    }
}
