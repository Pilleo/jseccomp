package io.contained

import io.contained.enforcer.ContainedExecutors
import io.contained.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ContainedExecutorsTest {

    @Test
    fun `test containment wrapper blocks execve`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        val future = safeExecutor.submit {
            // Attempt to spawn a process
            ProcessBuilder("echo", "hello").start()
        }

        val ex = assertFailsWith<ExecutionException> {
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
        val future = safeExecutor.submit {
            "success"
        }

        assertTrue(future.get() == "success")
        executor.shutdown()
    }

    @Test
    fun `test per-thread isolation (TSYNC bug fix)`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        // 1. Run a task on the safe executor to install the seccomp filter on that specific thread
        val future = safeExecutor.submit(java.util.concurrent.Callable {
            "installed"
        })
        kotlin.test.assertEquals("installed", future.get())

        // 2. Now the main thread (uncontained) should still be able to exec!
        // If SECCOMP_FILTER_FLAG_TSYNC was used, the main thread would be permanently blocked here.
        val process = ProcessBuilder("echo", "uncontained").start()
        process.waitFor()
        kotlin.test.assertEquals(0, process.exitValue())

        executor.shutdown()
    }

    @Test
    fun `invokeAll applies containment to all tasks`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val tasks = listOf(
                java.util.concurrent.Callable { ProcessBuilder("echo", "1").start() },
                java.util.concurrent.Callable { ProcessBuilder("echo", "2").start() }
            )

            val futures = safeExecutor.invokeAll(tasks)
            for (future in futures) {
                val ex = assertFailsWith<ExecutionException> {
                    future.get()
                }
                assertTrue(ex.cause is ContainmentViolationException)
            }
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `invokeAny applies containment`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val tasks = listOf(
                java.util.concurrent.Callable {
                    Runtime.getRuntime().exec(arrayOf("echo", "fail"))
                    "should not reach here"
                }
            )

            assertFailsWith<ExecutionException> {
                safeExecutor.invokeAny(tasks)
            }
        } finally {
            executor.shutdown()
        }
    }
}
