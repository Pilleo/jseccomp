package io.contained

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
            Runtime.getRuntime().exec(arrayOf("echo", "hello"))
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
        val process = Runtime.getRuntime().exec(arrayOf("echo", "uncontained"))
        process.waitFor()
        kotlin.test.assertEquals(0, process.exitValue())
        
        executor.shutdown()
    }
}
