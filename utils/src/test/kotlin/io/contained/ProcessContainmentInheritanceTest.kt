package io.contained

import io.contained.enforcer.ContainedExecutors
import io.contained.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class ProcessContainmentInheritanceTest {

    @Test
    fun `threads spawned after installOnProcess inherit the filter`() {
        // Install custom NO_EXEC (allowing mmap exec) process-wide
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowMmapExec()
            .build()
        ContainedExecutors.installOnProcess(policy)

        // Spawn a new thread
        val thread = Thread {
            try {
                ProcessBuilder("echo", "inherited").start()
                throw RuntimeException("Should not have been able to exec")
            } catch (e: java.io.IOException) {
                // Expected if blocked
            }
        }
        thread.start()
        thread.join()

        // Also test via an executor created after the fact
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit {
                ProcessBuilder("echo", "executor-inherited").start()
            }
            val ex = org.junit.jupiter.api.assertThrows<ExecutionException> {
                future.get()
            }
            // Note: Since we installed process-wide WITHOUT wrapping the executor,
            // the exception might not be wrapped in ContainmentViolationException
            // unless we use ContainedExecutors.wrap or manually catch it.
            // But installOnProcess applies to the WHOLE process.
            assertTrue(ex.cause is java.io.IOException)
        } finally {
            executor.shutdown()
        }
    }
}
