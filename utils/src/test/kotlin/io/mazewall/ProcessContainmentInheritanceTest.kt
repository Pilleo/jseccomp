package io.mazewall

import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationDetector
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class ProcessContainmentInheritanceTest {
    @Test
    fun `threads spawned after installOnProcess inherit the filter`() {
        // Install custom NO_EXEC (allowing mmap exec) process-wide
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowMmapExec()
                .build()
        ContainedExecutors.installOnProcess(policy)

        // Spawn a new thread
        val thread =
            Thread {
                try {
                    ProcessBuilder("echo", "inherited").start()
                    throw IllegalStateException("Should not have been able to exec")
                } catch (e: java.io.IOException) {
                    assertTrue(ContainmentViolationDetector.isContainmentViolation(e), "Expected a containment violation exception, but got: $e")
                }
            }
        thread.start()
        thread.join()

        // Also test via an executor created after the fact
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future =
                executor.submit {
                    ProcessBuilder("echo", "executor-inherited").start()
                }
            val ex =
                org.junit.jupiter.api.assertThrows<ExecutionException> {
                    future.get()
                }
            // Note: Since we installed process-wide WITHOUT wrapping the executor,
            // the exception might not be wrapped in ContainmentViolationException
            // unless we use ContainedExecutors.wrap or manually catch it.
            // But installOnProcess applies to the WHOLE process.
            assertTrue(ContainmentViolationDetector.isContainmentViolation(ex.cause!!), "Expected cause to be a containment violation exception, but got: ${ex.cause}")
        } finally {
            executor.shutdown()
        }
    }
}
