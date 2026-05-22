package io.contained

import io.contained.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class VirtualThreadGuardrailTest {

    @Test
    fun `installOnCurrentThread throws IllegalStateException on virtual thread`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newVirtualThreadPerTaskExecutor()
        try {
            val future = executor.submit {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
            }
            val exception = assertFailsWith<ExecutionException> {
                future.get()
            }
            assertTrue(exception.cause is IllegalStateException)
            assertTrue(exception.cause!!.message!!.contains("virtual thread"))
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `installOnCurrentThread succeeds on platform thread`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        try {
            executor.submit {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
                // If it doesn't throw, it succeeds
            }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `wrap does not throw on virtual thread submission`() {
        // Even if the executor uses virtual threads, wrap() itself should be safe.
        // The guardrail only kicks in when the task actually runs.
        val vExecutor = Executors.newVirtualThreadPerTaskExecutor()
        try {
            val safeExecutor = ContainedExecutors.wrap(vExecutor, Policy.NO_EXEC)
            
            val future = safeExecutor.submit {
                // This task will fail when it tries to apply containment
            }
            
            assertFailsWith<ExecutionException> {
                future.get()
            }
        } finally {
            vExecutor.shutdown()
        }
    }
}
