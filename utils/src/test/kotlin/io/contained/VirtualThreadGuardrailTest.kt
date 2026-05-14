package io.contained

import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class VirtualThreadGuardrailTest {

    @Test
    fun `installOnCurrentThread throws IllegalStateException on virtual thread`() {
        val errorRef = AtomicReference<Throwable>(null)

        val vt = Thread.ofVirtual().name("test-vt").start {
            try {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
            } catch (e: IllegalStateException) {
                errorRef.set(e)
            }
        }
        vt.join()

        val ex = errorRef.get()
        assertNotNull(ex, "Expected IllegalStateException from virtual thread")
        assertTrue(ex.message!!.contains("virtual thread"), "Expected message about virtual threads, got: ${ex.message}")
    }

    @Test
    fun `installOnCurrentThread succeeds on platform thread`() {
        if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        var error: Throwable? = null
        val thread = Thread {
            try {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
            } catch (e: Throwable) {
                error = e
            }
        }
        thread.start()
        thread.join()
        error?.let { throw it }
    }

    @Test
    fun `wrap does not throw on virtual thread submission`() {
        if (!Platform.isSupported()) return

        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        val future = safeExecutor.submit { "hello" }
        future.get()

        executor.shutdown()
    }
}
