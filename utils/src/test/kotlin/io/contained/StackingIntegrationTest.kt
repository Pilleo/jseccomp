package io.contained

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.util.concurrent.Executors
import kotlin.test.assertTrue

class StackingIntegrationTest {
    @Test
    fun `test filter stacking depth limit`() {
        if (!Platform.isSupported()) return

        var depthException: IllegalStateException? = null
        val t = Thread {
            try {
                val safeSyscalls = Syscall.values().filter { 
                    it != Syscall.PRCTL && it != Syscall.MMAP && it != Syscall.MPROTECT && it != Syscall.CLONE 
                }
                for (i in 0..33) {
                    val syscall = safeSyscalls[i % safeSyscalls.size] 
                    val policy = Policy.builder().block(syscall).build()
                    ContainedExecutors.installOnCurrentThread(policy)
                }
            } catch (e: IllegalStateException) {
                depthException = e
            }
        }
        t.start()
        t.join()

        assertTrue(depthException != null, "Expected IllegalStateException after 32 filters")
        assertTrue(depthException!!.message!!.contains("Cannot install more than 32 seccomp filters"), 
            "Unexpected exception message: ${depthException!!.message}")
    }
}
