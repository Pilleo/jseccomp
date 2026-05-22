package io.contained

import io.contained.seccomp.PureJavaBpfEngine
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import kotlin.test.assertTrue

class PureJavaBpfEngineTest {

    @Test
    fun `test PureJavaBpfEngine blocks execve`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<Boolean> {
                PureJavaBpfEngine.install(Policy.NO_EXEC)
                try {
                    ProcessBuilder("echo", "hello").start()
                    false
                } catch (e: Exception) {
                    true
                }
            }.get()
            assertTrue(result == true, "execve should have been blocked by PureJavaBpfEngine")
        } finally {
            executor.shutdown()
        }
    }
}
