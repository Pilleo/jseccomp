package io.contained.seccomp

import io.contained.EnabledIfLinuxAndSupported
import io.contained.Platform
import io.contained.Policy
import io.contained.Syscall
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class PureJavaBpfEngineTest {

    @Test
    @EnabledIfLinuxAndSupported
    fun `test PureJavaBpfEngine blocks execve`() {
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

    @Test
    @EnabledIfLinuxAndSupported
    fun `test PureJavaBpfEngine isSupported`() {
        assertTrue(PureJavaBpfEngine.isSupported, "PureJavaBpfEngine should be supported on Linux")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test PureJavaBpfEngine with large policy`() {
        val builder = Policy.builder()
        // Block a lot of syscalls to exercise BPF generation
        Syscall.entries.take(50).forEach { builder.block(it) }
        val policy = builder.build()

        val executor = Executors.newSingleThreadExecutor()
        try {
            executor.submit {
                PureJavaBpfEngine.install(policy)
            }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `test SeccompEngine default implementation`() {
        val engine = object : SeccompEngine {
            override val isSupported: Boolean = true
            override fun install(policy: Policy) {}
        }
        // Should throw UnsupportedOperationException as per default impl
        assertFailsWith<UnsupportedOperationException> {
            engine.installOnProcess(Policy.PURE_COMPUTE)
        }
    }
}
