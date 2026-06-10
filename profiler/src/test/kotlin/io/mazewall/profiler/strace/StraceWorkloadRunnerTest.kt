package io.mazewall.profiler.strace

import io.mazewall.profiler.TraceableWorkload
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicBoolean

class StraceWorkloadRunnerTest {
    class MockWorkload : TraceableWorkload {
        companion object {
            val executed = AtomicBoolean(false)
        }

        override fun run() {
            executed.set(true)
        }
    }

    @Test
    fun `main executes valid workload`() {
        MockWorkload.executed.set(false)
        StraceWorkloadRunner.main(arrayOf(MockWorkload::class.java.name))
        assertTrue(MockWorkload.executed.get(), "Workload should have been executed")
    }

    @Test
    fun `main throws on missing argument`() {
        assertThrows(IllegalArgumentException::class.java) {
            StraceWorkloadRunner.main(emptyArray())
        }
    }

    @Test
    fun `main throws on invalid class`() {
        assertThrows(ClassNotFoundException::class.java) {
            StraceWorkloadRunner.main(arrayOf("non.existent.Class"))
        }
    }

    @Test
    fun `main throws on non-workload class`() {
        assertThrows(IllegalArgumentException::class.java) {
            StraceWorkloadRunner.main(arrayOf(String::class.java.name))
        }
    }

    private fun assertTrue(
        condition: Boolean,
        message: String,
    ) {
        if (!condition) throw AssertionError(message)
    }
}
