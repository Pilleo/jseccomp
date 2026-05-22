package io.contained

import io.contained.profiler.BillOfBehavior
import io.contained.profiler.TraceEvent
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BillOfBehaviorTest {

    @Test
    fun `test plus operator merges stack traces without data loss`() {
        val event = TraceEvent(0, "OPEN", longArrayOf(1), listOf("/test"))

        val stack1 = arrayOf(StackTraceElement("Class1", "method1", "File1.kt", 1))
        val stack2 = arrayOf(StackTraceElement("Class2", "method2", "File2.kt", 2))

        val bob1 = BillOfBehavior(
            stackProfile = mapOf(event to listOf(stack1))
        )

        val bob2 = BillOfBehavior(
            stackProfile = mapOf(event to listOf(stack2))
        )

        val merged = bob1 + bob2

        val traces = merged.stackProfile[event]
        assertTrue(traces != null)
        assertEquals(2, traces.size)
        assertEquals("Class1", traces[0][0].className)
        assertEquals("Class2", traces[1][0].className)
    }

    @Test
    fun `test plus operator merges other fields correctly`() {
        val bob1 = BillOfBehavior(
            opens = setOf("/read1"),
            fsWritePaths = setOf("/write1"),
            syscalls = setOf(Syscall.OPEN),
            execs = setOf("/bin/ls")
        )

        val bob2 = BillOfBehavior(
            opens = setOf("/read2"),
            fsWritePaths = setOf("/write2"),
            syscalls = setOf(Syscall.GETPID),
            execs = setOf("/bin/sh")
        )

        val merged = bob1 + bob2

        assertEquals(setOf("/read1", "/read2"), merged.opens)
        assertEquals(setOf("/write1", "/write2"), merged.fsWritePaths)
        assertEquals(setOf(Syscall.OPEN, Syscall.GETPID), merged.syscalls)
        assertEquals(setOf("/bin/ls", "/bin/sh"), merged.execs)
    }
}
