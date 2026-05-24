package io.mazewall.profiler

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class TraceEventTest {
    @Test
    fun `test trace events equality ignores pid`() {
        val event1 = TraceEvent(1001, "OPENAT", longArrayOf(1, 2, 3), listOf("/etc/passwd"))
        val event2 = TraceEvent(1002, "OPENAT", longArrayOf(1, 2, 3), listOf("/etc/passwd"))
        val event3 = TraceEvent(1001, "OPENAT", longArrayOf(1, 2, 4), listOf("/etc/passwd"))

        assertEquals(event1, event2, "Events with different PIDs but same syscall/args/paths should be equal")
        assertEquals(event1.hashCode(), event2.hashCode(), "HashCodes should match for equal events")

        assertNotEquals(event1, event3, "Events with different args should not be equal")
    }

    @Test
    fun `test trace events in a set deduplicate by behavior`() {
        val event1 = TraceEvent(1001, "OPENAT", longArrayOf(1, 2, 3), listOf("/etc/passwd"))
        val event2 = TraceEvent(1002, "OPENAT", longArrayOf(1, 2, 3), listOf("/etc/passwd"))

        val set = setOf(event1, event2)
        assertEquals(1, set.size, "Set should deduplicate events by behavior, ignoring PID")
    }
}
