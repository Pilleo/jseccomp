package io.mazewall.profiler.engine

import io.mazewall.EnabledIfLinuxAndSupported
import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals

class ProfilerDaemonTest {
    @Test
    @EnabledIfLinuxAndSupported
    fun `test readStringFromProcess successfully reads valid null-terminated string`() {
        Arena.ofConfined().use { arena ->
            val testStr = "Hello, Mazewall!"
            val bytes = testStr.toByteArray(StandardCharsets.UTF_8)
            // Allocate space for string + null terminator
            val segment = arena.allocate((bytes.size + 1).toLong())
            for (i in bytes.indices) {
                segment.set(ValueLayout.JAVA_BYTE, i.toLong(), bytes[i])
            }
            segment.set(ValueLayout.JAVA_BYTE, bytes.size.toLong(), 0.toByte()) // Null terminator

            val selfPid = ProcessHandle.current().pid().toInt()
            val result = ProfilerDaemon.readStringFromProcess(selfPid, segment.address(), 4096)
            assertEquals(testStr, result)
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test readStringFromProcess returns best-effort string when null-terminator is missing`() {
        Arena.ofConfined().use { arena ->
            val testStr = "Not null-terminated"
            val bytes = testStr.toByteArray(StandardCharsets.UTF_8)
            // Allocate only space for the characters, NO space for null terminator
            val segment = arena.allocate(bytes.size.toLong())
            for (i in bytes.indices) {
                segment.set(ValueLayout.JAVA_BYTE, i.toLong(), bytes[i])
            }

            val selfPid = ProcessHandle.current().pid().toInt()
            // We pass maxLen = bytes.size so that processVmReadv reads exactly bytes.size bytes.
            // Since there is no null terminator in those bytes, it should return the best-effort string.
            val result = ProfilerDaemon.readStringFromProcess(selfPid, segment.address(), bytes.size)
            assertEquals(testStr, result, "Expected best-effort string due to missing null-terminator within bounds")
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test readStringFromProcess handles empty string`() {
        Arena.ofConfined().use { arena ->
            // Allocate space for a single null byte
            val segment = arena.allocate(1)
            segment.set(ValueLayout.JAVA_BYTE, 0L, 0.toByte())

            val selfPid = ProcessHandle.current().pid().toInt()
            val result = ProfilerDaemon.readStringFromProcess(selfPid, segment.address(), 10)
            assertEquals("", result)
        }
    }
}
