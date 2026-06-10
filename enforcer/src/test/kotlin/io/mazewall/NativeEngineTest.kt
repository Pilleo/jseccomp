package io.mazewall

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class NativeEngineTest {
    @AfterEach
    fun tearDown() {
        // Always reset to real engine after each test to avoid polluting other tests
        LinuxNative.setEngine(RealNativeEngine)
    }

    @Test
    fun `LinuxNative delegates to injected engine`() {
        val mock = MockNativeEngine()
        mock.prctlResult = LinuxNative.SyscallResult(42, 0)

        LinuxNative.setEngine(mock)

        val result = LinuxNative.prctl(0)
        assertEquals(42L, result.returnValue)
    }

    @Test
    fun `fault injection works for errno`() {
        val mock = MockNativeEngine()
        mock.syscallResult = LinuxNative.SyscallResult(-1, 13) // EACCES

        LinuxNative.setEngine(mock)

        val result = LinuxNative.syscall(1L)
        assertEquals(-1L, result.returnValue)
        assertEquals(13, result.errno)
    }
}
