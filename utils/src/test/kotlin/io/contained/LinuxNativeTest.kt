package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class LinuxNativeTest {

    @Test
    fun testPrctlGetSeccomp() {
        val result = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
        // Usually returns 0 or 2, unless error
        assertTrue(result.returnValue >= 0)
    }

    @Test
    fun testStrerror() {
        val msg = LinuxNative.strerror(LinuxNative.EPERM)
        assertTrue(msg.isNotEmpty())
    }
}
