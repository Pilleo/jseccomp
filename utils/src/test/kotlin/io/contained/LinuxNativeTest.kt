package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

import kotlin.test.assertFailsWith

class LinuxNativeTest {

    @Test
    fun testPrctlGetSeccomp() {
        if (!Platform.isSupported()) return

        val result = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
        // Usually returns 0 or 2, unless error
        assertTrue(result.returnValue >= 0)
    }

    @Test
    fun testStrerror() {
        val msg = LinuxNative.strerror(LinuxNative.EPERM)
        assertTrue(msg.isNotEmpty())
    }

    @Test
    fun testSockFilterBoundsValidation() {
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, 256.toShort(), 0.toShort(), 0)
        }
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, (-1).toShort(), 0.toShort(), 0)
        }
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, 0.toShort(), 256.toShort(), 0)
        }
        // Valid bounds should not throw
        SockFilter(0, 0.toShort(), 255.toShort(), 0)
    }
}
