package io.mazewall

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Isolated
class PlatformTest {
    @Test
    fun `test Platform support`() {
        val osName = System.getProperty("os.name")
        if (osName.equals("Linux", ignoreCase = true)) {
            assertTrue(Platform.isSupported())
        }
    }

    @Test
    fun `test FallbackBehavior resolution`() {
        val current = Platform.configuredFallback()
        // Default is FAIL
        assertEquals(Platform.FallbackBehavior.FAIL, current)

        assertEquals(Platform.FallbackBehavior.FAIL, Platform.FallbackBehavior.valueOf("FAIL"))
        assertEquals(Platform.FallbackBehavior.WARN_AND_BYPASS, Platform.FallbackBehavior.valueOf("WARN_AND_BYPASS"))
    }

    @Test
    fun `isArchitectureSupported returns false for unsupported architecture`() {
        val originalArch = System.getProperty("os.arch")
        try {
            System.setProperty("os.arch", "mips")
            assertFalse(Platform.isArchitectureSupported())
        } finally {
            if (originalArch != null) {
                System.setProperty("os.arch", originalArch)
            } else {
                System.clearProperty("os.arch")
            }
        }
    }
}
