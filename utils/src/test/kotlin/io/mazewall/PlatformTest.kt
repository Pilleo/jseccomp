package io.mazewall

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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
}
