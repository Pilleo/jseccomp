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
            org.junit.jupiter.api.Assumptions
                .assumeTrue(Platform.isSupported())
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

    @Test
    fun `test Platform diagnostics`() {
        val diagnostics = Platform.diagnose()
        assertTrue(diagnostics.osName.isNotEmpty())
        assertTrue(diagnostics.osVersion.isNotEmpty())
        assertTrue(diagnostics.osArch.isNotEmpty())

        val osName = System.getProperty("os.name")
        if (osName.equals("Linux", ignoreCase = true)) {
            assertEquals(true, diagnostics.isLinux)
        } else {
            assertEquals(false, diagnostics.isLinux)
        }

        // Run toString() to cover Diagnostics formatting code paths
        val output = diagnostics.toString()
        assertTrue(output.contains("Mazewall Platform Diagnostics"))
        assertTrue(output.contains("OS Name:"))
        assertTrue(output.contains("Architecture:"))
        assertTrue(output.contains("no_new_privs Enabled:"))
        assertTrue(output.contains("Container Detected:"))
    }
}
