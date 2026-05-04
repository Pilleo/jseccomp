package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ArchTest {

    @Test
    fun testCurrentPlatformIsDetected() {
        val osArch = System.getProperty("os.arch")
        if (osArch in listOf("amd64", "x86_64", "aarch64", "arm64")) {
            val arch = Arch.current()
            assertNotNull(arch)
            assertTrue(arch.name == "amd64" || arch.name == "aarch64")
        }
    }
}
