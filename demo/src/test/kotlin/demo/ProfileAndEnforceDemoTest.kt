package demo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS

class ProfileAndEnforceDemoTest {
    @Test
    @EnabledOnOs(OS.LINUX)
    fun `test profile and enforce demo runs successfully`() {
        if (!io.mazewall.Platform.isSupported()) return

        // Verify that the entire end-to-end profile and enforce demo completes successfully
        runProfileAndEnforce()
    }
}
