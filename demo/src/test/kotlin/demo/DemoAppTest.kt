package demo

import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.io.File
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DemoAppTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `main with no arguments runs all demos and succeeds`() {
        if (!io.mazewall.Platform.isSupported()) return

        val unsafeMarker = File("/tmp/pwned_unsafe")
        val safeMarker = File("/tmp/pwned_safe")
        unsafeMarker.delete()
        safeMarker.delete()

        // Running main() without arguments should trigger the "all" mode
        main(emptyArray())

        assertTrue(unsafeMarker.exists(), "Unsafe demo should have created the marker")
        assertFalse(safeMarker.exists(), "Safe demo should NOT have created the marker")

        // Cleanup
        unsafeMarker.delete()
        safeMarker.delete()
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `SafeRunner handles malformed payload`() {
        // This won't trigger the JNDI logic, so it's a simple success path
        SafeRunner.run("not-jndi")
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `SafeRunner blocks execution in JNDI`() {
        assertFailsWith<ContainmentViolationException> {
            SafeRunner.run("\${jndi:ldap://test?cmd=ls}")
        }
    }
}
