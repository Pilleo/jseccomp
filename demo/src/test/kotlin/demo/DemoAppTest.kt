package demo

import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DemoAppTest {
    @Test
    @EnabledIfLinuxAndSupported
    fun `main with no arguments runs all demos and succeeds`() {
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
    @EnabledIfLinuxAndSupported
    fun `SafeRunner handles malformed payload`() {
        // This won't trigger the JNDI logic, so it's a simple success path
        SafeRunner.run("not-jndi")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `SafeRunner blocks execution in JNDI`() {
        assertFailsWith<ContainmentViolationException> {
            SafeRunner.run($$"${jndi:ldap://test?cmd=ls}")
        }
    }
}
