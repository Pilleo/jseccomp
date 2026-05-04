package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import java.util.concurrent.atomic.AtomicReference

class SeccompInstallerTest {

    @Test
    fun `test successful installation on a background thread`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val errorRef = AtomicReference<Throwable>(null)

        // We MUST run this in a separate thread so we don't permanently
        // nerf the Gradle test runner thread!
        val thread = Thread {
            try {
                // Use a policy that won't break basic thread cleanup 
                // NO_EXEC is safe because thread exit doesn't call execve
                SeccompInstaller.install(Policy.NO_EXEC)

                val r = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
                assertEquals(2, r.returnValue, "Seccomp should be active (mode 2)")
            } catch (t: Throwable) {
                errorRef.set(t)
            }
        }

        thread.start()
        thread.join()

        val err = errorRef.get()
        if (err != null) {
            throw err
        }
    }
}
