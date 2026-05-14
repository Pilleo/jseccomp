package io.contained

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ProcessContainmentTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `installOnProcess applies containment globally`() {
        if (!Platform.isSupported()) return

        // Spawn a thread to install process-wide containment
        val installerThread = Thread {
            ContainedExecutors.installOnProcess(Policy.NO_EXEC)
        }
        installerThread.start()
        installerThread.join()

        // Even though the filter was installed by a different thread,
        // it should apply to THIS thread because of TSYNC.
        val ex = assertFailsWith<Exception> {
            Runtime.getRuntime().exec(arrayOf("echo", "should-fail"))
        }

        assertTrue(ContainedExecutors.isContainmentViolation(ex), "Expected containment violation, got $ex")
    }
}
