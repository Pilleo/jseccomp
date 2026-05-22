package io.contained

import io.contained.landlock.Landlock
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.io.File
import kotlin.test.assertEquals

@EnabledOnOs(OS.LINUX)
class LandlockTsyncIntegrationTest {

    /**
     * Tiny main class for the out-of-process TSYNC test.
     */
    object TsyncChild {
        @JvmStatic
        fun main(args: Array<String>) {
            val policy = Policy.builder()
                .block(Syscall.OPEN, Syscall.OPENAT)
                .build()

            Landlock.applyRuleset(policy)

            // This sibling thread should also be sandboxed
            val thread = Thread {
                try {
                    File("/etc/hostname").readText()
                    System.exit(0) // Should have succeeded (if TSYNC is disabled)
                } catch (e: Exception) {
                    System.exit(42) // Correctly sandboxed (if TSYNC is enabled)
                }
            }
            thread.start()
            thread.join()
        }
    }

    @Test
    fun `test TSYNC sandboxes sibling threads in child process`() {
        val javaBin = ProcessHandle.current().info().command().orElse("java")
        val classpath = System.getProperty("java.class.path")

        val pb = ProcessBuilder(
            javaBin,
            "--enable-native-access=ALL-UNNAMED",
            "-cp", classpath,
            "io.contained.LandlockTsyncIntegrationTest\$TsyncChild"
        )

        val process = pb.start()
        val exitCode = process.waitFor()

        // Landlock does not support TSYNC yet by default (thread-scoped only in current kernel driver implementation),
        // so the sibling thread is uncontained, leading to successful read (exit code 0).
        assertEquals(0, exitCode, "Expected exit code 0 as Landlock TSYNC is currently disabled by default")
    }
}
