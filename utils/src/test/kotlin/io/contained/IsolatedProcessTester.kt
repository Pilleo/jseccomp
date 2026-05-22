package io.contained

import java.io.File
import kotlin.test.assertEquals

/**
 * Standardized utility for running integration tests in an isolated JVM process.
 * This is required for tests that install irreversible seccomp or Landlock filters,
 * preventing them from "poisoning" the shared Gradle test worker thread/process.
 */
object IsolatedProcessTester {

    /**
     * Spawns a new JVM process to run the specified [testClassName]'s [main] method with [mode].
     * Asserts that the process exits with code 0.
     */
    fun runIsolatedTest(testClassName: String, mode: String) {
        val javaHome = System.getProperty("java.home")
        val javaBin = javaHome + File.separator + "bin" + File.separator + "java"
        val classpath = System.getProperty("java.class.path")

        val builder = ProcessBuilder(
            javaBin, "-cp", classpath,
            "--enable-native-access=ALL-UNNAMED",
            testClassName,
            mode
        )
        builder.inheritIO()
        val process = builder.start()
        val exitCode = process.waitFor()
        assertEquals(0, exitCode, "Isolated test process ($testClassName $mode) failed with exit code $exitCode")
    }
}
