package io.mazewall

import java.io.File

/**
 * Standardized utility for running integration tests in an isolated JVM process.
 * This is required for tests that install irreversible seccomp or Landlock filters,
 * preventing them from "poisoning" the shared Gradle test worker thread/process.
 */
object IsolatedProcessTester {
    /**
     * Spawns a new JVM process to run the specified [testClassName]'s [main] method with [args].
     * Asserts that the process exits with code 0.
     */
    fun runIsolatedTest(
        testClassName: String,
        vararg args: String,
    ) {
        val javaHome = System.getProperty("java.home")
        val javaBin = javaHome + File.separator + "bin" + File.separator + "java"
        val classpath = System.getProperty("java.class.path")

        val command = mutableListOf(
            javaBin,
            "-Xint",
            "-cp",
            classpath,
            "--enable-native-access=ALL-UNNAMED",
            testClassName,
        )
        command.addAll(args)

        val builder = ProcessBuilder(command)
        // Redirect error stream to stdout so we can capture everything if needed,
        // or just inherit it to see it in the logs.
        builder.inheritIO()

        val process = builder.start()
        val exitCode = process.waitFor()

        if (exitCode != 0) {
            val cmdString = command.joinToString(" ")
            throw IllegalStateException("Isolated test process failed with exit code $exitCode.\nCommand: $cmdString")
        }
    }
}
