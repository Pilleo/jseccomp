package io.mazewall.landlock

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.Syscall
import io.mazewall.profiler.IterativeProfiler
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class IterativeProfilerTest {
    @Test
    fun `test iterative profiling converges on absolute paths`() {
        val target = File("/etc/hostname")

        // Use a base policy that allows OPEN syscalls but has NO allowed paths (denies all by default in Landlock)
        val basePolicy =
            Policy
                .builder()
                .unblock(Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2)
                .build()

        val compiledPolicy =
            IterativeProfiler.profile(basePolicy) {
                target.readText()
            }

        assertTrue(compiledPolicy.allowedFsReadPaths.contains("/etc/hostname"))
    }

    @Test
    fun `test iterative profiling converges on write paths`() {
        val target = File("build/tmp/iterative-write-test.txt").absoluteFile
        target.parentFile.mkdirs()
        target.delete()

        // Base policy allows write/open syscalls but has NO allowed paths
        val basePolicy =
            Policy
                .builder()
                .unblock(
                    Syscall.OPEN,
                    Syscall.OPENAT,
                    Syscall.OPENAT2,
                    Syscall.UNLINK,
                ).build()

        val compiledPolicy =
            IterativeProfiler.profile(basePolicy) {
                target.writeText("hello from iterative profiler write path")
            }

        assertTrue(
            compiledPolicy.allowedFsWritePaths.contains(target.absolutePath),
            "Should allow write access to path: ${target.absolutePath}",
        )

        // Clean up
        target.delete()
    }
}
