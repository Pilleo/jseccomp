package io.mazewall.profiler.iterative

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.Syscall
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

    @Test
    fun `test iterative profiling rethrows unrelated exceptions`() {
        val basePolicy = Policy.PURE_COMPUTE_UNSAFE
        org.junit.jupiter.api.assertThrows<IllegalStateException> {
            IterativeProfiler.profile(basePolicy) {
                throw IllegalStateException("completely unrelated error")
            }
        }
    }

    @Test
    fun `test iterative profiling parses path from generic exception messages`() {
        val basePolicy = Policy.PURE_COMPUTE_UNSAFE
        var attempts = 0
        val targetPath = "/etc/custom_denied_path"
        val compiledPolicy = IterativeProfiler.profile(basePolicy) {
            attempts++
            if (attempts == 1) {
                throw java.io.IOException("$targetPath (Permission denied)")
            }
            // Second attempt succeeds
        }
        assertTrue(compiledPolicy.allowedFsReadPaths.contains(targetPath))
        assertTrue(!compiledPolicy.allowedFsWritePaths.contains(targetPath), "Should not grant write permission by default")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test iterative profiling of existing file read grants read and not write permission`() {
        val parentDir = File("/tmp/iterative_existing_read").absoluteFile
        parentDir.mkdirs()
        val existingFile = File(parentDir, "exists.txt")
        existingFile.writeText("some content")

        try {
            val basePolicy =
                Policy
                    .builder()
                    .unblock(
                        Syscall.OPEN,
                        Syscall.OPENAT,
                        Syscall.OPENAT2,
                    ).build()

            val compiledPolicy =
                IterativeProfiler.profile(basePolicy) {
                    existingFile.readText()
                }
            println("COMPILED POLICY READS: ${compiledPolicy.allowedFsReadPaths}")
            println("COMPILED POLICY WRITES: ${compiledPolicy.allowedFsWritePaths}")
            // We should have read permission, but absolutely NO write permission!
            assertTrue(compiledPolicy.allowedFsReadPaths.contains(existingFile.absolutePath))
            assertTrue(!compiledPolicy.allowedFsWritePaths.contains(existingFile.absolutePath), "Should not grant write permission for existing file read")
        } finally {
            parentDir.deleteRecursively()
        }
    }

    @Test
    fun `test iterative profiling retry limit exceeded`() {
        val basePolicy = Policy.PURE_COMPUTE_UNSAFE
        val compiledPolicy = IterativeProfiler.profile(basePolicy) {
            throw java.io.IOException("/etc/forever_denied (Permission denied)")
        }
        assertTrue(compiledPolicy.allowedFsReadPaths.contains("/etc/forever_denied"))
    }

    @Test
    fun `test iterative profiling ignores exception with null message`() {
        val basePolicy = Policy.PURE_COMPUTE_UNSAFE
        org.junit.jupiter.api.assertThrows<java.io.IOException> {
            IterativeProfiler.profile(basePolicy) {
                throw java.io.IOException(null as String?)
            }
        }
    }
}
