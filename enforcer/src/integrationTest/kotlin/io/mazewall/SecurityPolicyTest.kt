package io.mazewall
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationDetector
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.assertTrue

/**
 * High-level behavioral contract tests for built-in [Policy] presets.
 *
 * These tests exercise the security guarantees at the Java API level, verifying that
 * [Policy] presets block the intended operations on live Linux kernel seccomp filters.
 *
 * For granular per-syscall BPF instruction tests, see:
 * - [io.mazewall.seccomp.AllowListTest]       — allow/block per individual syscall
 * - [io.mazewall.seccomp.MmapProtectionTest]  — PROT_EXEC blocking via BPF argument inspection
 * - [io.mazewall.seccomp.BpfHardeningTest]    — prctl, clone argument inspection sequences
 * - [io.mazewall.seccomp.ProcessContainmentTest] — process-wide and thread-inheritance tests
 */
@EnabledIfLinuxAndSupported
class SecurityPolicyTest {
    @Test
    fun `PURE_COMPUTE blocks filesystem modifications`() {
        val executor = Executors.newSingleThreadExecutor()
        val safe = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        val tempFile = Files.createTempFile("mazewall-test", ".txt").toFile()
        tempFile.writeText("original")

        try {
            // Test RENAME (Files.move throws IOException on failure)
            val renameFuture =
                safe.submit {
                    val newPath = tempFile.toPath().resolveSibling("renamed-${System.currentTimeMillis()}.txt")
                    Files.move(tempFile.toPath(), newPath)
                }
            val ex =
                org.junit.jupiter.api.assertThrows<ExecutionException> {
                    renameFuture.get()
                }
            assertTrue(ex.cause is ContainmentViolationException, "Expected violation for rename, got ${ex.cause}")

            // Test MKDIR (Files.createDirectory throws IOException on failure)
            val mkdirFuture =
                safe.submit {
                    val dir = tempFile.toPath().resolveSibling("new-dir-${System.currentTimeMillis()}")
                    Files.createDirectory(dir)
                }
            val ex2 =
                org.junit.jupiter.api.assertThrows<ExecutionException> {
                    mkdirFuture.get()
                }
            assertTrue(ex2.cause is ContainmentViolationException, "Expected violation for mkdir, got ${ex2.cause}")
        } finally {
            tempFile.delete()
            executor.shutdown()
        }
    }

    @Test
    fun `NO_NETWORK blocks outbound connect() at the kernel level`() {
        val executor = Executors.newSingleThreadExecutor()
        val safe = ContainedExecutors.wrap(executor, Policy.NO_NETWORK)

        try {
            val future =
                safe.submit {
                    // Connect to a local port — we don't care if it's listening,
                    // the kernel should block the connect() syscall before TCP handshake.
                    Socket().connect(InetSocketAddress("127.0.0.1", 65432), 500)
                }
            val ex = org.junit.jupiter.api
                .assertThrows<ExecutionException> { future.get() }
            assertTrue(
                ContainmentViolationDetector.isContainmentViolation(ex),
                "Expected a containment violation for connect(), got: ${ex.cause?.javaClass?.name}: ${ex.cause?.message}",
            )
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `NO_EXEC blocks process spawning via ProcessBuilder`() {
        val executor = Executors.newSingleThreadExecutor()
        val safe = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val future =
                safe.submit {
                    // execve() is blocked by NO_EXEC — ProcessBuilder.start() should fail with EPERM.
                    ProcessBuilder("echo", "should-be-blocked").start()
                }
            val ex = org.junit.jupiter.api
                .assertThrows<ExecutionException> { future.get() }
            assertTrue(
                ContainmentViolationDetector.isContainmentViolation(ex),
                "Expected a containment violation for execve(), got: ${ex.cause?.javaClass?.name}: ${ex.cause?.message}",
            )
        } finally {
            executor.shutdown()
        }
    }
}
