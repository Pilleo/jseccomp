package io.mazewall.landlock

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.nio.file.AccessDeniedException
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class LandlockTest {
    @Test
    fun `testLandlockReadAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("secret")

        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsRead(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    Files.readString(testFile)
                },
            )

        assertEquals("secret", future.get())

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockReadBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")

        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsRead(tempDir.toString()) // Allow temp, but we will try to read /etc/passwd
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    Files.readString(Path.of("/etc/passwd"))
                },
            )

        val ex =
            assertFailsWith<ExecutionException> {
                future.get()
            }

        assertTrue(
            ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException,
            "Expected AccessDeniedException, got ${ex.cause}",
        )

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockWriteAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_write_allowed")
        val testFile = tempDir.resolve("test.txt")

        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsWrite(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit {
                testFile.writeText("hello")
            }

        future.get() // Should not throw
        assertEquals("hello", Files.readString(testFile))

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockWriteBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_read_only")
        val testFile = tempDir.resolve("test.txt")

        // Only allow read, not write
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsRead(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit {
                testFile.writeText("hello")
            }

        val ex =
            assertFailsWith<ExecutionException> {
                future.get()
            }

        assertTrue(ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException)

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockUnconstrainedThreadUnaffected`() {
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // The worker thread is blocked from reading /etc/passwd (and everything else)
        val future =
            safeExecutor.submit {
                Files.readString(Path.of("/etc/passwd"))
            }

        val ex =
            assertFailsWith<ExecutionException> {
                future.get()
            }
        assertTrue(ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException)

        // But the main thread (unconstrained) can still read it!
        val content = Files.readString(Path.of("/etc/passwd"))
        assertTrue(content.isNotEmpty())

        executor.shutdown()
    }

    // ── Issue #1: Ruleset stacking ──────────────────────────────────────

    @Test
    fun `testLandlockRulesetNotStackedOnRecycledThread`() {
        if (!Landlock.isSupported()) return

        val tempDir = createTempDirectory("landlock_stacking_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("data")

        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsRead(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // Submit 20 tasks to the same single thread.
        // Without dedup, task ~17 would crash with E2BIG.
        for (i in 1..20) {
            val future =
                safeExecutor.submit(
                    java.util.concurrent.Callable {
                        Files.readString(testFile)
                    },
                )
            assertEquals("data", future.get(), "Task $i failed")
        }

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    // ── Issue #2: Execute bypass ────────────────────────────────────────

    @Test
    fun `testLandlockBlocksExecuteOutsideAllowedPaths`() {
        if (!Landlock.isSupported()) return

        val tempDir = createTempDirectory("landlock_exec_test")

        // Landlock-only restrictions (no seccomp EXECVE block), but FS_EXECUTE
        // should be in the handled mask, so /bin/echo is blocked.
        val policy =
            Policy
                .builder()
                .allowJvmClasspath()
                .allowFsRead(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    ProcessBuilder("/bin/echo", "escaped").start()
                },
            )

        val ex = assertFailsWith<ExecutionException> { future.get() }
        // Should be blocked by Landlock FS_EXECUTE restriction
        assertTrue(
            ex.cause is ContainmentViolationException || ex.cause is java.io.IOException,
            "Expected execution to be blocked, got ${ex.cause}",
        )

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    // ── Issue #3: Non-existent path fallback ────────────────────────────

    @Test
    fun `testLandlockAllowWriteToNonExistentFileUsesParentDir`() {
        if (!Landlock.isSupported()) return

        val tempDir = createTempDirectory("landlock_nonexist_test")
        val newFile = tempDir.resolve("does_not_exist_yet.txt")

        // User allows the specific file path (which doesn't exist yet)
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsWrite(newFile.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit {
                newFile.writeText("created!")
            }

        future.get() // Should succeed because addRule falls back to parent dir
        assertEquals("created!", Files.readString(newFile))

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    // ── Issue #4: Symlink rejection ─────────────────────────────────────

    @Test
    fun `testLandlockResolvesSymlinkPathAutomatically`() {
        if (!Landlock.isSupported()) return

        val realDir = createTempDirectory("landlock_real_target")
        val realFile = realDir.resolve("secret.txt")
        realFile.writeText("real-content")

        val symlinkDir = createTempDirectory("landlock_symlink_holder")
        val symlink = symlinkDir.resolve("link_to_real")
        Files.createSymbolicLink(symlink, realDir)

        // Allow the symlink path — with auto-canonicalization inside mazewall,
        // this symlink path is automatically resolved to the target realDir.
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowJvmClasspath()
                .allowFsRead(symlink.toString()) // This is a symlink
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // Reading the real file should now succeed because the symlink was automatically resolved!
        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    Files.readString(realFile)
                },
            )

        assertEquals("real-content", future.get())

        executor.shutdown()
        realDir.toFile().deleteRecursively()
        symlinkDir.toFile().deleteRecursively()
    }

    // ── Issue #5: Auto-classpath allow ──────────────────────────────────

    @Test
    fun `testContainmentWorksWithoutExplicitAllowJvmClasspath`() {
        if (!Landlock.isSupported()) return

        val tempDir = createTempDirectory("landlock_auto_cp_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("auto-cp-ok")

        // Intentionally NOT calling allowJvmClasspath() — Landlock should auto-add it
        val policy =
            Policy
                .builder()
                .base(Policy.NO_EXEC)
                .allowFsRead(tempDir.toString())
                .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future =
            safeExecutor.submit(
                java.util.concurrent.Callable {
                    Files.readString(testFile)
                },
            )

        assertEquals("auto-cp-ok", future.get())

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    // ── Issue #6: Older Kernel Silent Bypasses ──────────────────────────

    @Test
    fun `testLandlockAbiGapFailClosed_Rename`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 2) return // Kernel supports it, won't throw

        val policy = Policy.builder().unblock(Syscall.RENAME).build()
        val ex =
            assertFailsWith<UnsupportedOperationException> {
                Landlock.applyRuleset(policy)
            }
        assertTrue(ex.message!!.contains("Policy allows rename/link syscalls, but this kernel"))
    }

    @Test
    fun `testLandlockAbiGapFailClosed_Truncate`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 3) return // Kernel supports it, won't throw

        val policy = Policy.builder().unblock(Syscall.TRUNCATE).build()
        val ex =
            assertFailsWith<UnsupportedOperationException> {
                Landlock.applyRuleset(policy)
            }
        assertTrue(ex.message!!.contains("Policy allows truncate syscalls, but this kernel"))
    }

    @Test
    fun `testLandlockAbiGapFailClosed_Ioctl`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 5) return // Kernel supports it, won't throw

        val policy = Policy.builder().unblock(Syscall.IOCTL).build()
        val ex =
            assertFailsWith<UnsupportedOperationException> {
                Landlock.applyRuleset(policy)
            }
        assertTrue(ex.message!!.contains("Policy allows ioctl, but this kernel"))
    }

    @Test
    fun `testLandlockNestedSymlinks`() {
        if (!Landlock.isSupported()) return

        val realDir = createTempDirectory("landlock_real_target")
        val realFile = realDir.resolve("secret.txt")
        realFile.writeText("nested-secret")

        val link1 = createTempDirectory("landlock_link1").resolve("l1")
        val link2 = createTempDirectory("landlock_link2").resolve("l2")

        // link2 -> link1 -> realDir
        Files.createSymbolicLink(link1, realDir)
        Files.createSymbolicLink(link2, link1)

        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(link2.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(
            java.util.concurrent.Callable {
            Files.readString(realFile)
        },
        )

        assertEquals("nested-secret", future.get())
        executor.shutdown()
    }

    @Test
    fun `testLandlockDotDotTraversal`() {
        if (!Landlock.isSupported()) return

        val baseDir = createTempDirectory("landlock_base")
        val allowedSub = Files.createDirectory(baseDir.resolve("allowed"))
        val forbiddenSub = Files.createDirectory(baseDir.resolve("forbidden"))

        forbiddenSub.resolve("secret.txt").writeText("forbidden")
        allowedSub.resolve("ok.txt").writeText("ok")

        // Policy allows only the 'allowed' subdirectory
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(allowedSub.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // Try to escape via ..
        val future = safeExecutor.submit(
            java.util.concurrent.Callable {
            val escapePath = allowedSub.resolve("../forbidden/secret.txt")
            Files.readString(escapePath)
        },
        )

        val ex = assertFailsWith<ExecutionException> { future.get() }
        assertTrue(ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException)

        executor.shutdown()
    }

    @Test
    fun `testLandlockCircularSymlinksFailGracefully`() {
        if (!Landlock.isSupported()) return

        val dir = createTempDirectory("landlock_circular")
        val linkA = dir.resolve("linkA")
        val linkB = dir.resolve("linkB")

        Files.createSymbolicLink(linkA, linkB)
        Files.createSymbolicLink(linkB, linkA)

        // This shouldn't crash the policy builder or application
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(linkA.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(
            java.util.concurrent.Callable {
            // Reading it should obviously fail with too many levels of symbolic links (ELOOP)
            try {
                Files.readString(linkA)
                "success"
            } catch (_: java.io.IOException) {
                "eloop"
            }
        },
        )

        assertEquals("eloop", future.get())
        executor.shutdown()
    }
}
