package io.contained.landlock

import io.contained.Platform
import io.contained.Policy
import io.contained.EnabledIfLinuxAndSupported
import io.contained.enforcer.ContainedExecutors
import io.contained.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals
import java.nio.file.AccessDeniedException

@EnabledIfLinuxAndSupported
class LandlockTest {

    @Test
    fun `testLandlockReadAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("secret")

        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(java.util.concurrent.Callable {
            Files.readString(testFile)
        })

        assertEquals("secret", future.get())

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockReadBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")

        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(tempDir.toString()) // Allow temp, but we will try to read /etc/passwd
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(java.util.concurrent.Callable {
            Files.readString(Path.of("/etc/passwd"))
        })

        val ex = assertFailsWith<ExecutionException> {
            future.get()
        }

        assertTrue(
            ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException,
            "Expected AccessDeniedException, got ${ex.cause}"
        )

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockWriteAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_write_allowed")
        val testFile = tempDir.resolve("test.txt")

        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsWrite(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit {
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
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit {
            testFile.writeText("hello")
        }

        val ex = assertFailsWith<ExecutionException> {
            future.get()
        }

        assertTrue(ex.cause is AccessDeniedException || ex.cause is ContainmentViolationException)

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `testLandlockUnconstrainedThreadUnaffected`() {
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // The worker thread is blocked from reading /etc/passwd (and everything else)
        val future = safeExecutor.submit {
            Files.readString(Path.of("/etc/passwd"))
        }

        val ex = assertFailsWith<ExecutionException> {
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

        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // Submit 20 tasks to the same single thread.
        // Without dedup, task ~17 would crash with E2BIG.
        for (i in 1..20) {
            val future = safeExecutor.submit(java.util.concurrent.Callable {
                Files.readString(testFile)
            })
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
        val policy = Policy.builder()
            .allowJvmClasspath()
            .allowFsRead(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(java.util.concurrent.Callable {
            ProcessBuilder("/bin/echo", "escaped").start()
        })

        val ex = assertFailsWith<ExecutionException> { future.get() }
        // Should be blocked by Landlock FS_EXECUTE restriction
        assertTrue(
            ex.cause is ContainmentViolationException || ex.cause is java.io.IOException,
            "Expected execution to be blocked, got ${ex.cause}"
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
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsWrite(newFile.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit {
            newFile.writeText("created!")
        }

        future.get() // Should succeed because addRule falls back to parent dir
        assertEquals("created!", Files.readString(newFile))

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }

    // ── Issue #4: Symlink rejection ─────────────────────────────────────

    @Test
    fun `testLandlockRejectsSymlinkPathWithONoFollow`() {
        if (!Landlock.isSupported()) return

        val realDir = createTempDirectory("landlock_real_target")
        val realFile = realDir.resolve("secret.txt")
        realFile.writeText("real-content")

        val symlinkDir = createTempDirectory("landlock_symlink_holder")
        val symlink = symlinkDir.resolve("link_to_real")
        Files.createSymbolicLink(symlink, realDir)

        // Allow the symlink path — with O_NOFOLLOW, the rule should be rejected
        // (symlink cannot be opened with O_PATH | O_NOFOLLOW for landlock),
        // and the real dir should remain blocked.
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(symlink.toString()) // This is a symlink
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        // Reading the real file should be blocked because the symlink rule was rejected
        val future = safeExecutor.submit(java.util.concurrent.Callable {
            Files.readString(realFile)
        })

        val ex = assertFailsWith<ExecutionException> { future.get() }
        assertTrue(
            ex.cause is ContainmentViolationException || ex.cause is AccessDeniedException,
            "Expected access denied, got ${ex.cause}"
        )

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
        val policy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowFsRead(tempDir.toString())
            .build()

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)

        val future = safeExecutor.submit(java.util.concurrent.Callable {
            Files.readString(testFile)
        })

        assertEquals("auto-cp-ok", future.get())

        executor.shutdown()
        tempDir.toFile().deleteRecursively()
    }
}
