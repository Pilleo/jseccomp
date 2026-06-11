package io.mazewall.landlock

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.IsolatedProcessTester
import io.mazewall.LinuxNative
import io.mazewall.MockNativeEngine
import io.mazewall.Policy
import io.mazewall.RealNativeEngine
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
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Helper app for isolated execution of [LandlockTest] methods.
 */
object LandlockIsolatedApp {
    @JvmStatic
    @Suppress("CyclomaticComplexMethod")
    fun main(args: Array<String>) {
        val mode = args.firstOrNull() ?: return
        try {
            when (mode) {
                "read-allowed" -> testReadAllowed(args[1], args[2])
                "read-blocked" -> testReadBlocked(args[1])
                "write-allowed" -> testWriteAllowed(args[1], args[2])
                "write-blocked" -> testWriteBlocked(args[1], args[2])
                "unconstrained" -> testUnconstrained()
                "stacking-recycled" -> testStackingRecycled(args[1], args[2])
                "exec-blocked" -> testExecBlocked(args[1])
                "nonexistent-fallback" -> testNonExistentFallback(args[2])
                "resolve-symlink" -> testResolveSymlink(args[2], args[3])
                "auto-classpath" -> testAutoClasspath(args[1], args[2])
                "nested-symlinks" -> testNestedSymlinks(args[1])
                "dot-dot-traversal" -> testDotDotTraversal(args[1])
                "circular-symlinks" -> testCircularSymlinks(args[1])
                else -> System.exit(1)
            }
            System.exit(0)
        } catch (
            @Suppress("TooGenericExceptionCaught") e: Throwable,
        ) {
            System.err.println("Isolated test failure in mode $mode: ${e.message}")
            System.exit(2)
        }
    }

    private fun testReadAllowed(
        dir: String,
        file: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        val res = safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(file)) }).get()
        if (res != "secret") throw IllegalStateException("Wrong content: $res")
        executor.shutdown()
    }

    private fun testReadBlocked(dir: String) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        try {
            safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of("/etc/passwd")) }).get()
            throw IllegalStateException("Should have failed")
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause !is AccessDeniedException && cause !is ContainmentViolationException) throw e
        } finally {
            executor.shutdown()
        }
    }

    private fun testWriteAllowed(
        dir: String,
        file: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsWrite(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        safeExecutor.submit { Files.writeString(Path.of(file), "hello") }.get()
        if (Files.readString(Path.of(file)) != "hello") throw IllegalStateException("Write failed")
        executor.shutdown()
    }

    private fun testWriteBlocked(
        dir: String,
        file: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        try {
            safeExecutor.submit { Files.writeString(Path.of(file), "hello") }.get()
            throw IllegalStateException("Should have failed")
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause !is AccessDeniedException && cause !is ContainmentViolationException) throw e
        } finally {
            executor.shutdown()
        }
    }

    private fun testUnconstrained() {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        try {
            safeExecutor.submit { Files.readString(Path.of("/etc/passwd")) }.get()
            throw IllegalStateException("Should have failed")
        } catch (
            @Suppress("SwallowedException") e: ExecutionException,
        ) {
            // Expected
        }
        Files.readString(Path.of("/etc/passwd")) // Main thread should succeed
        executor.shutdown()
    }

    private fun testStackingRecycled(
        dir: String,
        file: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        for (i in 1..20) {
            val res = safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(file)) }).get()
            if (res != "data") throw IllegalStateException("Task $i failed")
        }
        executor.shutdown()
    }

    private fun testExecBlocked(dir: String) {
        val policy = Policy
            .builder()
            .allowJvmClasspath()
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        try {
            safeExecutor.submit(java.util.concurrent.Callable { ProcessBuilder("/bin/echo", "fail").start() }).get()
            throw IllegalStateException("Should have failed")
        } catch (
            @Suppress("SwallowedException") e: ExecutionException,
        ) {
            // Expected
        } finally {
            executor.shutdown()
        }
    }

    private fun testNonExistentFallback(file: String) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsWrite(file)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        safeExecutor.submit { Files.writeString(Path.of(file), "created!") }.get()
        if (Files.readString(Path.of(file)) != "created!") throw IllegalStateException("Write failed")
        executor.shutdown()
    }

    private fun testResolveSymlink(
        realFile: String,
        symlink: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(symlink)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        val res = safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(realFile)) }).get()
        if (res != "real-content") throw IllegalStateException("Wrong content: $res")
        executor.shutdown()
    }

    private fun testAutoClasspath(
        dir: String,
        file: String,
    ) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowFsRead(dir)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        val res = safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(file)) }).get()
        if (res != "auto-cp-ok") throw IllegalStateException("Wrong content: $res")
        executor.shutdown()
    }

    private fun testNestedSymlinks(realFile: String) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(realFile)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        val res = safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(realFile)) }).get()
        if (res != "nested-secret") throw IllegalStateException("Wrong content: $res")
        executor.shutdown()
    }

    private fun testDotDotTraversal(allowed: String) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(allowed)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        try {
            safeExecutor.submit(java.util.concurrent.Callable { Files.readString(Path.of(allowed).resolve("../forbidden/secret.txt")) }).get()
            throw IllegalStateException("Should have failed")
        } catch (
            @Suppress("SwallowedException") e: ExecutionException,
        ) {
            // Expected
        } finally {
            executor.shutdown()
        }
    }

    private fun testCircularSymlinks(linkA: String) {
        val policy = Policy
            .builder()
            .base(Policy.NO_EXEC)
            .allowJvmClasspath()
            .allowFsRead(linkA)
            .build()
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, policy)
        val res = safeExecutor
            .submit(
            java.util.concurrent.Callable {
            try {
                Files.readString(Path.of(linkA))
                "success"
            } catch (
                @Suppress("SwallowedException") _: java.io.IOException,
            ) {
                "eloop"
            }
        },
        ).get()
        if (res != "eloop") throw IllegalStateException("Expected eloop, got $res")
        executor.shutdown()
    }
}

@EnabledIfLinuxAndSupported
class LandlockTest {
    @Test
    fun `testLandlockReadAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("secret")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "read-allowed", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockReadBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "read-blocked", tempDir.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockWriteAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_write_allowed")
        val testFile = tempDir.resolve("test.txt")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "write-allowed", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockWriteBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_read_only")
        val testFile = tempDir.resolve("test.txt")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "write-blocked", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockUnconstrainedThreadUnaffected`() {
        IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "unconstrained")
    }

    @Test
    fun `testLandlockRulesetNotStackedOnRecycledThread`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_stacking_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("data")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "stacking-recycled", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockBlocksExecuteOutsideAllowedPaths`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_exec_test")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "exec-blocked", tempDir.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockAllowWriteToNonExistentFileUsesParentDir`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_nonexist_test")
        val newFile = tempDir.resolve("does_not_exist_yet.txt")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "nonexistent-fallback", tempDir.toString(), newFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockResolvesSymlinkPathAutomatically`() {
        if (!Landlock.isSupported()) return
        val realDir = createTempDirectory("landlock_real_target")
        val realFile = realDir.resolve("secret.txt")
        realFile.writeText("real-content")
        val symlinkDir = createTempDirectory("landlock_symlink_holder")
        val symlink = symlinkDir.resolve("link_to_real")
        Files.createSymbolicLink(symlink, realDir)
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "resolve-symlink", realDir.toString(), realFile.toString(), symlink.toString())
        } finally {
            realDir.toFile().deleteRecursively()
            symlinkDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testContainmentWorksWithoutExplicitAllowJvmClasspath`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_auto_cp_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("auto-cp-ok")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "auto-classpath", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockAbiGapFailClosed_Rename`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 2) return
        val policy = Policy.builder().unblock(Syscall.RENAME).build()
        val ex = assertFailsWith<UnsupportedOperationException> { Landlock.applyRuleset(policy) }
        assertTrue(ex.message!!.contains("Policy allows rename/link syscalls, but this kernel"))
    }

    @Test
    fun `testLandlockAbiGapFailClosed_Truncate`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 3) return
        val policy = Policy.builder().unblock(Syscall.TRUNCATE).build()
        val ex = assertFailsWith<UnsupportedOperationException> { Landlock.applyRuleset(policy) }
        assertTrue(ex.message!!.contains("Policy allows truncate syscalls, but this kernel"))
    }

    @Test
    fun `testLandlockAbiGapFailClosed_Ioctl`() {
        if (!Landlock.isSupported()) return
        val abi = Landlock.getAbiVersion()
        if (abi >= 5) return
        val policy = Policy.builder().unblock(Syscall.IOCTL).build()
        val ex = assertFailsWith<UnsupportedOperationException> { Landlock.applyRuleset(policy) }
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
        Files.createSymbolicLink(link1, realDir)
        Files.createSymbolicLink(link2, link1)
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "nested-symlinks", realFile.toString(), link1.toString(), link2.toString(), realDir.toString())
        } finally {
            realDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockDotDotTraversal`() {
        if (!Landlock.isSupported()) return
        val baseDir = createTempDirectory("landlock_base")
        val allowedSub = Files.createDirectory(baseDir.resolve("allowed"))
        val forbiddenSub = Files.createDirectory(baseDir.resolve("forbidden"))
        forbiddenSub.resolve("secret.txt").writeText("forbidden")
        allowedSub.resolve("ok.txt").writeText("ok")
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "dot-dot-traversal", allowedSub.toString(), forbiddenSub.toString(), "", baseDir.toString())
        } finally {
            baseDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockCircularSymlinksFailGracefully`() {
        if (!Landlock.isSupported()) return
        val dir = createTempDirectory("landlock_circular")
        val linkA = dir.resolve("linkA")
        val linkB = dir.resolve("linkB")
        Files.createSymbolicLink(linkA, linkB)
        Files.createSymbolicLink(linkB, linkA)
        try {
            IsolatedProcessTester.runIsolatedTest(LandlockIsolatedApp::class.java.name, "circular-symlinks", linkA.toString(), linkB.toString(), dir.toString())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `testLandlockSessionStateTransitions`() {
        val mockEngine = object : MockNativeEngine() {
            override fun syscall(
                nr: Long,
                a1: Any?,
                a2: Any?,
                a3: Any?,
                a4: Any?,
                a5: Any?,
                a6: Any?,
            ): LinuxNative.SyscallResult {
                return if (nr == io.mazewall.ffi.NativeConstants.LANDLOCK_CREATE_RULESET_NR &&
                    a3 == io.mazewall.ffi.NativeConstants.LANDLOCK_CREATE_RULESET_VERSION
                ) {
                    LinuxNative.SyscallResult(5, 0) // ABI version 5
                } else if (nr == io.mazewall.ffi.NativeConstants.LANDLOCK_CREATE_RULESET_NR) {
                    LinuxNative.SyscallResult(42, 0) // Fake ruleset FD
                } else {
                    LinuxNative.SyscallResult(0, 0) // Success for other syscalls
                }
            }
        }
        LinuxNative.setEngine(mockEngine)
        try {
            val session = LandlockSession(Policy.PURE_COMPUTE_UNSAFE)
            assertTrue(session.state is LandlockState.Uninitialized)
            session.applyRuleset()
            assertTrue(session.state is LandlockState.Applied)
        } finally {
            LinuxNative.setEngine(RealNativeEngine)
        }
    }

    @Test
    fun `testLandlockSessionFailedState`() {
        val mockEngine = object : MockNativeEngine() {
            override fun syscall(
                nr: Long,
                a1: Any?,
                a2: Any?,
                a3: Any?,
                a4: Any?,
                a5: Any?,
                a6: Any?,
            ): LinuxNative.SyscallResult {
                return if (nr == io.mazewall.ffi.NativeConstants.LANDLOCK_CREATE_RULESET_NR &&
                    a3 == io.mazewall.ffi.NativeConstants.LANDLOCK_CREATE_RULESET_VERSION
                ) {
                    LinuxNative.SyscallResult(5, 0) // ABI version 5
                } else {
                    LinuxNative.SyscallResult(-1, 22) // EINVAL for ruleset creation
                }
            }
        }
        LinuxNative.setEngine(mockEngine)
        try {
            val session = LandlockSession(Policy.PURE_COMPUTE_UNSAFE)
            assertFailsWith<IllegalStateException> {
                session.applyRuleset()
            }
            assertTrue(session.state is LandlockState.Failed)
        } finally {
            LinuxNative.setEngine(RealNativeEngine)
        }
    }

    @Test
    fun `testLandlockStateDataClassCoverage`() {
        val s1 = LandlockState.ConfiguringRuleset(10, 5)
        val s2 = LandlockState.ConfiguringRuleset(10, 5)
        val s3 = LandlockState.ConfiguringRuleset(11, 5)
        assertEquals(s1, s2)
        assertNotEquals(s1, s3)
        assertEquals(s1.hashCode(), s2.hashCode())
        assertNotNull(s1.toString())
        assertEquals(10, s1.rulesetFd)
        assertEquals(5, s1.abi)
        val copied = s1.copy(rulesetFd = 12)
        assertEquals(12, copied.rulesetFd)

        val q1 = LandlockState.QueryingAbi(3)
        val q2 = LandlockState.QueryingAbi(3)
        assertEquals(q1, q2)
        assertEquals(q1.hashCode(), q2.hashCode())
        assertNotNull(q1.toString())
        val qCopied = q1.copy(abi = 4)
        assertEquals(4, qCopied.abi)

        val c1 = LandlockState.CreatingRuleset(3)
        val c2 = LandlockState.CreatingRuleset(3)
        assertEquals(c1, c2)
        assertEquals(c1.hashCode(), c2.hashCode())
        assertNotNull(c1.toString())
        val cCopied = c1.copy(abi = 4)
        assertEquals(4, cCopied.abi)

        val e1 = LandlockState.Enforcing(10)
        val e2 = LandlockState.Enforcing(10)
        assertEquals(e1, e2)
        assertEquals(e1.hashCode(), e2.hashCode())
        assertNotNull(e1.toString())
        val eCopied = e1.copy(rulesetFd = 11)
        assertEquals(11, eCopied.rulesetFd)

        val err = RuntimeException("test")
        val f1 = LandlockState.Failed(err)
        val f2 = LandlockState.Failed(err)
        assertEquals(f1, f2)
        assertEquals(f1.hashCode(), f2.hashCode())
        assertNotNull(f1.toString())
        val fCopied = f1.copy(error = err)
        assertEquals(err, fCopied.error)
    }
}
