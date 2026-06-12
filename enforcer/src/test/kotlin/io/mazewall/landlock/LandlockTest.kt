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

class LandlockTest {
    fun testReadAllowed(
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

    fun testReadBlocked(dir: String) {
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

    fun testWriteAllowed(
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

    fun testWriteBlocked(
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

    fun testUnconstrained() {
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

    fun testStackingRecycled(
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

    fun testExecBlocked(dir: String) {
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

    fun testNonExistentFallback(file: String) {
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

    fun testResolveSymlink(
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

    fun testAutoClasspath(
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

    fun testNestedSymlinks(realFile: String) {
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

    fun testDotDotTraversal(allowed: String) {
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

    fun testCircularSymlinks(linkA: String) {
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

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockReadAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("secret")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testReadAllowed", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockReadBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_allowed")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testReadBlocked", tempDir.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockWriteAllowedPath`() {
        val tempDir = createTempDirectory("landlock_test_write_allowed")
        val testFile = tempDir.resolve("test.txt")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testWriteAllowed", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockWriteBlockedPath`() {
        val tempDir = createTempDirectory("landlock_test_read_only")
        val testFile = tempDir.resolve("test.txt")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testWriteBlocked", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockUnconstrainedThreadUnaffected`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testUnconstrained")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockRulesetNotStackedOnRecycledThread`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_stacking_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("data")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testStackingRecycled", tempDir.toString(), testFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockBlocksExecuteOutsideAllowedPaths`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_exec_test")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testExecBlocked", tempDir.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockAllowWriteToNonExistentFileUsesParentDir`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_nonexist_test")
        val newFile = tempDir.resolve("does_not_exist_yet.txt")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testNonExistentFallback", newFile.toString())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockResolvesSymlinkPathAutomatically`() {
        if (!Landlock.isSupported()) return
        val realDir = createTempDirectory("landlock_real_target")
        val realFile = realDir.resolve("secret.txt")
        realFile.writeText("real-content")
        val symlinkDir = createTempDirectory("landlock_symlink_holder")
        val symlink = symlinkDir.resolve("link_to_real")
        Files.createSymbolicLink(symlink, realDir)
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testResolveSymlink", realFile.toString(), symlink.toString())
        } finally {
            realDir.toFile().deleteRecursively()
            symlinkDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testContainmentWorksWithoutExplicitAllowJvmClasspath`() {
        if (!Landlock.isSupported()) return
        val tempDir = createTempDirectory("landlock_auto_cp_test")
        val testFile = tempDir.resolve("test.txt")
        testFile.writeText("auto-cp-ok")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testAutoClasspath", tempDir.toString(), testFile.toString())
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
    @EnabledIfLinuxAndSupported
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
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testNestedSymlinks", realFile.toString())
        } finally {
            realDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockDotDotTraversal`() {
        if (!Landlock.isSupported()) return
        val baseDir = createTempDirectory("landlock_base")
        val allowedSub = Files.createDirectory(baseDir.resolve("allowed"))
        val forbiddenSub = Files.createDirectory(baseDir.resolve("forbidden"))
        forbiddenSub.resolve("secret.txt").writeText("forbidden")
        allowedSub.resolve("ok.txt").writeText("ok")
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testDotDotTraversal", allowedSub.toString())
        } finally {
            baseDir.toFile().deleteRecursively()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `testLandlockCircularSymlinksFailGracefully`() {
        if (!Landlock.isSupported()) return
        val dir = createTempDirectory("landlock_circular")
        val linkA = dir.resolve("linkA")
        val linkB = dir.resolve("linkB")
        Files.createSymbolicLink(linkA, linkB)
        Files.createSymbolicLink(linkB, linkA)
        try {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testCircularSymlinks", linkA.toString())
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
