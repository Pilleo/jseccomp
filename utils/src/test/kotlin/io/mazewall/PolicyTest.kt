package io.mazewall

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class PolicyTest {

    @Test
    fun `syscallNumbers returns sorted array`() {
        val policy = Policy.builder()
            .block(Syscall.SENDTO, Syscall.ACCEPT, Syscall.CONNECT, Syscall.BIND)
            .build()

        val restricted = policy.syscallNumbers(Arch.current())
        val sorted = restricted.sortedArray()

        assertTrue(restricted.contentEquals(sorted), "syscallNumbers should return a sorted array")
    }

    @Test
    fun `NO_NETWORK policy includes all network server syscalls`() {
        val policy = Policy.NO_NETWORK
        val arch = Arch.current()
        val restricted = policy.syscallNumbers(arch).toList()

        assertTrue(restricted.contains(arch.bind), "NO_NETWORK should block bind")
        assertTrue(restricted.contains(arch.listen), "NO_NETWORK should block listen")
        assertTrue(restricted.contains(arch.accept), "NO_NETWORK should block accept")
        assertTrue(restricted.contains(arch.accept4), "NO_NETWORK should block accept4")
        assertTrue(restricted.contains(arch.connect), "NO_NETWORK should block connect")
    }

    @Test
    fun `builder methods correctly set flags`() {
        val policy = Policy.builder()
            .allowMmapExec()
            .allowNonThreadClone()
            .allowUnsafePrctl()
            .allowFsRead("/tmp/r")
            .allowFsWrite("/tmp/w")
            .build()

        assertTrue(policy.allowMmapExec, "allowMmapExec should be true")
        assertTrue(policy.allowNonThreadClone, "allowNonThreadClone should be true")
        assertTrue(policy.allowUnsafePrctl, "allowUnsafePrctl should be true")
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/r"))
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/w"))
    }

    @Test
    fun `builder allowJvmClasspath works`() {
        val policy = Policy.builder()
            .allowJvmClasspath()
            .build()
        assertTrue(policy.allowedFsReadPaths.isNotEmpty())
    }

    @Test
    fun `builder base() correctly merges policies`() {
        val policy = Policy.builder()
            .base(Policy.NO_NETWORK)
            .unblock(Syscall.CONNECT)
            .build()

        val arch = Arch.current()
        val restricted = policy.syscallNumbers(arch).toList()

        assertTrue(restricted.contains(arch.bind))
        assertFalse(restricted.contains(arch.connect))
    }

    @Test
    fun `combine() merges multiple policies`() {
        val p1 = Policy.builder().block(Syscall.BIND).build()
        val p2 = Policy.builder().block(Syscall.CONNECT).build()
        val combined = Policy.combine(p1, p2)

        val arch = Arch.current()
        val restricted = combined.syscallNumbers(arch).toList()
        assertTrue(restricted.contains(arch.bind))
        assertTrue(restricted.contains(arch.connect))
    }

    @Test
    fun `combine() with different modes fails`() {
        val p1 = Policy.builder().mode(Policy.Mode.DENY_LIST).build()
        val p2 = Policy.builder().mode(Policy.Mode.ALLOW_LIST).build()
        assertFailsWith<IllegalArgumentException> {
            Policy.combine(p1, p2)
        }
    }

    @Test
    fun `combine() intersects ALLOW_LIST syscalls`() {
        val p1 = Policy.builder().mode(Policy.Mode.ALLOW_LIST).allow(Syscall.READ, Syscall.WRITE).build()
        val p2 = Policy.builder().mode(Policy.Mode.ALLOW_LIST).allow(Syscall.WRITE, Syscall.CLOSE).build()
        val combined = Policy.combine(p1, p2)

        assertEquals(Policy.Mode.ALLOW_LIST, combined.mode)
        assertEquals(setOf(Syscall.WRITE), combined.syscalls)
    }

    @Test
    fun `builder unblock of already unblocked syscall`() {
        val policy = Policy.builder()
            .unblock(Syscall.OPEN)
            .unblock(Syscall.OPEN)
            .build()
        assertTrue(!policy.syscallNumbers(Arch.current()).toList().contains(Arch.current().open))
    }

    @Test
    fun `builder allowFsRead with duplicate path`() {
        val policy = Policy.builder()
            .allowFsRead("/tmp/r")
            .allowFsRead("/tmp/r")
            .build()
        assertEquals(1, policy.allowedFsReadPaths.size)
    }

    @Test
    fun `builder allowFsWrite rejects invalid paths`() {
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsWrite("")
        }
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsWrite("relative/path")
        }
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsWrite("/path/with/\u0000/null")
        }
    }

    @Test
    fun `builder allowFsRead rejects null bytes`() {
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsRead("/path/with/\u0000/null")
        }
    }

    @Test
    fun `builder base() merges all flags`() {
        val p1 = Policy.builder()
            .allowMmapExec()
            .allowNonThreadClone()
            .allowUnsafePrctl()
            .allowFsRead("/r")
            .allowFsWrite("/w")
            .block(Syscall.OPEN)
            .build()

        val p2 = Policy.builder().base(p1).build()

        assertTrue(p2.allowMmapExec)
        assertTrue(p2.allowNonThreadClone)
        assertTrue(p2.allowUnsafePrctl)
        assertTrue(p2.allowedFsReadPaths.contains("/r"))
        assertTrue(p2.allowedFsWritePaths.contains("/w"))
        assertTrue(p2.syscalls.contains(Syscall.OPEN))
    }

    @Test
    fun `builder allowJvmClasspath handles missing properties`() {
        // We can't easily mock System.getProperty in a clean way here without affecting other tests,
        // but we can verify it doesn't crash even if we can't fully control the environment.
        val p = Policy.builder().allowJvmClasspath().build()
        // It should at least include java.home
        assertTrue(p.allowedFsReadPaths.any { it.contains("java") || it.contains("jdk") })
    }

    @Test
    fun `combine() intersects Landlock paths`() {
        val p1 = Policy.builder().allowFsRead("/a").allowFsRead("/common").build()
        val p2 = Policy.builder().allowFsRead("/b").allowFsRead("/common").build()
        val combined = Policy.combine(p1, p2)

        assertEquals(setOf("/common"), combined.allowedFsReadPaths, "Landlock paths should be intersected")
    }

    @Test
    fun `combine() with no FS paths results in empty set`() {
        val p1 = Policy.builder().block(Syscall.BIND).build()
        val p2 = Policy.builder().block(Syscall.CONNECT).build()
        val combined = Policy.combine(p1, p2)

        assertTrue(combined.allowedFsReadPaths.isEmpty())
    }

    @Test
    fun `STRICT_SANDBOX includes PURE_COMPUTE and classpath`() {
        val policy = Policy.STRICT_SANDBOX
        val arch = Arch.current()
        val restricted = policy.syscallNumbers(arch).toList()

        assertTrue(restricted.contains(arch.connect))
        assertTrue(restricted.contains(arch.execve))
        assertTrue(policy.allowedFsReadPaths.isNotEmpty(), "STRICT_SANDBOX should allow reading from classpath")
    }
    @Test
    fun `isSyscallAllowed checks mode correctly`() {
        // Deny list mode
        val p1 = Policy.builder().mode(Policy.Mode.DENY_LIST).block(Syscall.OPEN).build()
        assertFalse(p1.isSyscallAllowed(Syscall.OPEN))
        assertTrue(p1.isSyscallAllowed(Syscall.CLOSE))

        // Allow list mode
        val p2 = Policy.builder().mode(Policy.Mode.ALLOW_LIST).allow(Syscall.READ).build()
        assertTrue(p2.isSyscallAllowed(Syscall.READ))
        assertFalse(p2.isSyscallAllowed(Syscall.WRITE))
    }
}
