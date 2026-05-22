package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class PolicyTest {

    @Test
    fun `blockedSyscalls returns sorted array`() {
        val policy = Policy.builder()
            .block(Syscall.SENDTO, Syscall.ACCEPT, Syscall.CONNECT, Syscall.BIND)
            .build()

        val blocked = policy.blockedSyscalls(Arch.current())
        val sorted = blocked.sortedArray()

        assertTrue(blocked.contentEquals(sorted), "blockedSyscalls should return a sorted array")
    }

    @Test
    fun `NO_NETWORK policy includes all network server syscalls`() {
        val policy = Policy.NO_NETWORK
        val arch = Arch.current()
        val blocked = policy.blockedSyscalls(arch).toList()

        assertTrue(blocked.contains(arch.bind), "NO_NETWORK should block bind")
        assertTrue(blocked.contains(arch.listen), "NO_NETWORK should block listen")
        assertTrue(blocked.contains(arch.accept), "NO_NETWORK should block accept")
        assertTrue(blocked.contains(arch.accept4), "NO_NETWORK should block accept4")
        assertTrue(blocked.contains(arch.connect), "NO_NETWORK should block connect")
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
        val blocked = policy.blockedSyscalls(arch).toList()

        assertTrue(blocked.contains(arch.bind))
        assertFalse(blocked.contains(arch.connect))
    }

    @Test
    fun `combine() merges multiple policies`() {
        val p1 = Policy.builder().block(Syscall.BIND).build()
        val p2 = Policy.builder().block(Syscall.CONNECT).build()
        val combined = Policy.combine(p1, p2)

        val arch = Arch.current()
        val blocked = combined.blockedSyscalls(arch).toList()
        assertTrue(blocked.contains(arch.bind))
        assertTrue(blocked.contains(arch.connect))
    }

    @Test
    fun `builder unblock of already unblocked syscall`() {
        val policy = Policy.builder()
            .unblock(Syscall.OPEN)
            .unblock(Syscall.OPEN)
            .build()
        assertTrue(!policy.blockedSyscalls(Arch.current()).toList().contains(Arch.current().open))
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
        assertTrue(p2.blocked.contains(Syscall.OPEN))
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
        val blocked = policy.blockedSyscalls(arch).toList()

        assertTrue(blocked.contains(arch.connect))
        assertTrue(blocked.contains(arch.execve))
        assertTrue(policy.allowedFsReadPaths.isNotEmpty(), "STRICT_SANDBOX should allow reading from classpath")
    }
}
