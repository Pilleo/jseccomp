package io.mazewall

import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PolicyTest {
    @Test
    fun `syscallNumbers returns sorted array`() {
        val policy =
            Policy
                .builder()
                .block(Syscall.SENDTO, Syscall.ACCEPT, Syscall.CONNECT, Syscall.BIND)
                .build()

        val restricted = policy.syscallActionNumbers(Arch.current()).keys.toIntArray()
        val sorted = restricted.sortedArray()

        assertTrue(restricted.contentEquals(sorted), "syscallNumbers should return a sorted array")
    }

    @Test
    fun `NO_NETWORK policy includes all network server syscalls`() {
        val policy = Policy.NO_NETWORK
        val arch = Arch.current()
        val restricted = policy.syscallActionNumbers(arch).keys.toList()

        assertTrue(restricted.contains(arch.bind), "NO_NETWORK should block bind")
        assertTrue(restricted.contains(arch.listen), "NO_NETWORK should block listen")
        assertTrue(restricted.contains(arch.accept), "NO_NETWORK should block accept")
        assertTrue(restricted.contains(arch.accept4), "NO_NETWORK should block accept4")
        assertTrue(restricted.contains(arch.connect), "NO_NETWORK should block connect")
    }

    @Test
    fun `builder methods correctly set flags`() {
        val policy =
            Policy
                .builder()
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
        val policy =
            Policy
                .builder()
                .allowJvmClasspath()
                .build()
        assertTrue(policy.allowedFsReadPaths.isNotEmpty())
    }

    @Test
    fun `builder base() correctly merges policies`() {
        val policy =
            Policy
                .builder()
                .base(Policy.NO_NETWORK)
                .unblock(Syscall.CONNECT)
                .build()

        val arch = Arch.current()
        val restricted = policy.syscallActionNumbers(arch).keys.toList()

        assertTrue(restricted.contains(arch.bind))
        assertFalse(restricted.contains(arch.connect))
    }

    @Test
    fun `combine() merges multiple policies`() {
        val p1 = Policy.builder().block(Syscall.BIND).build()
        val p2 = Policy.builder().block(Syscall.CONNECT).build()
        val combined = Policy.combine(p1, p2)

        val arch = Arch.current()
        val restricted = combined.syscallActionNumbers(arch).keys.toList()
        assertTrue(restricted.contains(arch.bind))
        assertTrue(restricted.contains(arch.connect))
    }

    @Test
    fun `combine() with different default actions resolves to most restrictive`() {
        val p1 = Policy.builder().defaultAction(SeccompAction.ACT_ALLOW).build()
        val p2 = Policy.builder().defaultAction(SeccompAction.ACT_ERRNO).build()
        val combined = Policy.combine(p1, p2)
        assertEquals(SeccompAction.ACT_ERRNO, combined.defaultAction)
    }

    @Test
    fun `combine() merges whitelist actions`() {
        val p1 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ERRNO)
            .allow(Syscall.READ, Syscall.WRITE)
            .build()
        val p2 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ERRNO)
            .allow(Syscall.WRITE, Syscall.CLOSE)
            .build()
        val combined = Policy.combine(p1, p2)

        assertEquals(SeccompAction.ACT_ERRNO, combined.defaultAction)
        assertTrue(combined.isSyscallAllowed(Syscall.READ))
        assertTrue(combined.isSyscallAllowed(Syscall.CLOSE))
        assertTrue(combined.isSyscallAllowed(Syscall.WRITE))
    }

    @Test
    fun `builder unblock of already unblocked syscall`() {
        val policy =
            Policy
                .builder()
                .unblock(Syscall.OPEN)
                .unblock(Syscall.OPEN)
                .build()
        assertTrue(policy.isSyscallAllowed(Syscall.OPEN))
    }

    @Test
    fun `builder allowFsRead with duplicate path`() {
        val policy =
            Policy
                .builder()
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
    fun `builder allowFsRead rejects invalid paths`() {
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsRead("")
        }
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsRead("relative/path")
        }
        assertFailsWith<IllegalArgumentException> {
            Policy.builder().allowFsRead("/path/with/\u0000/null")
        }
    }

    @Test
    fun `builder base() merges all flags`() {
        val p1 =
            Policy
                .builder()
                .allowMmapExec()
                .allowNonThreadClone()
                .allowUnsafePrctl()
                .allowFsRead("/r")
                .allowFsWrite("/w")
                .block(Syscall.CONNECT)
                .build()

        val p2 = Policy.builder().base(p1).build()

        assertTrue(p2.allowMmapExec)
        assertTrue(p2.allowNonThreadClone)
        assertTrue(p2.allowUnsafePrctl)
        assertTrue(p2.allowedFsReadPaths.contains("/r"))
        assertTrue(p2.allowedFsWritePaths.contains("/w"))
        assertTrue(!p2.isSyscallAllowed(Syscall.CONNECT))
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
        val p1 =
            Policy
                .builder()
                .allowFsRead("/a")
                .allowFsRead("/common")
                .build()
        val p2 =
            Policy
                .builder()
                .allowFsRead("/b")
                .allowFsRead("/common")
                .build()
        val combined = Policy.combine(p1, p2)

        assertEquals(setOf("/common"), combined.allowedFsReadPaths, "Landlock paths should be intersected")
        assertTrue(combined.enforceLandlock, "Should enforce Landlock")
    }

    @Test
    fun `combine() hierarchical Landlock paths yield most restrictive`() {
        val p1 = Policy.builder().allowFsRead("/var").build()
        val p2 = Policy.builder().allowFsRead("/var/log").build()
        val combined = Policy.combine(p1, p2)

        assertEquals(setOf("/var/log"), combined.allowedFsReadPaths, "Should yield the more restrictive path")
        assertTrue(combined.enforceLandlock)
    }

    @Test
    fun `combine() path intersection edge cases`() {
        // Test /home vs /home-bak (should not intersect)
        val p1 = Policy.builder().allowFsRead("/home").build()
        val p2 = Policy.builder().allowFsRead("/home-bak").build()
        val combined = Policy.combine(p1, p2)
        assertTrue(combined.allowedFsReadPaths.isEmpty(), "/home should not intersect with /home-bak")

        // Test trailing slashes
        val p3 = Policy.builder().allowFsRead("/data/").build()
        val p4 = Policy.builder().allowFsRead("/data/db").build()
        assertEquals(setOf("/data/db"), Policy.combine(p3, p4).allowedFsReadPaths)

        val p5 = Policy.builder().allowFsRead("/data").build()
        val p6 = Policy.builder().allowFsRead("/data/").build()
        assertEquals(setOf("/data/"), Policy.combine(p5, p6).allowedFsReadPaths, "Should preserve trailing slash if deeper")
        // Actually, if they are equal, either is fine. Current code adds p1 if p2 prefix of p1, or p2 if p1 prefix of p2.
        // If p5=/data, p6=/data/, p5 prefix of p6 (true), p6 prefix of p5 (true).
        // Let's see: isParent("/data", "/data/") -> "/data" == "/data/" (false), "/data" + "/" = "/data/". "/data/".startsWith("/data/") (true).
        // isParent("/data/", "/data") -> "/data/" == "/data" (false), "/data/".endsWith("/") (true). "/data".startsWith("/data/") (false).
        // So p5 is parent of p6. Adds p6.
    }

    @Test
    fun `combine() disjoint Landlock paths forces Landlock`() {
        val p1 = Policy.builder().allowFsRead("/a").build()
        val p2 = Policy.builder().allowFsRead("/b").build()
        val combined = Policy.combine(p1, p2)

        assertTrue(combined.allowedFsReadPaths.isEmpty(), "Disjoint paths result in empty set")
        assertTrue(combined.enforceLandlock, "Disjoint paths must still enforce Landlock")
    }

    @Test
    fun `combine() with no FS paths results in empty set`() {
        val p1 = Policy.builder().block(Syscall.BIND).build()
        val p2 = Policy.builder().block(Syscall.CONNECT).build()
        val combined = Policy.combine(p1, p2)

        assertTrue(combined.allowedFsReadPaths.isEmpty())
    }

    @Test
    fun `PURE_COMPUTE includes PURE_COMPUTE_UNSAFE and classpath allowance`() {
        val policy = Policy.PURE_COMPUTE
        val arch = Arch.current()
        val restricted = policy.syscallActionNumbers(arch).keys.toList()

        assertTrue(restricted.contains(arch.connect))
        assertTrue(restricted.contains(arch.execve))
        assertTrue(policy.allowedFsReadPaths.isNotEmpty(), "PURE_COMPUTE should allow reading from classpath")
    }

    @Test
    fun `isSyscallAllowed checks defaultAction correctly`() {
        val p1 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ALLOW)
            .block(Syscall.OPEN)
            .build()
        assertFalse(p1.isSyscallAllowed(Syscall.OPEN))
        assertTrue(p1.isSyscallAllowed(Syscall.CLOSE))

        val p2 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ERRNO)
            .allow(Syscall.READ)
            .build()
        assertTrue(p2.isSyscallAllowed(Syscall.READ))
        assertFalse(p2.isSyscallAllowed(Syscall.WRITE))
    }

    @Test
    fun `open syscalls are automatically unblocked when Landlock is active`() {
        // Deny list mode
        val policyDeny =
            Policy
                .builder()
                .base(Policy.PURE_COMPUTE_UNSAFE) // use the raw block list as the Landlock test base
                .allowFsRead("/tmp")
                .build()

        assertTrue(policyDeny.enforceLandlock)
        assertTrue(policyDeny.isSyscallAllowed(Syscall.OPEN))
        assertTrue(policyDeny.isSyscallAllowed(Syscall.OPENAT))
        assertTrue(policyDeny.isSyscallAllowed(Syscall.OPENAT2))

        // Allow list mode
        val policyAllow =
            Policy
                .builder()
                .defaultAction(SeccompAction.ACT_ERRNO)
                .allowFsRead("/tmp")
                .build()

        assertTrue(policyAllow.enforceLandlock)
        assertTrue(policyAllow.isSyscallAllowed(Syscall.OPEN))
        assertTrue(policyAllow.isSyscallAllowed(Syscall.OPENAT))
        assertTrue(policyAllow.isSyscallAllowed(Syscall.OPENAT2))
    }

    @Test
    fun `open syscalls are automatically unblocked in combined policies when Landlock is active`() {
        val p1 = Policy.builder().block(Syscall.OPEN, Syscall.OPENAT).build()
        val p2 = Policy.builder().allowFsRead("/tmp").build()

        val combined = Policy.combine(p1, p2)
        assertTrue(combined.enforceLandlock)
        assertTrue(combined.isSyscallAllowed(Syscall.OPEN))
        assertTrue(combined.isSyscallAllowed(Syscall.OPENAT))
    }
}
