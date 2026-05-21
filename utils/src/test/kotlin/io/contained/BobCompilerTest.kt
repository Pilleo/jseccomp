package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BobCompilerTest {

    companion object {
        private const val O_WRONLY = 1L
        private const val O_CREAT  = 64L
    }

    @Test
    fun `test compiling various events to policy and DSL`() {
        val events = listOf(
            TraceEvent(12345, "CONNECT", longArrayOf(3, 139626353982016, 16, 0, 0, 0), emptyList()),
            TraceEvent(
                12345,
                "OPENAT",
                longArrayOf(0, 139626353983000, 0, 0, 0, 0),
                listOf("/etc/hostname")
            ), // O_RDONLY
            TraceEvent(
                12345,
                "OPEN",
                longArrayOf(139626353983000, O_WRONLY, 0, 0, 0, 0),
                listOf("/tmp/write-test.txt")
            ), // O_WRONLY
            TraceEvent(12345, "MKDIR", longArrayOf(139626353983000, 0, 0, 0, 0, 0), listOf("/tmp/new-dir"))
        )

        // Compile to Bill of Behavior
        val bob = BobCompiler.compile(events)

        // Transpile to Policy
        val policy = bob.toPolicy(Policy.PURE_COMPUTE)

        // Verify unblocked syscalls
        // PURE_COMPUTE blocks CONNECT, OPEN, OPENAT. They should be unblocked now.
        val arch = Arch.current()
        val blocked = policy.blockedSyscalls(arch).toSet()

        val connectNr = Syscall.CONNECT.numberFor(arch)
        val openNr = Syscall.OPEN.numberFor(arch)
        val openatNr = Syscall.OPENAT.numberFor(arch)

        assertTrue(connectNr !in blocked, "CONNECT should be unblocked")
        assertTrue(openNr !in blocked, "OPEN should be unblocked")
        assertTrue(openatNr !in blocked, "OPENAT should be unblocked")

        // Verify fs paths
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hostname"), "Should contain read path")
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/write-test.txt"), "Should contain write path")
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/new-dir"), "Should contain write path")

        // Compile to DSL
        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        println("Generated DSL:\n$dsl")

        val expectedDsl = """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .unblock(
        Syscall.CONNECT,
        Syscall.OPEN,
        Syscall.OPENAT
    )
    .allowFsRead("/etc/hostname")
    .allowFsWrite("/tmp/new-dir")
    .allowFsWrite("/tmp/write-test.txt")
    .build()
        """.trimIndent()

        assertEquals(expectedDsl.trim(), dsl.trim())
    }

    @Test
    fun `test empty events returns unmodified base policy`() {
        val bob = BobCompiler.compile(emptyList())
        val policy = bob.toPolicy(Policy.PURE_COMPUTE)
        val arch = Arch.current()
        val blocked = policy.blockedSyscalls(arch).toSet()

        assertTrue(Syscall.CONNECT.numberFor(arch) in blocked)
        assertTrue(policy.allowedFsReadPaths.isEmpty())
        assertTrue(policy.allowedFsWritePaths.isEmpty())

        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        val expectedDsl = """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .build()
        """.trimIndent()
        assertEquals(expectedDsl.trim(), dsl.trim())
    }

    @Test
    fun `test C-1 bug fix - syscall observed but not blocked by base policy is absent from compiled policy`() {
        // GETPID is generally not blocked by Policy.PURE_COMPUTE.
        // If we observe GETPID, compiling against PURE_COMPUTE should NOT list it in the unblocked list of the DSL
        // and should not have any effect.
        val events = listOf(
            TraceEvent(12345, "GETPID", longArrayOf(0, 0, 0, 0, 0, 0), emptyList())
        )

        val bob = BobCompiler.compile(events)

        // Generate DSL - GETPID should not be listed as unblocked since PURE_COMPUTE does not block it.
        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        val expectedDsl = """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .build()
        """.trimIndent()

        assertEquals(expectedDsl.trim(), dsl.trim())
    }
}
