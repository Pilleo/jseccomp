package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BobCompilerTest {

    @Test
    fun `test compiling various logs to policy and DSL`() {
        val logs = listOf(
            "[PROFILER] pid=12345 syscall=CONNECT args=[3, 139626353982016, 16, 0, 0, 0]",
            "[PROFILER] pid=12345 syscall=OPENAT args=[0, 139626353983000, 0, 0, 0, 0] paths=/etc/hostname", // O_RDONLY
            "[PROFILER] pid=12345 syscall=OPEN args=[139626353983000, 1, 0, 0, 0, 0] paths=/tmp/write-test.txt", // O_WRONLY
            "[PROFILER] pid=12345 syscall=MKDIR args=[139626353983000, 0, 0, 0, 0, 0] paths=/tmp/new-dir",
            "Random unrelated garbage log message"
        )

        // Compile to Policy
        val policy = BobCompiler.compile(logs, Policy.PURE_COMPUTE)

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
        val dsl = BobCompiler.compileToDsl(logs, "Policy.PURE_COMPUTE")
        println("Generated DSL:\n$dsl")

        val expectedDsl = """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .unblock(
        Syscall.CONNECT,
        Syscall.MKDIR,
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
    fun `test empty logs returns unmodified base policy`() {
        val policy = BobCompiler.compile(emptyList(), Policy.PURE_COMPUTE)
        val arch = Arch.current()
        val blocked = policy.blockedSyscalls(arch).toSet()

        assertTrue(Syscall.CONNECT.numberFor(arch) in blocked)
        assertTrue(policy.allowedFsReadPaths.isEmpty())
        assertTrue(policy.allowedFsWritePaths.isEmpty())

        val dsl = BobCompiler.compileToDsl(emptyList(), "Policy.PURE_COMPUTE")
        val expectedDsl = """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .build()
        """.trimIndent()
        assertEquals(expectedDsl.trim(), dsl.trim())
    }
}
