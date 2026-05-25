package io.mazewall.profiler

import io.mazewall.Arch
import io.mazewall.Policy
import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BobCompilerTest {
    companion object {
        private const val O_WRONLY = 1L
        private const val O_CREAT = 64L
    }

    @Test
    fun `test compiling various events to policy and DSL`() {
        val events =
            listOf(
                TraceEvent(12345, "CONNECT", longArrayOf(3, 139626353982016, 16, 0, 0, 0), emptyList()),
                TraceEvent(
                    12345,
                    "OPENAT",
                    longArrayOf(0, 139626353983000, 0, 0, 0, 0),
                    listOf("/etc/hostname"),
                ), // O_RDONLY
                TraceEvent(
                    12345,
                    "OPEN",
                    longArrayOf(139626353983000, O_WRONLY, 0, 0, 0, 0),
                    listOf("/tmp/write-test.txt"),
                ), // O_WRONLY
                TraceEvent(12345, "MKDIR", longArrayOf(139626353983000, 0, 0, 0, 0, 0), listOf("/tmp/new-dir")),
            )

        // Compile to Bill of Behavior
        val bob = BobCompiler.compile(events)

        // Transpile to Policy
        val policy = bob.toPolicy(Policy.PURE_COMPUTE)

        // Verify unrestricted syscalls
        // PURE_COMPUTE blocks CONNECT, OPEN, OPENAT. They should be unrestricted now.
        val arch = Arch.current()
        val restricted = policy.syscallNumbers(arch).toSet()

        val connectNr = Syscall.CONNECT.numberFor(arch)
        val openNr = Syscall.OPEN.numberFor(arch)
        val openatNr = Syscall.OPENAT.numberFor(arch)

        assertTrue(connectNr !in restricted, "CONNECT should be unrestricted")
        assertTrue(openNr !in restricted, "OPEN should be unrestricted")
        assertTrue(openatNr !in restricted, "OPENAT should be unrestricted")

        // Verify fs paths
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hostname"), "Should contain read path")
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/write-test.txt"), "Should contain write path")
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/new-dir"), "Should contain write path")

        // Compile to DSL
        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        println("Generated DSL:\n$dsl")

        val expectedDsl =
            """
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
    fun `test empty events returns unmodified base policy`() {
        val bob = BobCompiler.compile(emptyList())
        val policy = bob.toPolicy(Policy.PURE_COMPUTE)
        val arch = Arch.current()
        val restricted = policy.syscallNumbers(arch).toSet()

        assertTrue(Syscall.CONNECT.numberFor(arch) in restricted)
        assertTrue(policy.allowedFsReadPaths.isEmpty())
        assertTrue(policy.allowedFsWritePaths.isEmpty())

        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        val expectedDsl =
            """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .build()
            """.trimIndent()
        assertEquals(expectedDsl.trim(), dsl.trim())
    }

    @Test
    fun `test C-1 bug fix - syscall observed but not restricted by base policy is absent from compiled policy`() {
        // GETPID is generally not restricted by Policy.PURE_COMPUTE.
        // If we observe GETPID, compiling against PURE_COMPUTE should NOT list it in the unrestricted list of the DSL
        // and should not have any effect.
        val events =
            listOf(
                TraceEvent(12345, "GETPID", longArrayOf(0, 0, 0, 0, 0, 0), emptyList()),
            )

        val bob = BobCompiler.compile(events)

        // Generate DSL - GETPID should not be listed as unrestricted since PURE_COMPUTE does not block it.
        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        val expectedDsl =
            """
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .build()
            """.trimIndent()

        assertEquals(expectedDsl.trim(), dsl.trim())
    }

    @Test
    fun `test OPENAT2 and AT variants categorization`() {
        val events =
            listOf(
                TraceEvent(
                    12345,
                    "OPENAT2",
                    longArrayOf(0, 0, 0x12345678, 0, 0, 0), // args[2] is a pointer
                    listOf("/tmp/openat2-test.txt"),
                ),
                TraceEvent(
                    12345,
                    "UNLINKAT",
                    longArrayOf(0, 0, 0, 0, 0, 0),
                    listOf("/tmp/deleted-file.txt"),
                ),
                TraceEvent(
                    12345,
                    "MKDIRAT",
                    longArrayOf(0, 0, 0, 0, 0, 0),
                    listOf("/tmp/new-subdir"),
                ),
                TraceEvent(
                    12345,
                    "RENAMEAT2",
                    longArrayOf(0, 0, 0, 0, 0, 0),
                    listOf("/tmp/old-name", "/tmp/new-name"),
                ),
            )

        val bob = BobCompiler.compile(events)

        assertTrue(bob.fsWritePaths.contains("/tmp/openat2-test.txt"), "OPENAT2 should be treated as write")
        assertTrue(bob.fsWritePaths.contains("/tmp/deleted-file.txt"), "UNLINKAT should be treated as write")
        assertTrue(bob.fsWritePaths.contains("/tmp/new-subdir"), "MKDIRAT should be treated as write")
        assertTrue(bob.fsWritePaths.contains("/tmp/old-name"), "RENAMEAT2 should be treated as write")
        assertTrue(bob.fsWritePaths.contains("/tmp/new-name"), "RENAMEAT2 target should be treated as write")
        assertTrue(bob.opens.isEmpty(), "No paths should be categorized as simple opens in this test")
    }

    @Test
    fun `test compile with empty list edge cases`() {
        val bob = BobCompiler.compile(emptyList())
        assertTrue(bob.opens.isEmpty())
        assertTrue(bob.fsWritePaths.isEmpty())
        assertTrue(bob.syscalls.isEmpty())
        assertTrue(bob.execs.isEmpty())
    }

    @Test
    fun `test unknown and invalid syscall names`() {
        val events = listOf(
            TraceEvent(pid = 1, syscallName = "UNKNOWN_SYSCALL_123", args = longArrayOf(), paths = listOf("/path/unknown")),
            TraceEvent(pid = 1, syscallName = "", args = longArrayOf(), paths = listOf("/path/empty")),
            TraceEvent(pid = 1, syscallName = "NOT_A_SYSCALL", args = longArrayOf(), paths = listOf("/path/invalid")),
        )
        val bob = BobCompiler.compile(events)

        // They should not throw, should not add to syscalls, but should add paths to opens as fallback
        assertTrue(bob.syscalls.isEmpty())
        assertTrue(bob.execs.isEmpty())
        assertTrue(bob.fsWritePaths.isEmpty())
        assertEquals(setOf("/path/unknown", "/path/empty", "/path/invalid"), bob.opens)
    }

    @Test
    fun `test execve and execveat`() {
        val events = listOf(
            TraceEvent(pid = 1, syscallName = "EXECVE", args = longArrayOf(), paths = listOf("/bin/sh")),
            TraceEvent(pid = 1, syscallName = "EXECVEAT", args = longArrayOf(), paths = listOf("/bin/bash")),
        )
        val bob = BobCompiler.compile(events)

        assertEquals(setOf(Syscall.EXECVE, Syscall.EXECVEAT), bob.syscalls)
        assertEquals(setOf("/bin/sh", "/bin/bash"), bob.execs)
        assertTrue(bob.fsWritePaths.isEmpty())
        assertTrue(bob.opens.isEmpty())
    }

    @Test
    fun `test file system mutation syscalls complete`() {
        val mutations = setOf(
            "MKDIR",
            "MKDIRAT",
            "RMDIR",
            "UNLINK",
            "UNLINKAT",
            "RENAME",
            "RENAMEAT",
            "RENAMEAT2",
            "LINK",
            "LINKAT",
            "SYMLINK",
            "SYMLINKAT",
            "CHMOD",
            "FCHMODAT",
            "CHOWN",
            "LCHOWN",
            "FCHOWNAT",
        )

        val events = mutations.map {
            TraceEvent(pid = 1, syscallName = it, args = longArrayOf(), paths = listOf("/path/$it"))
        }

        val bob = BobCompiler.compile(events)

        // They should all map to fsWritePaths
        val expectedWritePaths = mutations.map { "/path/$it" }.toSet()
        assertEquals(expectedWritePaths, bob.fsWritePaths)
        assertTrue(bob.execs.isEmpty())
        assertTrue(bob.opens.isEmpty())

        // Syscalls that are known should be in syscalls
        val expectedSyscalls = mutations
            .mapNotNull {
            runCatching { Syscall.valueOf(it) }.getOrNull()
        }.toSet()
        assertEquals(expectedSyscalls, bob.syscalls)
    }

    @Test
    fun `test OPEN with different args sizes and flags`() {
        val oRdonly = 0L
        val oWronly = 1L
        val oRdwr = 2L
        val oCreat = 64L
        val oTrunc = 512L

        val events = listOf(
            // Missing flags arg (size <= 1), treated as read-only (0)
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(), paths = listOf("/path/missing")),
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10), paths = listOf("/path/missing2")),
            // Read-only
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, oRdonly), paths = listOf("/path/readonly")),
            // Write-only
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, oWronly), paths = listOf("/path/writeonly")),
            // Read-write
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, oRdwr), paths = listOf("/path/readwrite")),
            // Create
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, oCreat), paths = listOf("/path/create")),
            // Truncate
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, oTrunc), paths = listOf("/path/truncate")),
        )

        val bob = BobCompiler.compile(events)

        assertEquals(
            setOf("/path/writeonly", "/path/readwrite", "/path/create", "/path/truncate"),
            bob.fsWritePaths,
        )
        assertEquals(
            setOf("/path/missing", "/path/missing2", "/path/readonly"),
            bob.opens,
        )
    }

    @Test
    fun `test OPENAT with different args sizes and flags`() {
        val oRdonly = 0L
        val oWronly = 1L
        val oRdwr = 2L
        val oCreat = 64L
        val oTrunc = 512L

        val events = listOf(
            // Missing flags arg (size <= 2), treated as read-only (0)
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(), paths = listOf("/path/missing")),
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10), paths = listOf("/path/missing2")),
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20), paths = listOf("/path/missing3")),
            // Read-only
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20, oRdonly), paths = listOf("/path/readonly")),
            // Write-only
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20, oWronly), paths = listOf("/path/writeonly")),
            // Read-write
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20, oRdwr), paths = listOf("/path/readwrite")),
            // Create
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20, oCreat), paths = listOf("/path/create")),
            // Truncate
            TraceEvent(pid = 1, syscallName = "OPENAT", args = longArrayOf(10, 20, oTrunc), paths = listOf("/path/truncate")),
        )

        val bob = BobCompiler.compile(events)

        assertEquals(
            setOf("/path/writeonly", "/path/readwrite", "/path/create", "/path/truncate"),
            bob.fsWritePaths,
        )
        assertEquals(
            setOf("/path/missing", "/path/missing2", "/path/missing3", "/path/readonly"),
            bob.opens,
        )
    }

    @Test
    fun `test overlapping paths`() {
        // A path is opened for reading, then opened for writing
        val events = listOf(
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, 0L), paths = listOf("/shared/path")), // Read-only
            TraceEvent(pid = 1, syscallName = "OPEN", args = longArrayOf(10, 1L), paths = listOf("/shared/path")), // Write-only
        )

        val bob = BobCompiler.compile(events)

        // Should appear in both sets
        assertTrue(bob.opens.contains("/shared/path"))
        assertTrue(bob.fsWritePaths.contains("/shared/path"))
    }

    @Test
    fun `test unknown syscall with arguments behaves as default`() {
        val events = listOf(
            TraceEvent(pid = 1, syscallName = "UNKNOWN", args = longArrayOf(10, 1L, 64L), paths = listOf("/path/unknown")),
        )

        val bob = BobCompiler.compile(events)

        // Unknown syscall, defaults to 0 flags, so not a write.
        assertTrue(bob.fsWritePaths.isEmpty())
        assertTrue(bob.opens.contains("/path/unknown"))
    }
}
