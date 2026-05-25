package io.mazewall.profiler

import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BillOfBehaviorTest {
    @Test
    fun `test plus operator merges stack traces without data loss`() {
        val event = TraceEvent(0, "OPEN", longArrayOf(1), listOf("/test"))

        val stack1 = arrayOf(StackTraceElement("Class1", "method1", "File1.kt", 1))
        val stack2 = arrayOf(StackTraceElement("Class2", "method2", "File2.kt", 2))

        val bob1 =
            BillOfBehavior(
                stackProfile = mapOf(event to listOf(stack1)),
            )

        val bob2 =
            BillOfBehavior(
                stackProfile = mapOf(event to listOf(stack2)),
            )

        val merged = bob1 + bob2

        val traces = merged.stackProfile[event]
        assertTrue(traces != null)
        assertEquals(2, traces.size)
        assertEquals("Class1", traces[0][0].className)
        assertEquals("Class2", traces[1][0].className)
    }

    @Test
    fun `test plus operator merges other fields correctly`() {
        val bob1 =
            BillOfBehavior(
                opens = setOf("/read1"),
                fsWritePaths = setOf("/write1"),
                syscalls = setOf(Syscall.OPEN),
                execs = setOf("/bin/ls"),
            )

        val bob2 =
            BillOfBehavior(
                opens = setOf("/read2"),
                fsWritePaths = setOf("/write2"),
                syscalls = setOf(Syscall.GETPID),
                execs = setOf("/bin/sh"),
            )

        val merged = bob1 + bob2

        assertEquals(setOf("/read1", "/read2"), merged.opens)
        assertEquals(setOf("/write1", "/write2"), merged.fsWritePaths)
        assertEquals(setOf(Syscall.OPEN, Syscall.GETPID), merged.syscalls)
        assertEquals(setOf("/bin/ls", "/bin/sh"), merged.execs)
    }

    @Test
    fun `test toPolicy translates fields correctly`() {
        val bob =
            BillOfBehavior(
                opens = setOf("/read"),
                fsWritePaths = setOf("/write"),
                syscalls = setOf(Syscall.OPEN, Syscall.CONNECT),
            )

        // Deny-list mode base policy (blocks OPEN, so should unblock it)
        val denyPolicy = io.mazewall.Policy.PURE_COMPUTE
        val compiledDeny = bob.toPolicy(denyPolicy)
        assertEquals(setOf("/read"), compiledDeny.allowedFsReadPaths)
        assertEquals(setOf("/write"), compiledDeny.allowedFsWritePaths)

        // Allow-list mode base policy
        val allowBase =
            io.mazewall.Policy
                .builder()
                .mode(io.mazewall.Policy.Mode.ALLOW_LIST)
                .build()
        val compiledAllow = bob.toPolicy(allowBase)
        assertEquals(io.mazewall.Policy.Mode.ALLOW_LIST, compiledAllow.mode)
        assertTrue(compiledAllow.syscalls.contains(Syscall.OPEN))
        assertTrue(compiledAllow.syscalls.contains(Syscall.CONNECT))
    }

    @Test
    fun `test toDsl generates correct snippets`() {
        val bob =
            BillOfBehavior(
                opens = setOf("/read"),
                fsWritePaths = setOf("/write"),
                syscalls = setOf(Syscall.OPEN),
            )

        // Deny-list base DSL
        val dslDeny = bob.toDsl("Policy.PURE_COMPUTE", io.mazewall.Policy.PURE_COMPUTE)
        assertTrue(dslDeny.contains("Policy.builder()"))
        assertTrue(dslDeny.contains(".base(Policy.PURE_COMPUTE)"))
        assertTrue(dslDeny.contains("Syscall.OPEN"))
        assertTrue(dslDeny.contains(".allowFsRead(\"/read\")"))
        assertTrue(dslDeny.contains(".allowFsWrite(\"/write\")"))

        // Allow-list base DSL
        val allowBase =
            io.mazewall.Policy
                .builder()
                .mode(io.mazewall.Policy.Mode.ALLOW_LIST)
                .build()
        val dslAllow = bob.toDsl("Policy.builder().mode(Mode.ALLOW_LIST).build()", allowBase)
        assertTrue(dslAllow.contains(".allow("))
        assertTrue(dslAllow.contains("Syscall.OPEN"))
    }

    @Test
    fun `test path pruning resolves redundant directories`() {
        val bob =
            BillOfBehavior(
                opens = setOf(
                    "/home",
                    "/home/leanid",
                    "/home/leanid/.sdkman",
                    "/tmp/config.json",
                    "/tmp",
                ),
                fsWritePaths = setOf(
                    "/var/log",
                    "/var/log/app.log",
                ),
            )

        val policy = bob.toPolicy(io.mazewall.Policy.PURE_COMPUTE)

        // Verifying the compiled policy allowed paths are pruned to keep the most specific child (least privilege)!
        assertEquals(setOf("/home/leanid/.sdkman", "/tmp/config.json"), policy.allowedFsReadPaths)
        assertEquals(setOf("/var/log/app.log"), policy.allowedFsWritePaths)

        // Verifying the generated DSL is also pruned!
        val dsl = bob.toDsl()
        assertTrue(dsl.contains(".allowFsRead(\"/home/leanid/.sdkman\")"))
        assertTrue(dsl.contains(".allowFsRead(\"/tmp/config.json\")"))
        assertFalse(dsl.contains(".allowFsRead(\"/home\")"))
        assertFalse(dsl.contains(".allowFsRead(\"/tmp\")"))
        assertTrue(dsl.contains(".allowFsWrite(\"/var/log/app.log\")"))
        assertFalse(dsl.contains(".allowFsWrite(\"/var/log\")"))
    }
}
