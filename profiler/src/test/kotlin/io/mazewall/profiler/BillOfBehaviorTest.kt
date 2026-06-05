package io.mazewall.profiler

import io.mazewall.Syscall
import io.mazewall.profiler.engine.TraceEvent
import org.junit.jupiter.api.Test
import java.nio.file.Files
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
        val denyPolicy = io.mazewall.Policy.PURE_COMPUTE_UNSAFE
        val compiledDeny = bob.toPolicy(denyPolicy)
        assertEquals(setOf("/read"), compiledDeny.allowedFsReadPaths)
        assertEquals(setOf("/write"), compiledDeny.allowedFsWritePaths)

        // Allow-list mode base policy
        val policy = bob.toPolicy(
            io.mazewall.Policy
                .builder()
                .defaultAction(io.mazewall.SeccompAction.ACT_ERRNO)
                .build(),
        )
        assertEquals(io.mazewall.SeccompAction.ACT_ERRNO, policy.defaultAction)

        val policyDenyList = bob.toPolicy()
        assertEquals(io.mazewall.SeccompAction.ACT_ALLOW, policyDenyList.defaultAction)
        assertTrue(policyDenyList.isSyscallAllowed(Syscall.OPEN))
        assertTrue(policyDenyList.isSyscallAllowed(Syscall.CONNECT))
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
        val dslDeny = bob.toDsl("Policy.PURE_COMPUTE_UNSAFE", io.mazewall.Policy.PURE_COMPUTE_UNSAFE)
        assertTrue(dslDeny.contains("Policy.builder()"))
        assertTrue(dslDeny.contains(".base(Policy.PURE_COMPUTE_UNSAFE)"))
        assertTrue(dslDeny.contains("Syscall.OPEN"))
        assertTrue(dslDeny.contains(".allowFsRead(\"/read\")"))
        assertTrue(dslDeny.contains(".allowFsWrite(\"/write\")"))

        // Allow-list base DSL
        val allowBase =
            io.mazewall.Policy
                .builder()
                .defaultAction(io.mazewall.SeccompAction.ACT_ERRNO)
                .build()
        val dslAllow = bob.toDsl("Policy.builder().defaultAction(SeccompAction.ACT_ERRNO).build()", allowBase)
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

        val policy = bob.toPolicy(io.mazewall.Policy.PURE_COMPUTE_UNSAFE)

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

    @Test
    fun `test JSON serialization and deserialization roundtrip`() {
        val bob =
            BillOfBehavior(
                opens = setOf("/home/user/read1", "/home/user/read2"),
                fsWritePaths = setOf("/home/user/write1"),
                syscalls = setOf(Syscall.OPEN, Syscall.CONNECT),
                execs = setOf("/bin/ls", "/bin/sh"),
            )

        val json = bob.toJson()
        val parsed = BillOfBehavior.fromJson(json)

        assertEquals(bob.opens, parsed.opens)
        assertEquals(bob.fsWritePaths, parsed.fsWritePaths)
        assertEquals(bob.syscalls, parsed.syscalls)
        assertEquals(bob.execs, parsed.execs)
    }

    @Test
    fun `test JSON serialization auto-prunes redundant paths`() {
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
                syscalls = setOf(Syscall.OPEN),
            )

        val json = bob.toJson()
        val parsed = BillOfBehavior.fromJson(json)

        // Verifying that they are pruned losslessly!
        assertEquals(setOf("/home/leanid/.sdkman", "/tmp/config.json"), parsed.opens)
        assertEquals(setOf("/var/log/app.log"), parsed.fsWritePaths)
        assertEquals(setOf(Syscall.OPEN), parsed.syscalls)
    }

    @Test
    fun `test loading from file and stream`() {
        val bob =
            BillOfBehavior(
                opens = setOf("/home/user/read"),
                fsWritePaths = setOf("/home/user/write"),
                syscalls = setOf(Syscall.OPEN),
            )

        val tempFile = Files.createTempFile("bob_test", ".json")
        try {
            Files.writeString(tempFile, bob.toJson())

            // Test fromFile
            val fromFileBob = BillOfBehavior.fromFile(tempFile)
            assertEquals(bob.opens, fromFileBob.opens)
            assertEquals(bob.fsWritePaths, fromFileBob.fsWritePaths)
            assertEquals(bob.syscalls, fromFileBob.syscalls)

            // Test fromStream
            Files.newInputStream(tempFile).use { stream ->
                val fromStreamBob = BillOfBehavior.fromStream(stream)
                assertEquals(bob.opens, fromStreamBob.opens)
                assertEquals(bob.fsWritePaths, fromStreamBob.fsWritePaths)
                assertEquals(bob.syscalls, fromStreamBob.syscalls)
            }
        } finally {
            Files.deleteIfExists(tempFile)
        }
    }

    @Test
    fun `test JSON serialization and deserialization roundtrip preserves stackProfile`() {
        val event1 = TraceEvent(0, "OPEN", longArrayOf(1, 2), listOf("/test1"))
        val event2 = TraceEvent(0, "CLOSE", longArrayOf(3), listOf("/test2"))

        val stack1 = arrayOf(
            StackTraceElement("app", "java.base", "11.0", "java.io.FileInputStream", "open0", "FileInputStream.java", 123),
            StackTraceElement("app", "demo.vulnapp", "1.0", "demo.vulnapp.Service", "doWork", "Service.kt", 12),
        )
        val stack2 = arrayOf(
            StackTraceElement("Class2", "method2", "File2.kt", 2),
        )

        val bob = BillOfBehavior(
            opens = setOf("/test1", "/test2"),
            syscalls = setOf(Syscall.OPEN, Syscall.CLOSE),
            stackProfile = mapOf<TraceEvent, List<Array<StackTraceElement>>>(
                event1 to listOf(stack1),
                event2 to listOf(stack2),
            ),
        )

        val json = bob.toJson()
        val parsed = BillOfBehavior.fromJson(json)

        assertEquals(bob.opens, parsed.opens)
        assertEquals(bob.syscalls, parsed.syscalls)

        // Assert stack profile exists and event keys match
        assertEquals(bob.stackProfile.size, parsed.stackProfile.size)

        val parsedEvent1 = parsed.stackProfile.keys.find { it.syscallName == "OPEN" }
        assertTrue(parsedEvent1 != null)
        assertEquals(event1.paths, parsedEvent1.paths)
        assertTrue(event1.args.contentEquals(parsedEvent1.args))

        val parsedTraces1 = parsed.stackProfile[parsedEvent1]!!
        assertEquals(1, parsedTraces1.size)
        assertEquals(stack1.size, parsedTraces1[0].size)
        assertEquals("java.io.FileInputStream", parsedTraces1[0][0].className)
        assertEquals("open0", parsedTraces1[0][0].methodName)
        assertEquals("FileInputStream.java", parsedTraces1[0][0].fileName)
        assertEquals(123, parsedTraces1[0][0].lineNumber)
        assertEquals("java.base", parsedTraces1[0][0].moduleName)
    }

    @Test
    fun `test plus operator deduplicates identical stack traces`() {
        val event = TraceEvent(0, "OPEN", longArrayOf(1), listOf("/test"))

        val stack1 = arrayOf(StackTraceElement("Class1", "method1", "File1.kt", 1))
        val stack2 = arrayOf(StackTraceElement("Class1", "method1", "File1.kt", 1)) // Identical contents
        val stack3 = arrayOf(StackTraceElement("Class2", "method2", "File2.kt", 2)) // Different contents

        val bob1 = BillOfBehavior(
            stackProfile = mapOf(event to listOf(stack1)),
        )
        val bob2 = BillOfBehavior(
            stackProfile = mapOf(event to listOf(stack2, stack3)),
        )

        val merged = bob1 + bob2
        val traces = merged.stackProfile[event]!!

        assertEquals(2, traces.size) // Only stack1 and stack3 should remain, stack2 is a duplicate of stack1
        assertEquals("Class1", traces[0][0].className)
        assertEquals("Class2", traces[1][0].className)
    }
}
