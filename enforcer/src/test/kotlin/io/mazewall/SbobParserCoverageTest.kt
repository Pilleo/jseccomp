package io.mazewall

import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import kotlin.test.*

class SbobParserCoverageTest {
    @Test
    fun `test escape sequences in JSON tokenizer`() {
        val json = """{"key": ["\b\f\n\r\t\/\\\" \"xyz\" \u0041"]}"""
        val policy = SbobParser.parseJsonToPolicy(json)
        assertNotNull(policy)
    }

    @Test
    fun `test skip value and array parsing branches`() {
        // Test parseStringArray with non-string values (should skip them)
        val json = """
            {
                "opens": [1, {"a":2}, "/valid/path", null, true]
            }
        """.trimIndent()
        val policy = SbobParser.parseJsonToPolicy(json)
        assertTrue(policy.allowedFsReadPaths.contains("/valid/path"))
        assertEquals(1, policy.allowedFsReadPaths.size)
    }

    @Test
    fun `test skip value logic in JSON tokenizer`() {
        // Test skipping nested structures and primitives in SBoB
        val json = """
            {
                "ignored_obj": {"a": 1, "b": [1, {"x": null}]},
                "ignored_arr": [[1], 2, "str", true, false, null],
                "ignored_prim": 123,
                "ignored_bool": true,
                "ignored_null": null,
                "opens": ["/tmp"]
            }
        """.trimIndent()
        val policy = SbobParser.parseJsonToPolicy(json)
        assertTrue(policy.allowedFsReadPaths.contains("/tmp"))
    }

    @Test
    fun `test blacklist base policy in parser`() {
        // Create a base policy with ACT_ALLOW (blacklist)
        val blacklistBase = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ALLOW)
            .block(Syscall.EXECVE)
            .build()

        val json = """{"syscalls": ["execve", "unknown_syscall"]}"""
        val policy = SbobParser.parseJsonToPolicy(json, blacklistBase)

        // In blacklist mode, 'execve' found in SBoB should be unblocked (removed from blacklist)
        assertFalse(policy.syscallActions.containsKey(Syscall.EXECVE))
    }

    @Test
    fun `test parse from InputStream`() {
        val json = """{"opens": ["/etc"]}"""
        val stream = ByteArrayInputStream(json.toByteArray())
        val policy = SbobParser.parseToPolicy(stream)
        assertTrue(policy.allowedFsReadPaths.contains("/etc"))
    }

    @Test
    fun `test malformed JSON handling`() {
        // Unclosed string
        assertNotNull(SbobParser.parseJsonToPolicy("""{"key": "val"""))
        // Unclosed object
        assertNotNull(SbobParser.parseJsonToPolicy("""{"key": ["val"]"""))
        // Missing colon
        assertNotNull(SbobParser.parseJsonToPolicy("""{"key" ["val"]}"""))
        // Random junk at end
        assertNotNull(SbobParser.parseJsonToPolicy("""{"key": "val"} junk"""))
        // Unexpected delimiter
        assertNotNull(SbobParser.parseJsonToPolicy("""{"key": "val", , "key2": "val2"}"""))
    }

    @Test
    fun `test pruneSubpaths logic`() {
        val json = """
            {
                "opens": ["/etc", "/etc/passwd", "/var/log", "/var/log/syslog", "/tmp/../tmp/foo"]
            }
        """.trimIndent()
        val policy = SbobParser.parseJsonToPolicy(json)
        // /etc/passwd should be pruned by /etc
        // /var/log/syslog should be pruned by /var/log
        // /tmp/../tmp/foo should be normalized to /tmp/foo
        assertTrue(policy.allowedFsReadPaths.contains("/etc"))
        assertTrue(policy.allowedFsReadPaths.contains("/var/log"))
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/foo"))
        assertFalse(policy.allowedFsReadPaths.contains("/etc/passwd"))
    }
}
