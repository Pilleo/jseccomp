package io.mazewall

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path

class SbobParserTest {
    @Test
    fun `test parsing simple sbob json`() {
        val json =
            """
            {
              "opens": ["/etc/hostname", "/tmp/foo/bar"],
              "fsWritePaths": ["/tmp/write.txt"],
              "syscalls": ["OPEN", "WRITE", "CONNECT"],
              "execs": []
            }
            """.trimIndent()

        val base = Policy.PURE_COMPUTE // blocks OPEN, WRITE, CONNECT
        val policy = SbobParser.parseJsonToPolicy(json, base)

        assertEquals(Policy.Mode.DENY_LIST, policy.mode)
        // Verify syscalls are unblocked
        assertTrue(!policy.syscalls.contains(Syscall.OPEN))
        assertTrue(!policy.syscalls.contains(Syscall.WRITE))
        assertTrue(!policy.syscalls.contains(Syscall.CONNECT))

        // Verify paths are added
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hostname"))
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/foo/bar"))
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/write.txt"))
    }

    @Test
    fun `test parsing from file`(
        @TempDir tempDir: Path,
    ) {
        val json =
            """
            {
              "opens": ["/etc/hosts"],
              "fsWritePaths": [],
              "syscalls": ["OPENAT"],
              "execs": []
            }
            """.trimIndent()
        val file = tempDir.resolve("sbob.json")
        Files.writeString(file, json)

        val policy = SbobParser.parseToPolicy(file, Policy.PURE_COMPUTE)
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hosts"))
        assertTrue(!policy.syscalls.contains(Syscall.OPENAT))
    }

    @Test
    fun `test parsing from stream`() {
        val json = "{\"opens\": [\"/etc/hosts\"], \"syscalls\": [\"OPEN\"]}"
        val stream = ByteArrayInputStream(json.toByteArray())
        val policy = SbobParser.parseToPolicy(stream, Policy.PURE_COMPUTE)
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hosts"))
        assertTrue(!policy.syscalls.contains(Syscall.OPEN))
    }

    @Test
    fun `test parsing with allow list base`() {
        val json = "{\"syscalls\": [\"OPEN\", \"READ\"]}"
        val base =
            Policy
                .builder()
                .mode(Policy.Mode.ALLOW_LIST)
                .allow(Syscall.WRITE)
                .build()
        val policy = SbobParser.parseJsonToPolicy(json, base)

        assertEquals(Policy.Mode.ALLOW_LIST, policy.mode)
        assertTrue(policy.syscalls.contains(Syscall.OPEN))
        assertTrue(policy.syscalls.contains(Syscall.READ))
        assertTrue(policy.syscalls.contains(Syscall.WRITE))
    }

    @Test
    fun `test escaped json strings`() {
        val json = "{\"opens\": [\"/tmp/space\\\\path\", \"/tmp/quote\\\"path\"]}"
        val policy = SbobParser.parseJsonToPolicy(json)
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/space\\path"))
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/quote\"path"))
    }

    @Test
    fun `test subpath pruning`() {
        val json =
            """
            {
              "opens": ["/tmp", "/tmp/foo", "/var/log", "/var/log/app.log"],
              "fsWritePaths": [],
              "syscalls": [],
              "execs": []
            }
            """.trimIndent()

        val policy = SbobParser.parseJsonToPolicy(json)

        // Should prune /tmp/foo because /tmp covers it, and /var/log/app.log because /var/log covers it
        assertEquals(setOf("/tmp", "/var/log"), policy.allowedFsReadPaths)
    }

    @Test
    fun `test parsing empty sbob`() {
        val json = "{}"
        val policy = SbobParser.parseJsonToPolicy(json)
        assertTrue(policy.allowedFsReadPaths.isEmpty())
        assertTrue(policy.allowedFsWritePaths.isEmpty())
    }

    @Test
    fun `test invalid syscall name ignored`() {
        val json = "{\"syscalls\": [\"INVALID_SYSCALL\", \"OPEN\"]}"
        val policy = SbobParser.parseJsonToPolicy(json, Policy.PURE_COMPUTE)
        assertTrue(!policy.syscalls.contains(Syscall.OPEN))
    }
}
