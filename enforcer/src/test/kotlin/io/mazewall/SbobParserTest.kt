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

        assertEquals(SeccompAction.ACT_ALLOW, policy.defaultAction)
        // Verify syscalls are unblocked
        assertTrue(policy.isSyscallAllowed(Syscall.OPEN))
        assertTrue(policy.isSyscallAllowed(Syscall.WRITE))
        assertTrue(policy.isSyscallAllowed(Syscall.CONNECT))

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
        assertTrue(policy.isSyscallAllowed(Syscall.OPENAT))
    }

    @Test
    fun `test parsing from stream`() {
        val json = "{\"opens\": [\"/etc/hosts\"], \"syscalls\": [\"OPEN\"]}"
        val stream = ByteArrayInputStream(json.toByteArray())
        val policy = SbobParser.parseToPolicy(stream, Policy.PURE_COMPUTE)
        assertTrue(policy.allowedFsReadPaths.contains("/etc/hosts"))
        assertTrue(policy.isSyscallAllowed(Syscall.OPEN))
    }

    @Test
    fun `test parsing with allow list base`() {
        val json = "{\"syscalls\": [\"OPEN\", \"READ\"]}"
        val base =
            Policy
                .builder()
                .defaultAction(SeccompAction.ACT_ERRNO)
                .allow(Syscall.WRITE)
                .build()
        val policy = SbobParser.parseJsonToPolicy(json, base)

        assertEquals(SeccompAction.ACT_ERRNO, policy.defaultAction)
        assertTrue(policy.isSyscallAllowed(Syscall.OPEN))
        assertTrue(policy.isSyscallAllowed(Syscall.READ))
        assertTrue(policy.isSyscallAllowed(Syscall.WRITE))
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
        assertTrue(policy.isSyscallAllowed(Syscall.OPEN))
    }

    @Test
    fun `test complex json structures`() {
        val json = """
            {
                "metadata": {
                    "nested_object": { "key": "value" },
                    "nested_array": [ [ "a", "b" ], [ "c" ] ],
                    "boolean_val": true,
                    "null_val": null,
                    "int_val": 12345
                },
                "opens": ["/tmp/app_data_[1]/cache"],
                "fsWritePaths": [
                    "/tmp/\"escaped\"", "/tmp/\\slash", "/tmp/\n\r\t\b\f\/foo"
                ]
            }
        """.trimIndent()

        val policy = SbobParser.parseJsonToPolicy(json)
        assertTrue(policy.allowedFsReadPaths.contains("/tmp/app_data_[1]/cache"))
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/\"escaped\""))
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/\\slash"))
        assertTrue(policy.allowedFsWritePaths.contains("/tmp/\n\r\t\b\u000C/foo"))
    }
}
