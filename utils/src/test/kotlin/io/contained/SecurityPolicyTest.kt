package io.contained

import io.contained.enforcer.ContainedExecutors
import io.contained.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class SecurityPolicyTest {

    @Test
    fun `PURE_COMPUTE blocks filesystem modifications`() {
        val executor = Executors.newSingleThreadExecutor()
        val safe = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        val tempFile = Files.createTempFile("jseccomp-test", ".txt").toFile()
        tempFile.writeText("original")

        try {
            // Test RENAME (Files.move throws IOException on failure)
            val renameFuture = safe.submit {
                val newPath = tempFile.toPath().resolveSibling("renamed-${System.currentTimeMillis()}.txt")
                Files.move(tempFile.toPath(), newPath)
            }
            val ex = org.junit.jupiter.api.assertThrows<ExecutionException> {
                renameFuture.get()
            }
            assertTrue(ex.cause is ContainmentViolationException, "Expected violation for rename, got ${ex.cause}")

            // Test MKDIR (Files.createDirectory throws IOException on failure)
            val mkdirFuture = safe.submit {
                val dir = tempFile.toPath().resolveSibling("new-dir-${System.currentTimeMillis()}")
                Files.createDirectory(dir)
            }
            val ex2 = org.junit.jupiter.api.assertThrows<ExecutionException> {
                mkdirFuture.get()
            }
            assertTrue(ex2.cause is ContainmentViolationException, "Expected violation for mkdir, got ${ex2.cause}")

        } finally {
            tempFile.delete()
            executor.shutdown()
        }
    }
}
