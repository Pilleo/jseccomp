package io.mazewall.enforcer

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.IOException
import java.net.ConnectException
import java.net.SocketException
import java.nio.file.AccessDeniedException
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ContainmentViolationDetectorTest {
    data class ViolationCase(
        val exception: Throwable,
        val expected: Boolean,
        val description: String,
    )

    companion object {
        @JvmStatic
        fun violationCases() =
            listOf(
                ViolationCase(IOException("Operation not permitted"), true, "IOException with EPERM"),
                ViolationCase(IOException("Permission denied"), true, "IOException with Permission denied"),
                ViolationCase(SocketException("Permission denied"), true, "SocketException with Permission denied"),
                ViolationCase(AccessDeniedException("/some/path"), true, "AccessDeniedException"),
                ViolationCase(
                    IOException("Cannot run program \"/bin/sh\": IOException: error=1, Operation not permitted"),
                    true,
                    "JVM exec EPERM",
                ),
                ViolationCase(ConnectException("Permission denied"), true, "ConnectException with Permission denied"),
                ViolationCase(IOException(null as String?), false, "IOException with null message"),
                ViolationCase(IOException("Connection reset by peer"), false, "Unrelated IOException"),
                ViolationCase(IllegalArgumentException("bad argument"), false, "Unrelated RuntimeException"),
                ViolationCase(
                    RuntimeException("Access denied by application rule"),
                    false,
                    "Non-IO exception with 'denied'",
                ),
                ViolationCase(
                    IOException("Authentication denied by endpoint"),
                    false,
                    "IOException with unrelated 'denied'",
                ),
            )
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("violationCases")
    fun `test violation detection`(case: ViolationCase) {
        if (case.expected) {
            assertTrue(ContainmentViolationDetector.isContainmentViolation(case.exception), case.description)
        } else {
            assertFalse(ContainmentViolationDetector.isContainmentViolation(case.exception), case.description)
        }
    }

    @Test
    fun `IOException with errno 1 deep in cause chain is detected`() {
        val root = IOException("Operation not permitted")
        val mid = RuntimeException("wrapper", root)
        val top = IllegalStateException("top", mid)
        assertTrue(ContainmentViolationDetector.isContainmentViolation(top))
    }

    @Test
    fun `suppressed exception with EPERM is detected`() {
        val primary = RuntimeException("task failed")
        val suppressed = IOException("Operation not permitted")
        primary.addSuppressed(suppressed)
        assertTrue(ContainmentViolationDetector.isContainmentViolation(primary))
    }

    @Test
    fun `findViolationCause returns root EPERM from cause chain`() {
        val root = IOException("Operation not permitted")
        val mid = RuntimeException("wrapper", root)
        val top = IllegalStateException("top", mid)
        val found = ContainmentViolationDetector.findViolationCause(top)
        assertTrue(found === root, "Expected the root IOException, got $found")
    }

    @Test
    fun `findViolationCause finds suppressed violation`() {
        val primary = RuntimeException("task failed")
        val suppressed = SocketException("Permission denied")
        primary.addSuppressed(suppressed)
        val found = ContainmentViolationDetector.findViolationCause(primary)
        assertTrue(found === suppressed, "Expected the suppressed SocketException, got $found")
    }
}
