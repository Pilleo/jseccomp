package io.contained

import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.ConnectException
import java.net.SocketException
import java.nio.file.AccessDeniedException
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ContainmentViolationDetectorTest {

    @Test
    fun `IOException with EPERM message is detected`() {
        val e = IOException("Operation not permitted")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `IOException with Permission denied message is detected`() {
        val e = IOException("Permission denied")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `SocketException with Permission in message is detected`() {
        val e = SocketException("Permission denied")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `AccessDeniedException is detected`() {
        val e = AccessDeniedException("/some/path")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `IOException with Cannot run is detected`() {
        val e = IOException("Cannot run program \"/bin/sh\": IOException: error=1, Operation not permitted")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `exception with null message is not detected`() {
        val e = IOException(null as String?)
        assertFalse(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `unrelated IOException is not detected`() {
        val e = IOException("Connection reset by peer")
        assertFalse(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `unrelated RuntimeException is not detected`() {
        val e = IllegalArgumentException("bad argument")
        assertFalse(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `IOException with errno 1 via cause chain is detected`() {
        val root = IOException("Operation not permitted")
        val wrapped = RuntimeException("task failed", root)
        assertTrue(ContainedExecutors.isContainmentViolation(wrapped))
    }

    @Test
    fun `IOException with errno 1 deep in cause chain is detected`() {
        val root = IOException("Operation not permitted")
        val mid = RuntimeException("wrapper", root)
        val top = IllegalStateException("top", mid)
        assertTrue(ContainedExecutors.isContainmentViolation(top))
    }

    @Test
    fun `non-EPERM cause chain is not detected`() {
        val root = IOException("Connection timed out")
        val wrapped = RuntimeException("task failed", root)
        assertFalse(ContainedExecutors.isContainmentViolation(wrapped))
    }

    @Test
    fun `ConnectException from blocked connect syscall is detected`() {
        val e = ConnectException("Permission denied")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `real exec EPERM produces detectable pattern`() {
        val e = IOException("Cannot run program \"/bin/sh\": error=1, Operation not permitted")
        assertTrue(ContainedExecutors.isContainmentViolation(e))
    }

    @Test
    fun `suppressed exception with EPERM is detected`() {
        val primary = RuntimeException("task failed")
        val suppressed = IOException("Operation not permitted")
        primary.addSuppressed(suppressed)
        assertTrue(ContainedExecutors.isContainmentViolation(primary))
    }

    @Test
    fun `findViolationCause returns root EPERM from cause chain`() {
        val root = IOException("Operation not permitted")
        val mid = RuntimeException("wrapper", root)
        val top = IllegalStateException("top", mid)
        val found = ContainedExecutors.findViolationCause(top)
        assertTrue(found === root, "Expected the root IOException, got $found")
    }

    @Test
    fun `findViolationCause returns null for non-violation`() {
        val e = IOException("Connection reset")
        val found = ContainedExecutors.findViolationCause(e)
        assertTrue(found == null, "Expected null for non-violation, got $found")
    }

    @Test
    fun `findViolationCause returns direct violation`() {
        val e = IOException("Operation not permitted")
        val found = ContainedExecutors.findViolationCause(e)
        assertTrue(found === e, "Expected the same exception, got $found")
    }

    @Test
    fun `findViolationCause finds suppressed violation`() {
        val primary = RuntimeException("task failed")
        val suppressed = SocketException("Permission denied")
        primary.addSuppressed(suppressed)
        val found = ContainedExecutors.findViolationCause(primary)
        assertTrue(found === suppressed, "Expected the suppressed SocketException, got $found")
    }
}
