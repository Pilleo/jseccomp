package io.mazewall.enforcer

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class ContainmentViolationExceptionTest {
    @Test
    fun `test constructors`() {
        val cause = RuntimeException("orig")
        val ex1 = ContainmentViolationException("msg", cause)
        assertEquals("msg", ex1.message)
        assertSame(cause, ex1.cause)

        val ex2 = ContainmentViolationException("msg")
        assertEquals("msg", ex2.message)
        assertEquals(null, ex2.cause)
    }
}
