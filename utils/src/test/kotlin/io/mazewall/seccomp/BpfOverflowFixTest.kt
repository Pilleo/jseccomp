package io.mazewall.seccomp

import io.mazewall.Arch
import io.mazewall.BpfFilter
import io.mazewall.Policy
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class BpfOverflowFixTest {
    @Test
    fun `linear scan filter generation handles 100 syscalls without jump offset overflow`() {
        val arch = Arch.AMD64
        val blocked = IntArray(100) { it + 1000 } // Use numbers that won't clash with preamble

        // This used to crash with "jt offset must be an unsigned 8-bit value"
        val filters = BpfFilter.buildFromNumbers(arch, blocked, Policy.Mode.DENY_LIST)

        assertTrue(filters.isNotEmpty())
        println("Filter with 100 syscalls: ${filters.size} instructions")

        // Verify linear scan properties:
        // A linear scan is robust against jump offset limit overflows because
        // each check is localized with a small relative jump offset.
        // The fact that it didn't throw IllegalStateException (offset > 255) is the key.
    }

    @Test
    fun `PURE_COMPUTE policy builds successfully on current arch`() {
        val arch = Arch.current()
        val filters = BpfFilter.build(arch, Policy.PURE_COMPUTE)
        assertTrue(filters.isNotEmpty())
        println("PURE_COMPUTE filter size: ${filters.size} instructions")
    }
}
