package io.contained.seccomp

import io.contained.Arch
import io.contained.BpfFilter
import io.contained.Policy
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class BpfOverflowFixTest {

    @Test
    fun `BST filter generation handles 100 syscalls without jump offset overflow`() {
        val arch = Arch.AMD64
        val blocked = IntArray(100) { it + 1000 } // Use numbers that won't clash with preamble

        // This used to crash with "jt offset must be an unsigned 8-bit value"
        val filters = BpfFilter.buildFromNumbers(arch, blocked)

        assertTrue(filters.isNotEmpty())
        println("Filter with 100 syscalls: ${filters.size} instructions")

        // Verify BST properties: depth should be around log2(300) ~= 8-9
        // Instruction 4 (check_bst) is the root.
        // It's harder to check depth without a full BPF emulator, but the fact
        // that it didn't throw IllegalStateException (offset > 255) is the key.
    }

    @Test
    fun `PURE_COMPUTE policy builds successfully on current arch`() {
        val arch = Arch.current()
        val filters = BpfFilter.build(arch, Policy.PURE_COMPUTE)
        assertTrue(filters.isNotEmpty())
        println("PURE_COMPUTE filter size: ${filters.size} instructions")
    }
}
