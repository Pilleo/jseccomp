package io.mazewall.seccomp

import io.mazewall.Arch
import io.mazewall.BpfFilter
import io.mazewall.Policy
import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class BpfFilterLabelTest {
    private val arch = Arch.AMD64

    @Test
    fun `linear scan filter generation handles multiple syscalls`() {
        val policy =
            Policy
                .builder()
                .block(Syscall.EXECVE, Syscall.OPEN, Syscall.SOCKET)
                .build()

        val filter = BpfFilter.build(arch, policy)
        assertTrue(filter.size >= 10, "Expected at least 10 instructions, got ${filter.size}")
    }

    @Test
    fun `all jump targets land on valid instructions`() {
        val arch = Arch.AMD64
        val policy = Policy.PURE_COMPUTE
        val filter = BpfFilter.build(arch, policy)

        for (i in filter.indices) {
            val insn = filter[i]
            if (insn.code.toInt() and 0x07 == 0x05) { // BPF_JMP
                val jt = insn.jt.toInt() and 0xff
                val jf = insn.jf.toInt() and 0xff
                assertTrue(
                    i + jt + 1 < filter.size,
                    "jt out of bounds at index $i (target ${i + jt + 1}, size ${filter.size})",
                )
                assertTrue(
                    i + jf + 1 < filter.size,
                    "jf out of bounds at index $i (target ${i + jf + 1}, size ${filter.size})",
                )
            }
        }
    }
}
