package io.mazewall.seccomp

import io.kotest.matchers.ints.shouldBeLessThan
import io.kotest.property.Exhaustive
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.collection
import io.mazewall.BpfFilter
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.Syscall
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class BpfFilterPropertyTest {
    @Test
    fun `bpf filter generation handles random combinations of syscalls without exceeding size limits`() {
        runBlocking {
            // Fuzz test with combinations of blocked syscalls
            checkAll(Exhaustive.collection(Syscall.entries.chunked(10))) { randomSyscalls ->
                val policy = Policy
                    .builder()
                    .apply {
                        randomSyscalls.forEach { block(it) }
                    }.build()

                val filter = BpfFilter.build(Arch.AMD64, policy)

                // Linux limits BPF programs to 4096 instructions
                filter.size shouldBeLessThan 4096
            }
        }
    }
}
