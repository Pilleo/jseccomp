package io.contained.seccomp

import io.contained.Arch
import io.contained.BpfFilter
import io.contained.EnabledIfLinuxAndSupported
import io.contained.LinuxNative
import io.contained.Policy
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BpfFilterTest {

    private val arch = Arch.AMD64

    @Test
    fun `filter contains arch check`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())

        // Find LD W ABS 4 (Load architecture audit ID)
        val hasArchLoad = filter.any { it.code == 0x20.toShort() && it.k == 4 }
        assertTrue(hasArchLoad, "Filter should contain instruction to load architecture audit ID")

        // Find JEQ AUDIT_ARCH_X86_64
        val hasArchCheck = filter.any { it.code == 0x15.toShort() && it.k == Arch.AUDIT_ARCH_X86_64 }
        assertTrue(hasArchCheck, "Filter should contain check for X86_64 architecture")
    }

    @Test
    fun `filter contains syscall nr load`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // Load syscall NR (LD W ABS 0)
        val hasSyscallLoad = filter.any { it.code == 0x20.toShort() && it.k == 0 }
        assertTrue(hasSyscallLoad, "Filter should contain instruction to load syscall number")
    }

    @Test
    fun `empty policy allows all syscalls`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // The last instruction should be RET ALLOW
        val last = filter.last()
        assertEquals(0x06.toShort(), last.code, "Last instruction should be RET")
        assertEquals(LinuxNative.SECCOMP_RET_ALLOW, last.k, "Last instruction should return ALLOW")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `filter is accepted by the kernel (BPF verifier)`() {
        val thread = Thread {
            val filter = BpfFilter.build(Arch.current(), Policy.NO_EXEC)
            java.lang.foreign.Arena.ofConfined().use { arena ->
                val prog = LinuxNative.newSockFProg(arena, filter)
                LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                val r = LinuxNative.prctl(
                    LinuxNative.PR_SET_SECCOMP,
                    LinuxNative.SECCOMP_MODE_FILTER.toLong(),
                    prog,
                    0,
                    0
                )
                assertEquals(0L, r.returnValue, "Kernel rejected BPF: errno ${r.errno}")
            }
        }
        thread.start()
        thread.join()
    }
}
