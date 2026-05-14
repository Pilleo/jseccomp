package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BpfFilterTest {

    private val arch = Arch.AMD64

    @Test
    fun `filter starts with arch check`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // LD arch
        assertEquals(0x20.toShort(), filter[0].code)
        assertEquals(4, filter[0].k)
        // JEQ arch_audit
        assertEquals(0x15.toShort(), filter[1].code)
        assertEquals(Arch.AUDIT_ARCH_X86_64, filter[1].k)
    }

    @Test
    fun `filter contains syscall nr load`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // Usually at index 2
        assertEquals(0x20.toShort(), filter[2].code)
        assertEquals(0, filter[2].k)
    }

    @Test
    fun `filter contains high-bound limit check`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // JGT limit
        assertEquals(0x25.toShort(), filter[3].code)
        assertEquals(arch.limit, filter[3].k)
    }

    @Test
    fun `empty policy allows all in-range syscalls`() {
        val filter = BpfFilter.build(arch, Policy.builder().build())
        // For empty policy, the last instruction is RET ALLOW
        val allow = filter[filter.size - 1]
        assertEquals(0x06.toShort(), allow.code)
        assertEquals(LinuxNative.SECCOMP_RET_ALLOW, allow.k)
    }

    @Test
    fun `filter is accepted by the kernel (BPF verifier)`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val thread = Thread {
            val filter = BpfFilter.build(Arch.current(), Policy.NO_EXEC)
            java.lang.foreign.Arena.ofConfined().use { arena ->
                val prog = LinuxNative.newSockFProg(arena, filter)
                LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                val r = LinuxNative.prctl(LinuxNative.PR_SET_SECCOMP, LinuxNative.SECCOMP_MODE_FILTER.toLong(), prog, 0, 0)
                assertEquals(0, r.returnValue, "Kernel rejected BPF: ${LinuxNative.strerror(r.errno)}")
            }
        }
        thread.start()
        thread.join()
    }
}
