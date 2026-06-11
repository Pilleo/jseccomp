package io.mazewall.seccomp

import io.mazewall.BpfFilter
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.ffi.NativeConstants
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
        assertEquals(NativeConstants.SECCOMP_RET_ALLOW, last.k, "Last instruction should return ALLOW")
    }

    @Test
    fun `ALLOW_LIST mode has RET DENY as default`() {
        val policy = Policy.builder().defaultAction(io.mazewall.core.SeccompAction.ACT_ERRNO).build()
        val filter = BpfFilter.build(arch, policy)
        val last = filter.last()
        assertEquals(0x06.toShort(), last.code)
        assertEquals(NativeConstants.SECCOMP_RET_ERRNO or NativeConstants.EPERM, last.k)
    }

    @Test
    fun `ALLOW_LIST mode generates RET ALLOW for listed syscalls`() {
        val policy =
            Policy
                .builder()
                .defaultAction(io.mazewall.core.SeccompAction.ACT_ERRNO)
                .allow(Syscall.READ)
                .build()
        val filter = BpfFilter.build(arch, policy)

        // Find JEQ read -> RET ALLOW
        val readNr = Syscall.READ.numberFor(arch)
        var found = false
        for (i in filter.indices) {
            val f = filter[i]
            if (f.code == 0x15.toShort() && f.k == readNr) {
                // jt=0 (match), next instruction should be RET ALLOW
                val next = filter[i + 1]
                if (next.code == 0x06.toShort() && next.k == NativeConstants.SECCOMP_RET_ALLOW) {
                    found = true
                    break
                }
            }
        }
        assertTrue(found, "Filter should return ALLOW for listed syscall in ALLOW_LIST mode")
    }

    @Test
    fun `clone3 always returns ENOSYS even in ALLOW_LIST`() {
        val policy = Policy.builder().defaultAction(io.mazewall.core.SeccompAction.ACT_ERRNO).build()
        val filter = BpfFilter.build(arch, policy)

        val clone3Nr = arch.clone3
        var found = false
        for (i in filter.indices) {
            val f = filter[i]
            if (f.code == 0x15.toShort() && f.k == clone3Nr) {
                val next = filter[i + 1]
                if (next.code == 0x06.toShort() && next.k == (NativeConstants.SECCOMP_RET_ERRNO or 38)) {
                    found = true
                    break
                }
            }
        }
        assertTrue(found, "clone3 should always return ENOSYS")
    }

    @Test
    fun `testBpfMmapArgumentInspection`() {
        val policy = Policy.builder().unblock(Syscall.MMAP).build() // NO_EXEC by default blocks mmap exec
        val filter = BpfFilter.build(arch, policy)

        // Find JEQ mmap -> check PROT_EXEC
        val mmapNr = Syscall.MMAP.numberFor(arch)
        var foundInspection = false
        for (i in filter.indices) {
            val f = filter[i]
            if (f.code == 0x15.toShort() && f.k == mmapNr) {
                // Should load args[2] (offset 32)
                val ldArgs = filter[i + 1]
                if (ldArgs.code == 0x20.toShort() && ldArgs.k == 32) {
                    // Should bitwise AND with 0x04 (PROT_EXEC)
                    val andIns = filter[i + 2]
                    if (andIns.code == 0x54.toShort() && andIns.k == 0x04) {
                        // Should check JEQ 0 (expected)
                        val jeqIns = filter[i + 3]
                        if (jeqIns.code == 0x15.toShort() && jeqIns.k == 0) {
                            foundInspection = true
                        }
                    }
                }
            }
        }
        assertTrue(foundInspection, "Filter should inspect mmap arguments for PROT_EXEC")
    }

    @Test
    fun `testBpfCloneArgumentInspection`() {
        val policy = Policy.builder().build() // NO_EXEC by default protects clone
        val filter = BpfFilter.build(arch, policy)

        val cloneNr = Syscall.CLONE.numberFor(arch)
        var foundInspection = false
        for (i in filter.indices) {
            val f = filter[i]
            if (f.code == 0x15.toShort() && f.k == cloneNr) {
                // Should load args[0] (offset 16)
                val ldArgs = filter[i + 1]
                if (ldArgs.code == 0x20.toShort() && ldArgs.k == 16) {
                    // Should mask CLONE_VM | CLONE_THREAD (0x00010100)
                    val mask = filter[i + 2]
                    if (mask.code == 0x54.toShort() && mask.k == 0x00010100) {
                        foundInspection = true
                    }
                }
            }
        }
        assertTrue(foundInspection, "Filter should inspect clone arguments for CLONE_THREAD")
    }

    @Test
    fun `testBpfPrctlArgumentInspection`() {
        val policy = Policy.builder().build() // NO_EXEC protects prctl
        val filter = BpfFilter.build(arch, policy)

        val prctlNr = Syscall.PRCTL.numberFor(arch)
        var foundInspection = false
        for (i in filter.indices) {
            val f = filter[i]
            if (f.code == 0x15.toShort() && f.k == prctlNr) {
                // Should load args[0] (offset 16)
                val ldArgs = filter[i + 1]
                if (ldArgs.code == 0x20.toShort() && ldArgs.k == 16) {
                     foundInspection = true
                }
            }
        }
        assertTrue(foundInspection, "Filter should inspect prctl arguments")
    }
}
