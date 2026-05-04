package io.contained

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BpfFilterTest {

    private val arch = Arch.AMD64

    @Test
    fun `filter has correct number of instructions for empty policy`() {
        val policy = Policy.builder().build()
        val filter = BpfFilter.build(arch, policy)
        // 0: LD arch
        // 1: JEQ arch
        // 2: LD nr
        // 3: JGT limit
        // 4: RET ALLOW  (n=0, so [4+0])
        // 5: RET DENY   (n=0, so [5+0])
        assertEquals(6, filter.size)
    }

    @Test
    fun `filter has correct number of instructions for N blocked syscalls`() {
        val policy = Policy.NO_EXEC
        val n = policy.blockedSyscalls(arch).size
        val filter = BpfFilter.build(arch, policy)
        // Fixed 4 preamble + N checks + 1 allow + 1 deny = N+6
        assertEquals(n + 6, filter.size)
    }

    @Test
    fun `first instruction loads arch field at offset 4`() {
        val filter = BpfFilter.build(arch, Policy.NO_EXEC)
        // BPF_LD|BPF_W|BPF_ABS = 0x20; k = SECCOMP_DATA_ARCH_OFFSET = 4
        assertEquals(0x20.toShort(), filter[0].code)
        assertEquals(4, filter[0].k)
    }

    @Test
    fun `second instruction is arch JEQ with correct audit constant`() {
        val filter = BpfFilter.build(arch, Policy.NO_EXEC)
        // BPF_JMP|BPF_JEQ|BPF_K = 0x15; k = AUDIT_ARCH_X86_64
        assertEquals(0x15.toShort(), filter[1].code)
        assertEquals(Arch.AUDIT_ARCH_X86_64, filter[1].k)
        // jt=0 (fall through on match)
        assertEquals(0, filter[1].jt)
    }

    @Test
    fun `third instruction loads syscall nr at offset 0`() {
        val filter = BpfFilter.build(arch, Policy.NO_EXEC)
        assertEquals(0x20.toShort(), filter[2].code)
        assertEquals(0, filter[2].k)
    }

    @Test
    fun `penultimate instruction allows all remaining syscalls`() {
        val policy = Policy.NO_EXEC
        val n = policy.blockedSyscalls(arch).size
        val filter = BpfFilter.build(arch, policy)
        // [4+n] RET ALLOW: code=BPF_RET|BPF_K=0x06, k=SECCOMP_RET_ALLOW
        assertEquals(0x06.toShort(), filter[4 + n].code)
        assertEquals(LinuxNative.SECCOMP_RET_ALLOW, filter[4 + n].k)
    }

    @Test
    fun `last instruction is deny with EPERM`() {
        val policy = Policy.NO_EXEC
        val n = policy.blockedSyscalls(arch).size
        val filter = BpfFilter.build(arch, policy)
        val last = filter[5 + n]
        assertEquals(0x06.toShort(), last.code)
        assertEquals(LinuxNative.SECCOMP_RET_ERRNO or LinuxNative.EPERM, last.k)
    }

    @Test
    fun `blocked syscall JEQ instructions jump directly to fail block`() {
        val policy = Policy.NO_EXEC
        val blocked = policy.blockedSyscalls(arch)
        val n = blocked.size
        val filter = BpfFilter.build(arch, policy)

        for (i in 0 until n) {
            val insn = filter[4 + i]
            // code = BPF_JMP|BPF_JEQ|BPF_K = 0x15
            assertEquals(0x15.toShort(), insn.code, "insn[${ 4 + i }] wrong opcode")
            assertEquals(blocked[i], insn.k, "insn[${4 + i}] wrong syscall nr")
            // jt should jump over remaining checks + ALLOW to land on DENY
            // jt = n - i
            assertEquals((n - i).toByte(), insn.jt, "insn[${4 + i}] wrong jt")
            // jf = 0 (fall through to next check)
            assertEquals(0, insn.jf)
        }
    }

    @Test
    fun `filter is accepted by the kernel (BPF verifier)`() {
        // Installing a filter requires PR_SET_NO_NEW_PRIVS first; skip if not Linux
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val errorRef = java.util.concurrent.atomic.AtomicReference<Throwable>(null)
        val thread = Thread {
            try {
                val filter = BpfFilter.build(Arch.current(), Policy.NO_EXEC)
                // Attempt to install — kernel BPF verifier will reject a malformed program
                java.lang.foreign.Arena.ofConfined().use { arena ->
                    val prog = LinuxNative.newSockFProg(arena, filter)
                    val r0 = LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                    assertTrue(r0.returnValue == 0, "PR_SET_NO_NEW_PRIVS failed: ${LinuxNative.strerror(r0.errno)}")
                    val r = LinuxNative.prctl(LinuxNative.PR_SET_SECCOMP, LinuxNative.SECCOMP_MODE_FILTER.toLong(), prog, 0, 0)
                    assertTrue(r.returnValue == 0, "prctl(PR_SET_SECCOMP) rejected filter: ${LinuxNative.strerror(r.errno)}")
                }
            } catch (t: Throwable) {
                errorRef.set(t)
            }
        }
        thread.start()
        thread.join()
        errorRef.get()?.let { throw it }
    }
}
