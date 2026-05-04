package io.contained

/**
 * Builds a seccomp-bpf filter program from an [Arch] and a [Policy].
 *
 * The generated program follows the standard structure:
 * 1. **Prologue**: verify the current CPU architecture matches [arch].
 * 2. **Range check**: reject any syscall number above [Arch.limit].
 * 3. **Policy checks**: block each syscall in the policy with SECCOMP_RET_ERRNO|EPERM.
 * 4. **Epilogue**: allow all remaining syscalls.
 *
 * Jump offsets are computed analytically so that every blocked syscall check
 * jumps directly to the single "deny" instruction at the end of the program.
 */
object BpfFilter {

    // BPF instruction class/size/mode bit-fields
    private const val BPF_LD  = 0x00
    private const val BPF_JMP = 0x05
    private const val BPF_RET = 0x06
    private const val BPF_W   = 0x00
    private const val BPF_ABS = 0x20
    private const val BPF_JEQ = 0x10
    private const val BPF_JGT = 0x20
    private const val BPF_K   = 0x00

    // Byte offsets into the seccomp_data struct passed to BPF by the kernel
    private const val SECCOMP_DATA_NR_OFFSET   = 0
    private const val SECCOMP_DATA_ARCH_OFFSET  = 4

    private fun stmt(code: Int, k: Int) =
        SockFilter(code.toShort(), 0, 0, k)

    private fun jump(code: Int, k: Int, jt: Int, jf: Int) =
        SockFilter(code.toShort(), jt.toByte(), jf.toByte(), k)

    /**
     * Builds a filter for [arch] blocking every syscall listed in [policy].
     *
     * Program layout (indices with N = blockedSyscalls.size):
     * ```
     * [0]         LD  arch field (offset 4)
     * [1]         JEQ audit_arch, jt=0, jf=(N+3)  → wrong arch → fail
     * [2]         LD  nr field   (offset 0)
     * [3]         JGT limit,     jt=(N+1), jf=0   → nr too high → fail
     * [4..3+N]    JEQ blocked[i],jt=(N-i), jf=0   → blocked nr  → fail
     * [4+N]       RET ALLOW
     * [5+N]       RET ERRNO|EPERM   ← single fail target
     * ```
     */
    fun build(arch: Arch, policy: Policy): Array<SockFilter> {
        val blocked = policy.blockedSyscalls(arch)
        val n = blocked.size
        val insns = mutableListOf<SockFilter>()

        // [0] Load arch field
        insns.add(stmt(BPF_LD or BPF_W or BPF_ABS, SECCOMP_DATA_ARCH_OFFSET))

        // [1] Arch check — mismatch jumps to fail block at [5+n]
        //     jf = (5+n) - 1 - 1 = n+3
        insns.add(jump(BPF_JMP or BPF_JEQ or BPF_K, arch.audit, jt = 0, jf = n + 3))

        // [2] Load syscall number
        insns.add(stmt(BPF_LD or BPF_W or BPF_ABS, SECCOMP_DATA_NR_OFFSET))

        // [3] Range check — syscall number > limit jumps to fail block at [5+n]
        //     jt = (5+n) - 3 - 1 = n+1
        insns.add(jump(BPF_JMP or BPF_JGT or BPF_K, arch.limit, jt = n + 1, jf = 0))

        // [4..3+n] Blocked syscall checks — match jumps to fail block at [5+n]
        //     from [4+i]: jt = (5+n) - (4+i) - 1 = n - i
        for (i in 0 until n) {
            insns.add(jump(BPF_JMP or BPF_JEQ or BPF_K, blocked[i], jt = n - i, jf = 0))
        }

        // [4+n] Allow — all remaining syscalls are permitted
        insns.add(stmt(BPF_RET or BPF_K, LinuxNative.SECCOMP_RET_ALLOW))

        // [5+n] Deny — return EPERM to the caller
        insns.add(stmt(BPF_RET or BPF_K, LinuxNative.SECCOMP_RET_ERRNO or LinuxNative.EPERM))

        return insns.toTypedArray()
    }
}
