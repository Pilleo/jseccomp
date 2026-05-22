package io.contained

import java.util.logging.Logger

/**
 * Builds seccomp-bpf programs using a robust strictly-forward linear scan approach.
 * This avoids all jump offset overflow and backward-jump issues.
 */
object BpfFilter {
    private val logger = Logger.getLogger(BpfFilter::class.java.name)

    private const val BPF_LD = 0x00
    private const val BPF_JMP = 0x05
    private const val BPF_RET = 0x06
    private const val BPF_W = 0x00
    private const val BPF_ABS = 0x20
    private const val BPF_JEQ = 0x10
    private const val BPF_JSET = 0x40
    private const val BPF_K = 0x00
    private const val BPF_ALU = 0x04
    private const val BPF_AND = 0x50

    private const val SECCOMP_DATA_NR_OFFSET = 0
    private const val SECCOMP_DATA_ARCH_OFFSET = 4
    private const val SECCOMP_DATA_ARGS_OFFSET = 16
    private const val SECCOMP_ARGS2_OFFSET = SECCOMP_DATA_ARGS_OFFSET + 16 // args[2] byte offset

    fun build(arch: Arch, policy: Policy, profilingMode: Boolean = false): Array<SockFilter> =
        buildFromNumbers(
            arch, 
            policy.blockedSyscalls(arch), 
            policy.allowMmapExec, 
            policy.allowNonThreadClone,
            policy.allowUnsafePrctl,
            profilingMode
        )

    /**
     * Constructs the BPF bytecode using a linear scan approach.
     * 
     * ### Performance Rationale
     * While an O(log N) Binary Search Tree (BST) is theoretically faster for large sets, 
     * we intentionally use a linear scan (O(N)) here for several reasons:
     * 1. **Simplicity:** The logic is trivial to audit and maintain.
     * 2. **Jump Limits:** BPF jump offsets are limited to 8 bits (max 255 instructions). 
     *    A BST for a large syscall list can easily exceed this limit, leading to 
     *    complex instruction reordering requirements.
     * 3. **Practicality:** Most security policies (e.g. blocking process execution or 
     *    network) only target <10 syscalls. Even a heavy policy like [Policy.PURE_COMPUTE] 
     *    only targets ~40 syscalls, which results in ~80 BPF instructions—well within 
     *    both performance and jump limit budgets.
     */
    internal fun buildFromNumbers(
        arch: Arch, 
        blocked: IntArray, 
        allowMmapExec: Boolean = false, 
        allowNonThreadClone: Boolean = false,
        allowUnsafePrctl: Boolean = false,
        profilingMode: Boolean = false
    ): Array<SockFilter> {
        val filters = mutableListOf<SockFilter>()
        val denyAction = if (profilingMode) LinuxNative.SECCOMP_RET_USER_NOTIF else (LinuxNative.SECCOMP_RET_ERRNO or LinuxNative.EPERM)
        val allowAction = LinuxNative.SECCOMP_RET_ALLOW
        val enosysAction = LinuxNative.SECCOMP_RET_ERRNO or 38

        // 1. Check Architecture
        filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARCH_OFFSET))
        // If arch matches, skip 1 instruction (the ret kill/deny)
        filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, arch.audit))
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))

        // 2. Load Syscall Number
        filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET))

        // 3. Special Syscall Argument Checks
        // mmap
        if (!allowMmapExec) {
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 4, arch.mmap))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_ARGS2_OFFSET))
            // BPF_JSET: jt=0 -> if (ACC & 0x04) != 0 (PROT_EXEC set): execute next instr (RET_DENY)
            //           jf=1 -> if (ACC & 0x04) == 0 (PROT_EXEC not set): skip 1 instr (the RET_DENY)
            filters.add(SockFilter((BPF_JMP or BPF_JSET or BPF_K).toShort(), 0, 1, 0x04)) 
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET)) // Restore NR

            // mprotect
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 4, arch.mprotect))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_ARGS2_OFFSET))
            // BPF_JSET: jt=0 -> if (ACC & 0x04) != 0 (PROT_EXEC set): execute next instr (RET_DENY)
            //           jf=1 -> if (ACC & 0x04) == 0 (PROT_EXEC not set): skip 1 instr (the RET_DENY)
            filters.add(SockFilter((BPF_JMP or BPF_JSET or BPF_K).toShort(), 0, 1, 0x04)) 
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET))
        }

        // clone
        if (!allowNonThreadClone) {
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 5, arch.clone))
            // Note: BPF_LD | BPF_W | BPF_ABS only loads a 32-bit word. On 64-bit kernels, seccomp_data.args[]
            // are 64-bit values. For clone flags, they are in the lower 32 bits, so 32-bit truncation here is safe.
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARGS_OFFSET))
            // AND the flags with our mask (CLONE_VM | CLONE_THREAD)
            filters.add(SockFilter((BPF_ALU or BPF_AND or BPF_K).toShort(), 0, 0, 0x00010100)) 
            // JEQ: if result equals the mask (both bits are set), skip 1 (the ret deny)
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, 0x00010100)) 
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET))
        }

        // clone3
        filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, arch.clone3))
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, enosysAction))

        // prctl argument-inspection
        if (!allowUnsafePrctl && arch.prctl >= 0) {
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 9, arch.prctl))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARGS_OFFSET))
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 6, 0, 15)) // PR_SET_NAME
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 5, 0, 16)) // PR_GET_NAME
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 4, 0, 21)) // PR_GET_SECCOMP
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 3, 0, 22)) // PR_SET_SECCOMP
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 2, 0, 38)) // PR_SET_NO_NEW_PRIVS
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, 39)) // PR_GET_NO_NEW_PRIVS
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET))
        }

        // 4. Block-based checks (Linear Scan)
        // Since BPF jump offsets are only 8-bit (max 255), and we have ~100 syscalls, 
        // a linear scan with individual RETs is safe and simple.
        val argInspectedNrs = setOf(arch.mmap, arch.mprotect, arch.clone, arch.clone3, arch.prctl).filter { it >= 0 }.toSet()
        for (nr in blocked.sortedArray()) {
            if (nr in argInspectedNrs) continue // already handled by argument inspection or special rules
            // If nr matches, skip 1 (don't ret allow), hit ret deny
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, nr))
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyAction))
        }

        // 5. Default Allow
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, allowAction))

        return filters.toTypedArray()
    }
}
