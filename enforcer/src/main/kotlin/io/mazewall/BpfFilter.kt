package io.mazewall

import io.mazewall.ffi.Layouts
import java.lang.foreign.MemoryLayout
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

    private val SECCOMP_DATA_NR_OFFSET = Layouts.SECCOMP_DATA.byteOffset(MemoryLayout.PathElement.groupElement("nr")).toInt()
    private val SECCOMP_DATA_ARCH_OFFSET = Layouts.SECCOMP_DATA.byteOffset(MemoryLayout.PathElement.groupElement("arch")).toInt()
    private val SECCOMP_DATA_ARGS_OFFSET = Layouts.SECCOMP_DATA.byteOffset(MemoryLayout.PathElement.groupElement("args")).toInt()
    private val SECCOMP_ARGS2_OFFSET = Layouts.SECCOMP_DATA
        .byteOffset(
            MemoryLayout.PathElement.groupElement("args"),
            MemoryLayout.PathElement.sequenceElement(2),
        ).toInt()

    fun build(
        arch: Arch,
        policy: Policy,
        profilingMode: Boolean = false,
    ): Array<SockFilter> =
        buildFromActions(
            arch,
            policy.syscallActionNumbers(arch),
            policy.defaultAction,
            policy.allowMmapExec,
            policy.allowNonThreadClone,
            policy.allowUnsafePrctl,
            profilingMode,
        )

    private fun resolveNativeAction(
        action: SeccompAction,
        profilingMode: Boolean,
    ): Int {
        return when (action) {
            SeccompAction.ACT_KILL_PROCESS -> LinuxNative.SECCOMP_RET_KILL_PROCESS
            SeccompAction.ACT_KILL_THREAD -> LinuxNative.SECCOMP_RET_KILL_THREAD
            SeccompAction.ACT_TRAP -> LinuxNative.SECCOMP_RET_TRAP
            SeccompAction.ACT_ERRNO -> if (profilingMode) {
                LinuxNative.SECCOMP_RET_USER_NOTIF
            } else {
                (LinuxNative.SECCOMP_RET_ERRNO or LinuxNative.EPERM)
            }
            SeccompAction.ACT_NOTIFY -> LinuxNative.SECCOMP_RET_USER_NOTIF
            SeccompAction.ACT_LOG -> LinuxNative.SECCOMP_RET_LOG
            SeccompAction.ACT_ALLOW -> LinuxNative.SECCOMP_RET_ALLOW
        }
    }

    /**
     * Constructs the BPF bytecode using a linear scan approach.
     */
    internal fun buildFromActions(
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        allowMmapExec: Boolean = false,
        allowNonThreadClone: Boolean = false,
        allowUnsafePrctl: Boolean = false,
        profilingMode: Boolean = false,
    ): Array<SockFilter> {
        val filters = mutableListOf<SockFilter>()
        val defaultNativeAction = resolveNativeAction(defaultAction, profilingMode)

        // Syscalls absolutely required for safepoints, GC, and thread stability.
        val jvmCriticalNrs = getJvmCriticalNrs(arch)

        // 1. Check Architecture
        emitArchCheck(filters, arch)

        // 2. Load Syscall Number
        filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_NR_OFFSET))

        // 3. Special Syscall Argument Checks
        val handledNrs = mutableSetOf<Int>()

        if (!allowMmapExec) {
            emitMmapInspections(filters, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        if (!allowNonThreadClone) {
            emitCloneInspections(filters, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        if (!allowUnsafePrctl) {
            emitPrctlInspections(filters, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        // 4. Block-based checks (Linear Scan)
        emitLinearScan(filters, syscallActions, jvmCriticalNrs, profilingMode, defaultNativeAction, handledNrs)

        // 5. Default Action
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, defaultNativeAction))

        return filters.toTypedArray()
    }

    private fun getJvmCriticalNrs(arch: Arch): Set<Int> =
        setOf(
            Syscall.FUTEX.numberFor(arch),
            Syscall.SCHED_YIELD.numberFor(arch),
            Syscall.RT_SIGRETURN.numberFor(arch),
            Syscall.RT_SIGACTION.numberFor(arch),
            Syscall.MADVISE.numberFor(arch),
            Syscall.GETTID.numberFor(arch),
            Syscall.CLOSE.numberFor(arch),
        ).filter { it >= 0 }.toSet()

    private fun emitArchCheck(
        filters: MutableList<SockFilter>,
        arch: Arch,
    ) {
        filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARCH_OFFSET))
        // If arch matches, skip 1 instruction (the ret kill)
        filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, arch.audit))
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, LinuxNative.SECCOMP_RET_KILL_THREAD))
    }

    private fun emitMmapInspections(
        filters: MutableList<SockFilter>,
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        listOf(arch.mmap, arch.mprotect, arch.pkeyMprotect).forEach { nr ->
            if (nr >= 0) {
                handledNrs.add(nr)
                filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 4, nr))
                filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_ARGS2_OFFSET))
                filters.add(SockFilter((BPF_JMP or BPF_JSET or BPF_K).toShort(), 0, 1, 0x04))
                val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
                filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyNative))
                emitInspectionResult(filters, nr, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
            }
        }
    }

    private fun emitCloneInspections(
        filters: MutableList<SockFilter>,
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        if (arch.clone >= 0) {
            handledNrs.add(arch.clone)
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 5, arch.clone))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARGS_OFFSET))
            filters.add(SockFilter((BPF_ALU or BPF_AND or BPF_K).toShort(), 0, 0, 0x00010100))
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, 0x00010100))
            val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyNative))
            emitInspectionResult(filters, arch.clone, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
        }

        // clone3 -> Always ENOSYS
        if (arch.clone3 >= 0) {
            val enosysAction = LinuxNative.SECCOMP_RET_ERRNO or 38
            handledNrs.add(arch.clone3)
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, arch.clone3))
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, enosysAction))
        }
    }

    private fun emitPrctlInspections(
        filters: MutableList<SockFilter>,
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        if (arch.prctl >= 0) {
            handledNrs.add(arch.prctl)
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 9, arch.prctl))
            filters.add(SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, SECCOMP_DATA_ARGS_OFFSET))
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 6, 0, 15)) // PR_SET_NAME
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 5, 0, 16)) // PR_GET_NAME
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 4, 0, 21)) // PR_GET_SECCOMP
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 3, 0, 22)) // PR_SET_SECCOMP
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 2, 0, 38)) // PR_SET_NO_NEW_PRIVS
            filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 1, 0, 39)) // PR_GET_NO_NEW_PRIVS
            val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
            filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, denyNative))
            emitInspectionResult(filters, arch.prctl, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
        }
    }

    private fun emitInspectionResult(
        filters: MutableList<SockFilter>,
        nr: Int,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
    ) {
        val mappedAction = syscallActions[nr] ?: defaultAction
        val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else mappedAction
        val nativeAction = resolveNativeAction(effectiveAction, profilingMode)
        filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, nativeAction))
    }

    private fun emitLinearScan(
        filters: MutableList<SockFilter>,
        syscallActions: Map<Int, SeccompAction>,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        defaultNativeAction: Int,
        handledNrs: MutableSet<Int>,
    ) {
        for ((nr, action) in syscallActions.entries.sortedBy { it.key }) {
            if (nr !in handledNrs) {
                handledNrs.add(nr)

                val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else action
                val nativeAction = resolveNativeAction(effectiveAction, profilingMode)

                if (nativeAction != defaultNativeAction) {
                    filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, nr))
                    filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, nativeAction))
                }
            }
        }

        // Inject the JVM Immutable Base for restrictive default actions (Whitelists)
        if (defaultNativeAction != LinuxNative.SECCOMP_RET_ALLOW) {
            for (nr in jvmCriticalNrs.sorted()) {
                if (nr in handledNrs) continue
                handledNrs.add(nr)
                filters.add(SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, nr))
                filters.add(SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, LinuxNative.SECCOMP_RET_ALLOW))
            }
        }
    }
}
