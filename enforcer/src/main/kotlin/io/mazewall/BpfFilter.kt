package io.mazewall

import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import io.mazewall.seccomp.BpfProgram
import java.lang.foreign.MemoryLayout
import java.util.logging.Logger

/**
 * Builds seccomp-bpf programs using a robust strictly-forward linear scan approach.
 * This avoids all jump offset overflow and backward-jump issues.
 */
object BpfFilter {
    private val logger = Logger.getLogger(BpfFilter::class.java.name)

    private const val SECCOMP_DATA_NR_OFFSET = 0
    private const val SECCOMP_DATA_ARCH_OFFSET = 4
    private val SECCOMP_ARGS2_OFFSET = Layouts.SECCOMP_DATA
        .byteOffset(
            MemoryLayout.PathElement.groupElement("args"),
            MemoryLayout.PathElement.sequenceElement(2),
        ).toInt()
    private val SECCOMP_DATA_ARGS_OFFSET = Layouts.SECCOMP_DATA
        .byteOffset(
            MemoryLayout.PathElement.groupElement("args"),
            MemoryLayout.PathElement.sequenceElement(0),
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
            SeccompAction.ACT_KILL_PROCESS -> NativeConstants.SECCOMP_RET_KILL_PROCESS
            SeccompAction.ACT_KILL_THREAD -> NativeConstants.SECCOMP_RET_KILL_THREAD
            SeccompAction.ACT_TRAP -> NativeConstants.SECCOMP_RET_TRAP
            SeccompAction.ACT_ERRNO -> if (profilingMode) {
                NativeConstants.SECCOMP_RET_USER_NOTIF
            } else {
                (NativeConstants.SECCOMP_RET_ERRNO or NativeConstants.EPERM)
            }
            SeccompAction.ACT_NOTIFY -> NativeConstants.SECCOMP_RET_USER_NOTIF
            SeccompAction.ACT_LOG -> NativeConstants.SECCOMP_RET_LOG
            SeccompAction.ACT_ALLOW -> NativeConstants.SECCOMP_RET_ALLOW
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
        val builder = BpfProgram.builder()
        val defaultNativeAction = resolveNativeAction(defaultAction, profilingMode)

        // Syscalls absolutely required for safepoints, GC, and thread stability.
        val jvmCriticalNrs = getJvmCriticalNrs(arch)

        // 1. Check Architecture
        emitArchCheck(builder, arch)

        // 2. Load Syscall Number
        builder.loadAbsolute(SECCOMP_DATA_NR_OFFSET)

        // 3. Special Syscall Argument Checks
        val handledNrs = mutableSetOf<Int>()

        if (!allowMmapExec) {
            emitMmapInspections(builder, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        if (!allowNonThreadClone) {
            emitCloneInspections(builder, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        if (!allowUnsafePrctl) {
            emitPrctlInspections(builder, arch, syscallActions, defaultAction, jvmCriticalNrs, profilingMode, handledNrs)
        }

        // 4. Block-based checks (Linear Scan)
        emitLinearScan(builder, syscallActions, jvmCriticalNrs, profilingMode, defaultNativeAction, handledNrs)

        // 5. Default Action
        builder.ret(defaultNativeAction)

        return builder.build().instructions
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
        builder: BpfProgram.Builder,
        arch: Arch,
    ) {
        builder.loadAbsolute(SECCOMP_DATA_ARCH_OFFSET)
        // If arch matches, skip 1 instruction (the ret kill)
        builder.jumpIfEqual(arch.audit, 1, 0)
        builder.ret(NativeConstants.SECCOMP_RET_KILL_THREAD)
    }

    private fun emitMmapInspections(
        builder: BpfProgram.Builder,
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
                builder.jumpIfEqual(nr, 0, 4)
                builder.loadAbsolute(SECCOMP_ARGS2_OFFSET)
                builder.jumpIfSet(0x04, 0, 1)
                val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
                builder.ret(denyNative)
                emitInspectionResult(builder, nr, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
            }
        }
    }

    private fun emitCloneInspections(
        builder: BpfProgram.Builder,
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        if (arch.clone >= 0) {
            handledNrs.add(arch.clone)
            builder.jumpIfEqual(arch.clone, 0, 5)
            builder.loadAbsolute(SECCOMP_DATA_ARGS_OFFSET)
            builder.and(0x00010100)
            builder.jumpIfEqual(0x00010100, 1, 0)
            val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
            builder.ret(denyNative)
            emitInspectionResult(builder, arch.clone, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
        }

        // clone3 -> Always ENOSYS
        if (arch.clone3 >= 0) {
            val enosysAction = NativeConstants.SECCOMP_RET_ERRNO or 38
            handledNrs.add(arch.clone3)
            builder.jumpIfEqual(arch.clone3, 0, 1)
            builder.ret(enosysAction)
        }
    }

    private fun emitPrctlInspections(
        builder: BpfProgram.Builder,
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        if (arch.prctl >= 0) {
            handledNrs.add(arch.prctl)
            builder.jumpIfEqual(arch.prctl, 0, 9)
            builder.loadAbsolute(SECCOMP_DATA_ARGS_OFFSET)
            builder.jumpIfEqual(15, 6, 0) // PR_SET_NAME
            builder.jumpIfEqual(16, 5, 0) // PR_GET_NAME
            builder.jumpIfEqual(21, 4, 0) // PR_GET_SECCOMP
            builder.jumpIfEqual(22, 3, 0) // PR_SET_SECCOMP
            builder.jumpIfEqual(38, 2, 0) // PR_SET_NO_NEW_PRIVS
            builder.jumpIfEqual(39, 1, 0) // PR_GET_NO_NEW_PRIVS
            val denyNative = resolveNativeAction(SeccompAction.ACT_ERRNO, profilingMode)
            builder.ret(denyNative)
            emitInspectionResult(builder, arch.prctl, syscallActions, defaultAction, jvmCriticalNrs, profilingMode)
        }
    }

    private fun emitInspectionResult(
        builder: BpfProgram.Builder,
        nr: Int,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        profilingMode: Boolean,
    ) {
        val mappedAction = syscallActions[nr] ?: defaultAction
        val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else mappedAction
        val nativeAction = resolveNativeAction(effectiveAction, profilingMode)
        builder.ret(nativeAction)
    }

    private fun emitLinearScan(
        builder: BpfProgram.Builder,
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
                    builder.jumpIfEqual(nr, 0, 1)
                    builder.ret(nativeAction)
                }
            }
        }

        // Inject the JVM Immutable Base for restrictive default actions (Whitelists)
        if (defaultNativeAction != NativeConstants.SECCOMP_RET_ALLOW) {
            for (nr in jvmCriticalNrs.sorted()) {
                if (nr in handledNrs) continue
                handledNrs.add(nr)
                builder.jumpIfEqual(nr, 0, 1)
                builder.ret(NativeConstants.SECCOMP_RET_ALLOW)
            }
        }
    }
}
