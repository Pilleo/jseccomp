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
        policy: Policy<*, *>,
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

        val inspections = getInspections(
            arch,
            syscallActions,
            defaultAction,
            jvmCriticalNrs,
            allowMmapExec,
            allowNonThreadClone,
            allowUnsafePrctl,
        )
        emitInspections(builder, inspections, profilingMode, handledNrs)

        // clone3 -> Always ENOSYS (does not need argument inspection)
        if (arch.clone3 >= 0) {
            val enosysAction = NativeConstants.SECCOMP_RET_ERRNO or 38
            handledNrs.add(arch.clone3)
            builder.jumpIfEqual(arch.clone3, jt = "clone3_match", jf = "clone3_skip")
            builder.label("clone3_match")
            builder.ret(enosysAction)
            builder.label("clone3_skip")
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
                        Syscall.RT_SIGPROCMASK.numberFor(arch),
        ).filter { it >= 0 }.toSet()

    private fun emitArchCheck(
        builder: BpfProgram.Builder,
        arch: Arch,
    ) {
        builder.loadAbsolute(SECCOMP_DATA_ARCH_OFFSET)
        builder.jumpIfEqual(arch.audit, jt = "arch_ok", jf = "arch_fail")
        builder.label("arch_fail")
        builder.ret(NativeConstants.SECCOMP_RET_KILL_THREAD)
        builder.label("arch_ok")
    }

    private fun getInspections(
        arch: Arch,
        syscallActions: Map<Int, SeccompAction>,
        defaultAction: SeccompAction,
        jvmCriticalNrs: Set<Int>,
        allowMmapExec: Boolean,
        allowNonThreadClone: Boolean,
        allowUnsafePrctl: Boolean,
    ): List<io.mazewall.seccomp.SyscallInspection> {
        val list = mutableListOf<io.mazewall.seccomp.SyscallInspection>()

        if (!allowMmapExec) {
            listOf(arch.mmap, arch.mprotect, arch.pkeyMprotect).forEach { nr ->
                if (nr >= 0) {
                    val mappedAction = syscallActions[nr] ?: defaultAction
                    val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else mappedAction
                    list.add(
                        io.mazewall.seccomp.SyscallInspection(
                            syscallNumber = nr,
                            argIndex = 2,
                            check = io.mazewall.seccomp.ArgCheck
                                .MaskEquals(0x04L, 0x00L),
                            ifMatched = effectiveAction,
                            ifNotMatched = SeccompAction.ACT_ERRNO,
                        ),
                    )
                }
            }
        }

        if (!allowNonThreadClone && arch.clone >= 0) {
            val nr = arch.clone
            val mappedAction = syscallActions[nr] ?: defaultAction
            val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else mappedAction
            list.add(
                io.mazewall.seccomp.SyscallInspection(
                    syscallNumber = nr,
                    argIndex = 0,
                    check = io.mazewall.seccomp.ArgCheck
                        .MaskEquals(0x00010100L, 0x00010100L),
                    ifMatched = effectiveAction,
                    ifNotMatched = SeccompAction.ACT_ERRNO,
                ),
            )
        }

        if (!allowUnsafePrctl && arch.prctl >= 0) {
            val nr = arch.prctl
            val mappedAction = syscallActions[nr] ?: defaultAction
            val effectiveAction = if (nr in jvmCriticalNrs) SeccompAction.ACT_ALLOW else mappedAction
            list.add(
                io.mazewall.seccomp.SyscallInspection(
                    syscallNumber = nr,
                    argIndex = 0,
                    check = io.mazewall.seccomp.ArgCheck
                        .EqualsAny(listOf(15L, 16L, 21L, 22L, 38L, 39L)),
                    ifMatched = effectiveAction,
                    ifNotMatched = SeccompAction.ACT_ERRNO,
                ),
            )
        }

        return list
    }

    internal fun emitInspections(
        builder: BpfProgram.Builder,
        inspections: List<io.mazewall.seccomp.SyscallInspection>,
        profilingMode: Boolean,
        handledNrs: MutableSet<Int>,
    ) {
        for ((idx, inspection) in inspections.withIndex()) {
            val nr = inspection.syscallNumber
            handledNrs.add(nr)

            val ifMatchedNative = resolveNativeAction(inspection.ifMatched, profilingMode)
            val ifNotMatchedNative = resolveNativeAction(inspection.ifNotMatched, profilingMode)

            val labelPrefix = "inspect_${nr}_$idx"
            builder.jumpIfEqual(nr, jt = "${labelPrefix}_match", jf = "${labelPrefix}_skip")
            builder.label("${labelPrefix}_match")

            builder.loadAbsolute(SECCOMP_DATA_ARGS_OFFSET + inspection.argIndex * 8)

            when (val check = inspection.check) {
                is io.mazewall.seccomp.ArgCheck.EqualsAny -> {
                    check.allowedValues.forEachIndexed { valIdx, value ->
                        builder.jumpIfEqual(value.toInt(), jt = "${labelPrefix}_allow", jf = null)
                    }
                    builder.ret(ifNotMatchedNative)
                    builder.label("${labelPrefix}_allow")
                    builder.ret(ifMatchedNative)
                }
                is io.mazewall.seccomp.ArgCheck.MaskEquals -> {
                    builder.and(check.mask.toInt())
                    builder.jumpIfEqual(check.expected.toInt(), jt = "${labelPrefix}_allow", jf = "${labelPrefix}_deny")
                    builder.label("${labelPrefix}_deny")
                    builder.ret(ifNotMatchedNative)
                    builder.label("${labelPrefix}_allow")
                    builder.ret(ifMatchedNative)
                }
            }
            builder.label("${labelPrefix}_skip")
        }
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
                    val label = "scan_$nr"
                    builder.jumpIfEqual(nr, jt = "${label}_match", jf = "${label}_skip")
                    builder.label("${label}_match")
                    builder.ret(nativeAction)
                    builder.label("${label}_skip")
                }
            }
        }

        // Inject the JVM Immutable Base for restrictive default actions (Whitelists)
        if (defaultNativeAction != NativeConstants.SECCOMP_RET_ALLOW) {
            for (nr in jvmCriticalNrs.sorted()) {
                if (nr in handledNrs) continue
                handledNrs.add(nr)

                val label = "critical_$nr"
                builder.jumpIfEqual(nr, jt = "${label}_match", jf = "${label}_skip")
                builder.label("${label}_match")
                builder.ret(NativeConstants.SECCOMP_RET_ALLOW)
                builder.label("${label}_skip")
            }
        }
    }
}
