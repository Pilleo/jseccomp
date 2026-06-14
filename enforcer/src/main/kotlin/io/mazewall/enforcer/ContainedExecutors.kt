package io.mazewall.enforcer

import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.PolicyScope
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.enforcer.internal.ContainedExecutorWrapper
import io.mazewall.landlock.Landlock
import io.mazewall.seccomp.PureJavaBpfEngine
import java.util.concurrent.ExecutorService
import java.util.logging.Logger

/**
 * Public API for wrapping an existing [java.util.concurrent.ExecutorService] to enforce seccomp containment.
 *
 * ### Security & Scope
 * Seccomp is a "blast radius" mitigator for I/O and execution. It is **not** a replacement
 * for internal Java security boundaries (like module exports) or data isolation. A contained
 * thread can still read the heap and any static variables it has access to. For resource
 * isolation (CPU, memory), use Linux cgroups.
 *
 * ### Filesystem Containment and Class Loading
 * [io.mazewall.Policy.Companion.PURE_COMPUTE] uses Landlock for filesystem enforcement and does
 * NOT block `openat`/`open` at the seccomp level. The JVM can load classes lazily from the
 * classpath without interference, as long as classpath paths are included via
 * [io.mazewall.Policy.Builder.allowJvmClasspath].
 *
 * [io.mazewall.Policy.Companion.PURE_COMPUTE_UNSAFE] is deprecated. It blocks `openat`/`open`
 * at the seccomp level, which prevents lazy class loading on the sandboxed thread. Only use it
 * when ALL classes needed by the task are guaranteed to be loaded before containment is applied.
 */
object ContainedExecutors {
    private val logger = Logger.getLogger(ContainedExecutors::class.java.name)
    private val processLock = Any()

    /**
     * Installs the given policies onto the current thread immediately.
     *
     * ### Virtual Thread Warning
     * Seccomp filters are per-thread. Virtual threads multiplex onto a small pool of OS
     * "carrier" threads. Installing a filter from within a virtual thread would sandbox
     * the carrier, inadvertently affecting all other virtual threads scheduled on it.
     * To prevent this "carrier contamination", this method throws [IllegalStateException]
     * if called from a virtual thread.
     */
    fun installOnCurrentThread(vararg policies: Policy<*, *>) {
        installInternal(false, *policies)
    }

    /**
     * Installs the given policies onto the entire process (all threads) immediately.
     * This acts as a global security lockdown and cannot be undone. All future threads
     * created by this process will inherit these restrictions.
     */
    fun installOnProcess(vararg policies: Policy<PolicyScope.ProcessWideSafe, *>) {
        installInternal(true, *policies)
    }

    /**
     * Wraps an [java.util.concurrent.ExecutorService] so that any task submitted to it will have the given
     * [policies] applied before execution.
     */
    fun wrap(
        delegate: ExecutorService,
        vararg policies: Policy<*, *>,
    ): ExecutorService {
        val combinedPolicy = Policy.combine(*policies)
        return ContainedExecutorWrapper(delegate, combinedPolicy)
    }

    private fun installInternal(
        processWide: Boolean,
        vararg policies: Policy<*, *>,
    ) {
        if (Thread.currentThread().isVirtual) {
            throw IllegalStateException(
                "Attempted to apply seccomp containment inside a virtual thread. " +
                        "Use a dedicated platform thread pool and install containment on its carrier threads instead.",
            )
        }
        val combinedPolicy = Policy.combine(*policies)
        applyLandlockIfNecessary(processWide, combinedPolicy)

        if (!Platform.isSupported()) {
            handleUnsupportedPlatform()
            return
        }

        installSeccompFilter(processWide, combinedPolicy)
    }

    private fun installSeccompFilter(
        processWide: Boolean,
        combinedPolicy: Policy<*, *>,
    ) {
        synchronized(processLock) {
            val state = resolveCurrentState()
            val plan = FilterInstallationPlanner.calculateNewFilter(combinedPolicy, state)

            if (plan.needsNewFilter) {
                FilterInstallationPlanner.verifyFilterDepth(state.currentDepth)
                applyBpfFilter(processWide, plan.toInstall, plan.newBlocks, plan.newDefaultAction)
            }
        }
    }

    private fun applyLandlockIfNecessary(
        processWide: Boolean,
        policy: Policy<*, *>,
    ) {
        if (!needsLandlock(policy)) return

        if (processWide) {
            throw UnsupportedOperationException(
                "Process-wide containment (installOnProcess) does not support Landlock filesystem rules. " +
                        "Use thread-scoped containment (installOnCurrentThread) for filesystem restrictions.",
            )
        }

        val appliedReads = ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_READS.get()
        val appliedWrites = ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_WRITES.get()

        if (appliedReads != null && appliedWrites != null) {
            // Assert that we are not trying to expand Landlock filesystem permissions on nested containment
            val readsSubset = isPathSubset(appliedReads, policy.allowedFsReadPaths)
            val writesSubset = isPathSubset(appliedWrites, policy.allowedFsWritePaths)
            if (!readsSubset || !writesSubset) {
                throw IllegalStateException("Cannot expand Landlock filesystem permissions on an already restricted thread.")
            }
        }

        if (appliedReads != policy.allowedFsReadPaths || appliedWrites != policy.allowedFsWritePaths) {
            Landlock.applyRuleset(policy)
            ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_READS.set(policy.allowedFsReadPaths)
            ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_WRITES.set(policy.allowedFsWritePaths)
        }
    }

    private fun needsLandlock(policy: Policy<*, *>) =
        policy.allowedFsReadPaths.isNotEmpty() ||
                policy.allowedFsWritePaths.isNotEmpty() ||
                policy.isSyscallAllowed(Syscall.IO_URING_SETUP)

    private fun isPathSubset(
        parentPaths: Set<String>,
        childPaths: Set<String>,
    ): Boolean {
        if (childPaths.isEmpty()) return true
        val parents = parentPaths.map {
            java.nio.file.Paths
            .get(it)
            .toAbsolutePath()
            .normalize()
        }
        return parents.isNotEmpty() &&
            childPaths.all { childStr ->
                val child = java.nio.file.Paths
                    .get(childStr)
                    .toAbsolutePath()
                    .normalize()
                parents.any { parent -> child.startsWith(parent) }
            }
    }

    private fun handleUnsupportedPlatform() {
        val fallback = Platform.configuredFallback()
        when (fallback) {
            Platform.FallbackBehavior.FAIL ->
                throw UnsupportedOperationException("Platform does not support seccomp")

            Platform.FallbackBehavior.WARN_AND_BYPASS ->
                logger.warning("Platform does not support seccomp. Code will run uncontained.")

            Platform.FallbackBehavior.SILENT_BYPASS -> {}
        }
    }

    private fun resolveCurrentState(): FilterInstallationPlanner.ContainerState {
        val threadActions = ContainerStateRegistry.THREAD_SYSCALL_ACTIONS.get()
        val processActions = ContainerStateRegistry.PROCESS_SYSCALL_ACTIONS

        val mergedActions = mutableMapOf<Syscall, SeccompAction>()
        for ((sys, action) in threadActions) {
            mergedActions[sys] = action
        }
        for ((sys, action) in processActions) {
            val current = mergedActions[sys]
            if (current == null || action.priority > current.priority) {
                mergedActions[sys] = action
            }
        }

        val threadDefault = ContainerStateRegistry.THREAD_DEFAULT_ACTION.get()
        val processDefault = ContainerStateRegistry.PROCESS_DEFAULT_ACTION.get()
        val mergedDefault = if (threadDefault.priority > processDefault.priority) threadDefault else processDefault

        val threadAllowed = ContainerStateRegistry.THREAD_ALLOWED_SYSCALLS.get()
        val processAllowed = ContainerStateRegistry.PROCESS_ALLOWED_SYSCALLS.get()
        val mergedAllowed = if (threadAllowed == null) {
            processAllowed
        } else if (processAllowed == null) {
            threadAllowed
        } else {
            threadAllowed.intersect(processAllowed)
        }

        return FilterInstallationPlanner.ContainerState(
            currentSyscallActions = mergedActions,
            currentDefaultAction = mergedDefault,
            currentlyAllowsMmapExec = ContainerStateRegistry.THREAD_ALLOWS_MMAP_EXEC.get() && ContainerStateRegistry.PROCESS_ALLOWS_MMAP_EXEC.get(),
            currentlyAllowsNonThreadClone = ContainerStateRegistry.THREAD_ALLOWS_NON_THREAD_CLONE.get() && ContainerStateRegistry.PROCESS_ALLOWS_NON_THREAD_CLONE.get(),
            currentlyAllowsUnsafePrctl = ContainerStateRegistry.THREAD_ALLOWS_UNSAFE_PRCTL.get() && ContainerStateRegistry.PROCESS_ALLOWS_UNSAFE_PRCTL.get(),
            currentDepth = ContainerStateRegistry.FILTER_DEPTH.get() + ContainerStateRegistry.PROCESS_FILTER_DEPTH.get(),
            currentlyAllowedSyscalls = mergedAllowed,
        )
    }

    private fun applyBpfFilter(
        processWide: Boolean,
        toInstall: Policy<*, *>,
        newBlocks: Map<Syscall, SeccompAction>,
        newDefaultAction: SeccompAction,
    ) {
        val arch = io.mazewall.core.Arch
            .current()
        val compiledPolicy = toInstall.compile(arch)
        if (processWide) {
            PureJavaBpfEngine.installOnProcess(compiledPolicy)
            updateProcessState(newBlocks, newDefaultAction, toInstall)
        } else {
            PureJavaBpfEngine.install(compiledPolicy)
            updateThreadState(newBlocks, newDefaultAction, toInstall)
        }
    }

    private fun updateProcessState(
        newBlocks: Map<Syscall, SeccompAction>,
        newDefaultAction: SeccompAction,
        toInstall: Policy<*, *>,
    ) {
        val currentActions = ContainerStateRegistry.PROCESS_SYSCALL_ACTIONS
        for ((sys, action) in newBlocks) {
            currentActions[sys] = action
        }
        val currentDefault = ContainerStateRegistry.PROCESS_DEFAULT_ACTION.get()
        if (newDefaultAction.priority > currentDefault.priority) {
            ContainerStateRegistry.PROCESS_DEFAULT_ACTION.set(newDefaultAction)
        }

        if (!toInstall.allowMmapExec) ContainerStateRegistry.PROCESS_ALLOWS_MMAP_EXEC.set(false)
        if (!toInstall.allowNonThreadClone) ContainerStateRegistry.PROCESS_ALLOWS_NON_THREAD_CLONE.set(false)
        if (!toInstall.allowUnsafePrctl) ContainerStateRegistry.PROCESS_ALLOWS_UNSAFE_PRCTL.set(false)
        ContainerStateRegistry.PROCESS_FILTER_DEPTH.incrementAndGet()

        if (toInstall.defaultAction != SeccompAction.ACT_ALLOW) {
            val toInstallAllowed = Syscall.entries.filter { toInstall.isSyscallAllowed(it) }.toSet()
            while (true) {
                val current = ContainerStateRegistry.PROCESS_ALLOWED_SYSCALLS.get()
                val next = current?.intersect(toInstallAllowed) ?: toInstallAllowed
                if (ContainerStateRegistry.PROCESS_ALLOWED_SYSCALLS.compareAndSet(current, next)) {
                    break
                }
            }
        }
    }

    private fun updateThreadState(
        newBlocks: Map<Syscall, SeccompAction>,
        newDefaultAction: SeccompAction,
        toInstall: Policy<*, *>,
    ) {
        val currentActions = ContainerStateRegistry.THREAD_SYSCALL_ACTIONS.get()
        val mergedActions = currentActions.toMutableMap()
        for ((sys, action) in newBlocks) {
            mergedActions[sys] = action
        }
        ContainerStateRegistry.THREAD_SYSCALL_ACTIONS.set(mergedActions)

        val currentDefault = ContainerStateRegistry.THREAD_DEFAULT_ACTION.get()
        if (newDefaultAction.priority > currentDefault.priority) {
            ContainerStateRegistry.THREAD_DEFAULT_ACTION.set(newDefaultAction)
        }

        if (!toInstall.allowMmapExec) ContainerStateRegistry.THREAD_ALLOWS_MMAP_EXEC.set(false)
        if (!toInstall.allowNonThreadClone) ContainerStateRegistry.THREAD_ALLOWS_NON_THREAD_CLONE.set(false)
        if (!toInstall.allowUnsafePrctl) ContainerStateRegistry.THREAD_ALLOWS_UNSAFE_PRCTL.set(false)
        ContainerStateRegistry.FILTER_DEPTH.set(ContainerStateRegistry.FILTER_DEPTH.get() + 1)

        if (toInstall.defaultAction != SeccompAction.ACT_ALLOW) {
            val toInstallAllowed = Syscall.entries.filter { toInstall.isSyscallAllowed(it) }.toSet()
            val currentAllowed = ContainerStateRegistry.THREAD_ALLOWED_SYSCALLS.get()
            ContainerStateRegistry.THREAD_ALLOWED_SYSCALLS.set(currentAllowed?.intersect(toInstallAllowed) ?: toInstallAllowed)
        }
    }
}
