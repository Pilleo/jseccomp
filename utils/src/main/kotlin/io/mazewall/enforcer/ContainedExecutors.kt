package io.mazewall.enforcer

import io.mazewall.Arch
import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.Syscall
import io.mazewall.landlock.Landlock
import io.mazewall.seccomp.PureJavaBpfEngine
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
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
 * ### The "Lazy Initialization" Trap
 * The JVM performs many operations lazily (class loading, JIT, JNI loading). If a restricted
 * thread is the first to trigger a specific lazy initialization path (e.g. loading a provider
 * that needs to read a config file blocked by [io.mazewall.Policy.Companion.PURE_COMPUTE]), the operation will fail.
 * **Mitigation:** Ensure critical classes and native libraries are loaded during application
 * startup before containment is applied.
 */
object ContainedExecutors {
    private val warmedUp = AtomicBoolean(false)

    init {
        performJitWarmup()
    }

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
    fun installOnCurrentThread(vararg policies: Policy) {
        installInternal(false, *policies)
    }

    /**
     * Installs the given policies onto the entire process (all threads) immediately.
     * This acts as a global security lockdown and cannot be undone. All future threads
     * created by this process will inherit these restrictions.
     */
    fun installOnProcess(vararg policies: Policy) {
        installInternal(true, *policies)
    }

    private fun installInternal(
        processWide: Boolean,
        vararg policies: Policy,
    ) {
        checkVirtualThread()
        performJitWarmup()

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
        combinedPolicy: Policy,
    ) {
        synchronized(processLock) {
            val state = resolveCurrentState()
            val plan = FilterInstallationPlanner.calculateNewFilter(combinedPolicy, state)

            if (plan.needsNewFilter) {
                FilterInstallationPlanner.verifyFilterDepth(state.currentDepth)
                applyBpfFilter(processWide, plan.toInstall, plan.newBlocks)
            }
        }
    }

    private fun checkVirtualThread() {
        if (Thread.currentThread().isVirtual) {
            throw IllegalStateException(
                "Attempted to apply seccomp containment inside a virtual thread. " +
                        "Use a dedicated platform thread pool and install containment on its carrier threads instead.",
            )
        }
    }

    private fun performJitWarmup() {
        if (warmedUp.compareAndSet(false, true)) {
            // Force JVM classloading and JIT compilation of core sandboxing components
            // before containment is applied to prevent the "lazy initialization trap".
            ContainmentViolationDetector.isContainmentViolation(Throwable(""))
            Platform.isSupported()
            try {
                Arch.current()
            } catch (e: Exception) {
                // Ignore unsupported architecture; will be handled by platform check
            }
        }
    }

    private fun applyLandlockIfNecessary(
        processWide: Boolean,
        policy: Policy,
    ) {
        val needsLandlock = policy.allowedFsReadPaths.isNotEmpty() ||
                policy.allowedFsWritePaths.isNotEmpty() ||
                policy.isSyscallAllowed(Syscall.IO_URING_SETUP)

        if (!needsLandlock) return

        if (processWide) {
            throw UnsupportedOperationException(
                "Process-wide containment (installOnProcess) does not support Landlock filesystem rules. " +
                        "Use thread-scoped containment (installOnCurrentThread) for filesystem restrictions.",
            )
        }

        val appliedReads = ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_READS.get()
        val appliedWrites = ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_WRITES.get()

        if (appliedReads != null || appliedWrites != null) {
            val prevReads = appliedReads ?: emptySet()
            val prevWrites = appliedWrites ?: emptySet()

            val hasNewReads = !isPathSubset(prevReads, policy.allowedFsReadPaths)
            val hasNewWrites = !isPathSubset(prevWrites, policy.allowedFsWritePaths)
            if (hasNewReads || hasNewWrites) {
                throw IllegalStateException("Cannot expand Landlock filesystem permissions on an already restricted thread.")
            }
        }

        if (appliedReads != policy.allowedFsReadPaths || appliedWrites != policy.allowedFsWritePaths) {
            Landlock.applyRuleset(policy)
            ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_READS.set(policy.allowedFsReadPaths)
            ContainerStateRegistry.THREAD_LANDLOCK_APPLIED_WRITES.set(policy.allowedFsWritePaths)
        }
    }

    private fun isPathSubset(
        parentPaths: Set<String>,
        childPaths: Set<String>,
    ): Boolean {
        if (childPaths.isEmpty()) return true
        if (parentPaths.isEmpty()) return false
        val parents = parentPaths.map {
            java.nio.file.Paths
            .get(it)
            .toAbsolutePath()
            .normalize()
        }
        return childPaths.all { childStr ->
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

    private fun resolveCurrentState(): FilterInstallationPlanner.ContainerState =
        FilterInstallationPlanner.ContainerState(
            currentlyBlocked = ContainerStateRegistry.THREAD_BLOCKED.get() + ContainerStateRegistry.PROCESS_BLOCKED,
            currentlyAllowsMmapExec = ContainerStateRegistry.THREAD_ALLOWS_MMAP_EXEC.get() && ContainerStateRegistry.PROCESS_ALLOWS_MMAP_EXEC.get(),
            currentlyAllowsNonThreadClone = ContainerStateRegistry.THREAD_ALLOWS_NON_THREAD_CLONE.get() && ContainerStateRegistry.PROCESS_ALLOWS_NON_THREAD_CLONE.get(),
            currentlyAllowsUnsafePrctl = ContainerStateRegistry.THREAD_ALLOWS_UNSAFE_PRCTL.get() && ContainerStateRegistry.PROCESS_ALLOWS_UNSAFE_PRCTL.get(),
            currentDepth = ContainerStateRegistry.FILTER_DEPTH.get() + ContainerStateRegistry.PROCESS_FILTER_DEPTH.get(),
        )

    private fun applyBpfFilter(
        processWide: Boolean,
        toInstall: Policy,
        newBlocks: Set<Syscall>,
    ) {
        if (processWide) {
            PureJavaBpfEngine.installOnProcess(toInstall)
            updateProcessState(newBlocks, toInstall)
        } else {
            PureJavaBpfEngine.install(toInstall)
            updateThreadState(newBlocks, toInstall)
        }
    }

    private fun updateProcessState(
        newBlocks: Set<Syscall>,
        toInstall: Policy,
    ) {
        ContainerStateRegistry.PROCESS_BLOCKED.addAll(newBlocks)
        if (!toInstall.allowMmapExec) ContainerStateRegistry.PROCESS_ALLOWS_MMAP_EXEC.set(false)
        if (!toInstall.allowNonThreadClone) ContainerStateRegistry.PROCESS_ALLOWS_NON_THREAD_CLONE.set(false)
        if (!toInstall.allowUnsafePrctl) ContainerStateRegistry.PROCESS_ALLOWS_UNSAFE_PRCTL.set(false)
        ContainerStateRegistry.PROCESS_FILTER_DEPTH.incrementAndGet()
    }

    private fun updateThreadState(
        newBlocks: Set<Syscall>,
        toInstall: Policy,
    ) {
        ContainerStateRegistry.THREAD_BLOCKED.set(ContainerStateRegistry.THREAD_BLOCKED.get() + newBlocks)
        if (!toInstall.allowMmapExec) ContainerStateRegistry.THREAD_ALLOWS_MMAP_EXEC.set(false)
        if (!toInstall.allowNonThreadClone) ContainerStateRegistry.THREAD_ALLOWS_NON_THREAD_CLONE.set(false)
        if (!toInstall.allowUnsafePrctl) ContainerStateRegistry.THREAD_ALLOWS_UNSAFE_PRCTL.set(false)
        ContainerStateRegistry.FILTER_DEPTH.set(ContainerStateRegistry.FILTER_DEPTH.get() + 1)
    }

    /**
     * Wraps an [java.util.concurrent.ExecutorService] so that any task submitted to it will have the given
     * [policies] applied before execution.
     *
     * ### Thread Pool Poisoning
     * Seccomp filters are **immutable and permanent** for the lifetime of an OS thread.
     * If you wrap a shared [java.util.concurrent.ExecutorService], the worker threads will be permanently
     * restricted after their first contained task. **Do not share the same pool between
     * contained and uncontained tasks.**
     *
     * For best results, always use a dedicated [java.util.concurrent.ExecutorService] for restricted tasks.
     */
    fun wrap(
        delegate: ExecutorService,
        vararg policies: Policy,
    ): ExecutorService {
        val combinedPolicy = Policy.combine(*policies)
        val fallback = Platform.configuredFallback()
        val supported = Platform.isSupported()

        return ContainedExecutorWrapper(delegate, combinedPolicy, supported, fallback)
    }

    internal class ContainedExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val supported: Boolean,
        private val fallback: Platform.FallbackBehavior,
    ) : ExecutorService by delegate {
        private fun <T> wrapCallable(task: Callable<T>): Callable<T> =
            Callable {
                applyContainment()
                val result = runCatching { task.call() }
                result.getOrElse { e ->
                    if (e is Exception && ContainmentViolationDetector.isContainmentViolation(e)) {
                        throw ContainmentViolationException("Task violated containment policy", e)
                    }
                    throw e
                }
            }

        private fun wrapRunnable(task: Runnable): Runnable =
            Runnable {
                applyContainment()
                val result = runCatching { task.run() }
                result.onFailure { e ->
                    if (e is Exception && ContainmentViolationDetector.isContainmentViolation(e)) {
                        throw ContainmentViolationException("Task violated containment policy", e)
                    }
                    throw e
                }
            }

        private fun applyContainment() {
            installOnCurrentThread(policy)
        }

        override fun execute(command: Runnable) {
            delegate.execute(wrapRunnable(command))
        }

        override fun <T> submit(task: Callable<T>): Future<T> = delegate.submit(wrapCallable(task))

        override fun <T> submit(
            task: Runnable,
            result: T,
        ): Future<T> = delegate.submit(wrapRunnable(task), result)

        override fun submit(task: Runnable): Future<*> = delegate.submit(wrapRunnable(task))

        override fun <T> invokeAll(tasks: Collection<Callable<T>>): List<Future<T>> = delegate.invokeAll(tasks.map { wrapCallable(it) })

        override fun <T> invokeAll(
            tasks: Collection<Callable<T>>,
            timeout: Long,
            unit: TimeUnit,
        ): List<Future<T>> = delegate.invokeAll(tasks.map { wrapCallable(it) }, timeout, unit)

        override fun <T> invokeAny(tasks: Collection<Callable<T>>): T = delegate.invokeAny(tasks.map { wrapCallable(it) })

        override fun <T> invokeAny(
            tasks: Collection<Callable<T>>,
            timeout: Long,
            unit: TimeUnit,
        ): T = delegate.invokeAny(tasks.map { wrapCallable(it) }, timeout, unit)

        override fun close() {
            delegate.close()
        }
    }
}
