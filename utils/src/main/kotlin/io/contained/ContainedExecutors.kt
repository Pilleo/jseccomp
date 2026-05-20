package io.contained

import java.io.IOException
import java.net.SocketException
import java.nio.file.AccessDeniedException
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.logging.Logger

/**
 * Public API for wrapping an existing [ExecutorService] to enforce seccomp containment.
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
 * that needs to read a config file blocked by [Policy.PURE_COMPUTE]), the operation will fail.
 * **Mitigation:** Ensure critical classes and native libraries are loaded during application
 * startup before containment is applied.
 */
object ContainedExecutors {
    private val logger = Logger.getLogger(ContainedExecutors::class.java.name)

    private val PROCESS_BLOCKED = CopyOnWriteArraySet<Syscall>()
    @Volatile
    private var PROCESS_ALLOWS_MMAP_EXEC = true
    @Volatile
    private var PROCESS_ALLOWS_NON_THREAD_CLONE = true
    @Volatile
    private var PROCESS_ALLOWS_UNSAFE_PRCTL = true
    private val PROCESS_FILTER_DEPTH = AtomicInteger(0)
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

    private fun installInternal(processWide: Boolean, vararg policies: Policy) {
        if (Thread.currentThread().isVirtual) {
            throw IllegalStateException(
                "Attempted to apply seccomp containment inside a virtual thread. " +
                        "Use a dedicated platform thread pool and install containment on its carrier threads instead."
            )
        }

        val policy = Policy.combine(*policies)

        if (!Platform.isSupported()) {
            val fallback = Platform.configuredFallback()
            when (fallback) {
                Platform.FallbackBehavior.FAIL ->
                    throw UnsupportedOperationException("Platform does not support seccomp")

                Platform.FallbackBehavior.WARN_AND_BYPASS ->
                    logger.warning("Platform does not support seccomp. Code will run uncontained.")

                Platform.FallbackBehavior.SILENT_BYPASS -> {}
            }
            return
        }

        // We use a lock to ensure process-wide updates are deterministic and prevent TOCTOU races
        // between reading PROCESS_BLOCKED and applying the thread's filter.
        synchronized(processLock) {
            // Synchronize with both thread-local and process-wide state
            val currentlyBlocked = THREAD_BLOCKED.get() + PROCESS_BLOCKED
            val currentlyAllowsMmapExec = THREAD_ALLOWS_MMAP_EXEC.get() && PROCESS_ALLOWS_MMAP_EXEC
            val currentlyAllowsNonThreadClone = THREAD_ALLOWS_NON_THREAD_CLONE.get() && PROCESS_ALLOWS_NON_THREAD_CLONE
            val currentlyAllowsUnsafePrctl = THREAD_ALLOWS_UNSAFE_PRCTL.get() && PROCESS_ALLOWS_UNSAFE_PRCTL
            val currentDepth = FILTER_DEPTH.get() + PROCESS_FILTER_DEPTH.get()

            val newBlocks = policy.blocked - currentlyBlocked
            val needsMmapProtection = !policy.allowMmapExec && currentlyAllowsMmapExec
            val needsCloneProtection = !policy.allowNonThreadClone && currentlyAllowsNonThreadClone
            val needsPrctlProtection = !policy.allowUnsafePrctl && currentlyAllowsUnsafePrctl

            if (newBlocks.isNotEmpty() || needsMmapProtection || needsCloneProtection || needsPrctlProtection) {
                if (currentDepth >= 32) {
                    throw IllegalStateException("Cannot install more than 32 seccomp filters on a single thread (including process-wide filters).")
                }
                if (currentDepth > 10) {
                    logger.warning("Thread ${Thread.currentThread().name} has $currentDepth seccomp filters.")
                }

                // Use PureJavaBpfEngine exclusively for zero-dependency enforcement
                val incrementalPolicy = Policy.builder()
                    .block(*newBlocks.toTypedArray())

                if (policy.allowMmapExec) incrementalPolicy.allowMmapExec()
                if (policy.allowNonThreadClone) incrementalPolicy.allowNonThreadClone()
                if (policy.allowUnsafePrctl) incrementalPolicy.allowUnsafePrctl()

                val toInstall = incrementalPolicy.build()

                if (processWide) {
                    PureJavaBpfEngine.installOnProcess(toInstall)
                    // Update global state
                    PROCESS_BLOCKED.addAll(newBlocks)
                    if (!policy.allowMmapExec) PROCESS_ALLOWS_MMAP_EXEC = false
                    if (!policy.allowNonThreadClone) PROCESS_ALLOWS_NON_THREAD_CLONE = false
                    if (!policy.allowUnsafePrctl) PROCESS_ALLOWS_UNSAFE_PRCTL = false
                    PROCESS_FILTER_DEPTH.incrementAndGet()
                } else {
                    PureJavaBpfEngine.install(toInstall)
                    // Update thread-local state
                    THREAD_BLOCKED.set(THREAD_BLOCKED.get() + newBlocks)
                    if (!policy.allowMmapExec) THREAD_ALLOWS_MMAP_EXEC.set(false)
                    if (!policy.allowNonThreadClone) THREAD_ALLOWS_NON_THREAD_CLONE.set(false)
                    if (!policy.allowUnsafePrctl) THREAD_ALLOWS_UNSAFE_PRCTL.set(false)
                    FILTER_DEPTH.set(FILTER_DEPTH.get() + 1)
                }
            }
        }
    }

    /**
     * Wraps an [ExecutorService] so that any task submitted to it will have the given
     * [policies] applied before execution.
     *
     * ### Thread Pool Poisoning
     * Seccomp filters are **immutable and permanent** for the lifetime of an OS thread.
     * If you wrap a shared [ExecutorService], the worker threads will be permanently
     * restricted after their first contained task. **Do not share the same pool between
     * contained and uncontained tasks.**
     *
     * For best results, always use a dedicated [ExecutorService] for restricted tasks.
     */
    fun wrap(delegate: ExecutorService, vararg policies: Policy): ExecutorService {
        val combinedPolicy = Policy.combine(*policies)
        val fallback = Platform.configuredFallback()
        val supported = Platform.isSupported()

        return ContainedExecutorWrapper(delegate, combinedPolicy, supported, fallback)
    }

    /**
     * Examines an exception thrown by a task to determine if it was likely
     * caused by a seccomp containment violation (e.g. EPERM).
     */
    internal fun isContainmentViolation(t: Throwable): Boolean {
        return isDirectContainmentViolation(t) || isViolationInCauseChain(t) || isViolationInSuppressed(t)
    }

    internal fun findViolationCause(t: Throwable): Throwable? {
        if (isDirectContainmentViolation(t)) return t
        var current = t.cause
        while (current != null && current !== t) {
            if (isDirectContainmentViolation(current)) return current
            current = current.cause
        }
        for (suppressed in t.suppressedExceptions) {
            if (isDirectContainmentViolation(suppressed)) return suppressed
        }
        return null
    }

    private val VIOLATION_MESSAGE_REGEX =
        Regex("(?i)Operation not permitted|Permission denied|error=1\\b|error=13\\b|\\bdenied\\b|refusé|verweigert|negado")

    private fun isDirectContainmentViolation(t: Throwable): Boolean {
        // EPERM (1) is the standard seccomp return code.
        if (t is AccessDeniedException || t is java.nio.file.FileSystemException && t.message?.contains("Operation not permitted") == true) {
            return true
        }

        val msg = t.message ?: return false

        // Check for explicit JVM error codes first to avoid locale-fragile string matching
        if (msg.contains("error=1\b") || msg.contains("error=13\b") || (t is IOException && msg.contains("error=1"))) {
            return true
        }

        if (VIOLATION_MESSAGE_REGEX.containsMatchIn(msg)) {
            return true
        }

        return (t is SocketException && (msg.contains("Permission") || msg.contains("denied")))
                || (t is IOException && msg.contains("Cannot run"))
    }

    private fun isViolationInCauseChain(t: Throwable): Boolean {
        var current = t.cause
        while (current != null && current !== t) {
            if (isDirectContainmentViolation(current)) return true
            current = current.cause
        }
        return false
    }

    private fun isViolationInSuppressed(t: Throwable): Boolean {
        for (suppressed in t.suppressedExceptions) {
            if (isDirectContainmentViolation(suppressed)) return true
        }
        return false
    }

    private val THREAD_BLOCKED = ThreadLocal.withInitial { emptySet<Syscall>() }
    private val THREAD_ALLOWS_MMAP_EXEC = ThreadLocal.withInitial { true }
    private val THREAD_ALLOWS_NON_THREAD_CLONE = ThreadLocal.withInitial { true }
    private val THREAD_ALLOWS_UNSAFE_PRCTL = ThreadLocal.withInitial { true }
    private val FILTER_DEPTH = ThreadLocal.withInitial { 0 }
    private val THREAD_LANDLOCK_APPLIED = ThreadLocal.withInitial { false }

    internal class ContainedExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val supported: Boolean,
        private val fallback: Platform.FallbackBehavior
    ) : ExecutorService by delegate {

        private fun <T> wrapCallable(task: Callable<T>): Callable<T> = Callable {
            // applyContainment() failures (e.g. landlock_create_ruleset errno, depth limit)
            // propagate as-is — they are not containment violations by the user task.
            applyContainment()
            try {
                task.call()
            } catch (e: Error) {
                // Critical JVM errors (OOM, StackOverflow) should propagate immediately
                throw e
            } catch (e: Exception) {
                // Only inspect exceptions thrown by the user task body.
                if (isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

        private fun wrapRunnable(task: Runnable): Runnable = Runnable {
            applyContainment()
            try {
                task.run()
            } catch (e: Error) {
                throw e
            } catch (e: Exception) {
                if (isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

        private fun applyContainment() {
            try {
                // Apply Landlock only once per OS thread to prevent intersective stacking
                // (the kernel limit is ~16 layers before E2BIG).
                if (!THREAD_LANDLOCK_APPLIED.get()) {
                    Landlock.applyRuleset(policy)
                    THREAD_LANDLOCK_APPLIED.set(true)
                }
                installOnCurrentThread(policy)
            } catch (e: UnsupportedOperationException) {
                throw e
            }
        }

        override fun execute(command: Runnable) {
            delegate.execute(wrapRunnable(command))
        }

        override fun <T> submit(task: Callable<T>): Future<T> =
            delegate.submit(wrapCallable(task))

        override fun <T> submit(task: Runnable, result: T): Future<T> =
            delegate.submit(wrapRunnable(task), result)

        override fun submit(task: Runnable): Future<*> =
            delegate.submit(wrapRunnable(task))

        override fun <T> invokeAll(tasks: Collection<Callable<T>>): List<Future<T>> =
            delegate.invokeAll(tasks.map { wrapCallable(it) })

        override fun <T> invokeAll(tasks: Collection<Callable<T>>, timeout: Long, unit: TimeUnit): List<Future<T>> =
            delegate.invokeAll(tasks.map { wrapCallable(it) }, timeout, unit)

        override fun <T> invokeAny(tasks: Collection<Callable<T>>): T =
            delegate.invokeAny(tasks.map { wrapCallable(it) })

        override fun <T> invokeAny(tasks: Collection<Callable<T>>, timeout: Long, unit: TimeUnit): T =
            delegate.invokeAny(tasks.map { wrapCallable(it) }, timeout, unit)
    }
}
