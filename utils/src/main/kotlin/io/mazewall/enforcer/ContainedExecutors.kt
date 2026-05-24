package io.mazewall.enforcer

import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.Syscall
import io.mazewall.landlock.Landlock
import io.mazewall.seccomp.PureJavaBpfEngine
import java.io.IOException
import java.nio.file.AccessDeniedException
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
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

        val needsLandlock = policy.allowedFsReadPaths.isNotEmpty() || 
                            policy.allowedFsWritePaths.isNotEmpty() ||
                            policy.isSyscallAllowed(Syscall.IO_URING_SETUP)
        if (needsLandlock) {
            if (processWide) {
                throw UnsupportedOperationException(
                    "Process-wide containment (installOnProcess) does not support Landlock filesystem rules. " +
                            "Use thread-scoped containment (installOnCurrentThread) for filesystem restrictions."
                )
            } else {
                val appliedReads = THREAD_LANDLOCK_APPLIED_READS.get()
                val appliedWrites = THREAD_LANDLOCK_APPLIED_WRITES.get()
                if (appliedReads != null || appliedWrites != null) {
                    val prevReads = appliedReads ?: emptySet()
                    val prevWrites = appliedWrites ?: emptySet()
                    val hasNewReads = !prevReads.containsAll(policy.allowedFsReadPaths)
                    val hasNewWrites = !prevWrites.containsAll(policy.allowedFsWritePaths)
                    if (hasNewReads || hasNewWrites) {
                        throw IllegalStateException(
                            "Cannot expand Landlock filesystem permissions on an already restricted thread."
                        )
                    }
                }

                val alreadyAppliedExactly =
                    appliedReads == policy.allowedFsReadPaths && appliedWrites == policy.allowedFsWritePaths
                if (!alreadyAppliedExactly) {
                    Landlock.applyRuleset(policy)
                    THREAD_LANDLOCK_APPLIED_READS.set(policy.allowedFsReadPaths)
                    THREAD_LANDLOCK_APPLIED_WRITES.set(policy.allowedFsWritePaths)
                }
            }
        }

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

            val newBlocks = if (policy.mode == Policy.Mode.DENY_LIST) {
                policy.syscalls - currentlyBlocked
            } else {
                emptySet()
            }

            val needsMmapProtection = !policy.allowMmapExec && currentlyAllowsMmapExec
            val needsCloneProtection = !policy.allowNonThreadClone && currentlyAllowsNonThreadClone
            val needsPrctlProtection = !policy.allowUnsafePrctl && currentlyAllowsUnsafePrctl

            val needsNewFilter = policy.mode == Policy.Mode.ALLOW_LIST ||
                    newBlocks.isNotEmpty() ||
                    needsMmapProtection ||
                    needsCloneProtection ||
                    needsPrctlProtection

            if (needsNewFilter) {
                if (currentDepth >= 32) {
                    throw IllegalStateException("Cannot install more than 32 seccomp filters on a single thread (including process-wide filters).")
                }
                if (currentDepth > 10) {
                    logger.warning("Thread ${Thread.currentThread().name} has $currentDepth seccomp filters.")
                }

                val toInstall = if (policy.mode == Policy.Mode.ALLOW_LIST) {
                    policy
                } else {
                    // Use PureJavaBpfEngine exclusively for zero-dependency enforcement
                    val incremental = Policy.builder()
                        .block(*newBlocks.toTypedArray())

                    if (policy.allowMmapExec) incremental.allowMmapExec()
                    if (policy.allowNonThreadClone) incremental.allowNonThreadClone()
                    if (policy.allowUnsafePrctl) incremental.allowUnsafePrctl()
                    incremental.build()
                }

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

    // Priority 1: JVM-encoded errno (most reliable — locale-independent)
    // Matches both "error=1" and "error: 1"
    private fun containsErrno(msg: String): Boolean {
        var start = 0
        while (true) {
            val idx = msg.indexOf("error", start)
            if (idx == -1) return false

            // Check word boundary before "error"
            if (idx > 0 && Character.isLetterOrDigit(msg[idx - 1])) {
                start = idx + 1
                continue
            }

            val afterErrorIdx = idx + 5
            if (afterErrorIdx >= msg.length) return false

            val sep = msg[afterErrorIdx]
            if (sep != '=' && sep != ':') {
                start = idx + 1
                continue
            }

            var valIdx = afterErrorIdx + 1
            // Skip optional whitespace after ':'
            if (sep == ':') {
                while (valIdx < msg.length && msg[valIdx].isWhitespace()) {
                    valIdx++
                }
            }

            if (valIdx >= msg.length) return false

            val isErr1 = msg[valIdx] == '1'
            val isErr13 = msg.regionMatches(valIdx, "13", 0, 2)

            if (isErr1 || isErr13) {
                val nextIdx = if (isErr13) valIdx + 2 else valIdx + 1
                // Check word boundary after number
                if (nextIdx < msg.length && Character.isLetterOrDigit(msg[nextIdx])) {
                    start = idx + 1
                    continue
                }
                return true
            }

            start = idx + 1
        }
    }

    // Priority 2: OS message fallback (locale-sensitive, narrowed to known safe patterns)
    internal val DENIED_PHRASES = arrayOf(
        "Operation not permitted",
        "Permission denied",
        "refusé",
        "verweigert",
        "negado"
    )

    private fun containsDeniedPhrase(msg: String): Boolean {
        for (phrase in DENIED_PHRASES) {
            if (msg.contains(phrase, ignoreCase = true)) return true
        }
        return false
    }

    private fun isDirectContainmentViolation(t: Throwable): Boolean {
        // AccessDeniedException is a direct native translation of EACCES/EPERM for path operations
        if (t is AccessDeniedException) return true

        val msg = t.message ?: return false

        // Check for explicit JVM-encoded error codes first (locale-independent)
        if (containsErrno(msg)) {
            return true
        }

        // Restrict OS message parsing to I/O and networking contexts to avoid false positives in business logic.
        if (t is IOException) {
            if (containsDeniedPhrase(msg)) {
                return true
            }
            if (msg.contains("Cannot run")) {
                return true
            }
        }

        return false
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
    private val THREAD_LANDLOCK_APPLIED_READS = ThreadLocal.withInitial<Set<String>?> { null }
    private val THREAD_LANDLOCK_APPLIED_WRITES = ThreadLocal.withInitial<Set<String>?> { null }

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
            installOnCurrentThread(policy)
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
