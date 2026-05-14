package io.contained

import java.io.IOException
import java.net.SocketException
import java.nio.file.AccessDeniedException
import java.util.concurrent.*
import java.util.logging.Logger

/**
 * Public API for wrapping an existing [ExecutorService] to enforce seccomp containment.
 */
object ContainedExecutors {
    private val logger = Logger.getLogger(ContainedExecutors::class.java.name)

    /**
     * Installs the given policies onto the current thread immediately.
     */
    fun installOnCurrentThread(vararg policies: Policy) {
        installInternal(false, *policies)
    }

    /**
     * Installs the given policies onto the entire process (all threads) immediately.
     * This acts as a global security lockdown and cannot be undone.
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

        val currentlyBlocked = THREAD_BLOCKED.get()
        val newBlocks = policy.blocked - currentlyBlocked
        if (newBlocks.isNotEmpty()) {
            val depth = FILTER_DEPTH.get()
            if (depth >= 32) {
                throw IllegalStateException("Cannot install more than 32 seccomp filters on a single thread.")
            }
            if (depth > 10) {
                logger.warning("Thread ${Thread.currentThread().name} has $depth seccomp filters.")
            }

            // Use PureJavaBpfEngine exclusively for zero-dependency enforcement
            if (processWide) {
                PureJavaBpfEngine.installOnProcess(Policy.builder().block(*newBlocks.toTypedArray()).build())
            } else {
                PureJavaBpfEngine.install(Policy.builder().block(*newBlocks.toTypedArray()).build())
            }
            
            THREAD_BLOCKED.set(currentlyBlocked + newBlocks)
            FILTER_DEPTH.set(depth + 1)
        }
    }

    /**
     * Wraps an [ExecutorService] so that any task submitted to it will have the given
     * [policies] applied before execution.
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

    private fun isDirectContainmentViolation(t: Throwable): Boolean {
        // EPERM (1) is the standard seccomp return code.
        if (t is AccessDeniedException || t is java.nio.file.FileSystemException && t.message?.contains("Operation not permitted") == true) {
            return true
        }

        val msg = t.message ?: return false

        return msg.contains("Operation not permitted") 
            || msg.contains("Permission denied")       
            || msg.contains("error=1,")                
            || msg.contains("error=13,")               
            || (t is SocketException && (msg.contains("Permission") || msg.contains("denied")))
            || (t is IOException && (msg.contains("Cannot run") || msg.contains("error=1")))
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
    private val FILTER_DEPTH = ThreadLocal.withInitial { 0 }

    internal class ContainedExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val supported: Boolean,
        private val fallback: Platform.FallbackBehavior
    ) : ExecutorService by delegate {
        
        private fun <T> wrapCallable(task: Callable<T>): Callable<T> = Callable {
            applyContainment()
            try {
                task.call()
            } catch (e: Exception) {
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
            } catch (e: Exception) {
                if (isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

        private fun applyContainment() {
            try {
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
