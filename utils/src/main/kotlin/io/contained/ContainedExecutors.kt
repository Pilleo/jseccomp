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
    
    // Tracks which syscalls are already blocked on this thread via seccomp filters.
    // Seccomp filters are append-only in the kernel (intersection semantics),
    // so we only need to install a supplemental filter for newly-requested blocks.
    private val THREAD_BLOCKED = ThreadLocal.withInitial { emptySet<Syscall>() }

    /**
     * Installs the given policies onto the current thread immediately.
     */
    fun installOnCurrentThread(vararg policies: Policy) {
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
            val deltaPolicy = Policy.builder().block(*newBlocks.toTypedArray()).build()
            SeccompInstaller.install(deltaPolicy)
            THREAD_BLOCKED.set(currentlyBlocked + newBlocks)
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
        val msg = t.message ?: return false
        
        return msg.contains("Operation not permitted")
            || msg.contains("Permission denied")
            || (t is SocketException && msg.contains("Permission"))
            || (t is AccessDeniedException)
            || (t is IOException && msg.contains("Cannot run"))
    }

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
            if (!supported) {
                when (fallback) {
                    Platform.FallbackBehavior.FAIL -> 
                        throw UnsupportedOperationException("Platform does not support seccomp")
                    Platform.FallbackBehavior.WARN_AND_BYPASS -> 
                        logger.warning("Platform does not support seccomp. Task running uncontained.")
                    Platform.FallbackBehavior.SILENT_BYPASS -> {}
                }
                return
            }

            val currentlyBlocked = THREAD_BLOCKED.get()
            val newBlocks = policy.blocked - currentlyBlocked
            if (newBlocks.isNotEmpty()) {
                val deltaPolicy = Policy.builder().block(*newBlocks.toTypedArray()).build()
                SeccompInstaller.install(deltaPolicy)
                THREAD_BLOCKED.set(currentlyBlocked + newBlocks)
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
