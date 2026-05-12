package io.contained

import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType
import java.net.SocketException
import java.nio.file.AccessDeniedException
import java.util.concurrent.*
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Public API for wrapping an existing [ExecutorService] to enforce seccomp containment.
 */
object ContainedExecutors {
    private val logger = Logger.getLogger(ContainedExecutors::class.java.name)
    
    /** Records details of a seccomp violation captured via SIGSYS. */
    data class Violation(val syscall: Int, val arch: Int)

    /**
     * A pre-allocated shared memory segment used to track per-thread seccomp violations.
     * 
     * Why not ThreadLocal? 
     * Signals are delivered asynchronously and the signal handler must be "async-signal-safe".
     * Accessing a Java ThreadLocal is NOT safe in a signal handler. Instead, we use raw 
     * MemorySegment access indexed by a hash of the native thread ID (TID), which 
     * is both fast and signal-safe.
     * 
     * The map has 64K slots (256KB total).
     */
    private val VIOLATION_MAP = Arena.ofShared().allocate(65536L * 4)

    init {
        setupSignalHandler()
        // Initialize all slots to -1 (no violation)
        for (i in 0 until 65536) {
            VIOLATION_MAP.set(ValueLayout.JAVA_INT, i.toLong() * 4, -1)
        }
    }

    private fun setupSignalHandler() {
        if (!Platform.isSupported()) return

        try {
            val linker = Linker.nativeLinker()
            val handle = MethodHandles.lookup().findStatic(
                ContainedExecutors::class.java,
                "handleSigSys",
                MethodType.methodType(Void.TYPE, Int::class.javaPrimitiveType, MemorySegment::class.java, MemorySegment::class.java)
            )

            val descriptor = FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            val stub = linker.upcallStub(handle, descriptor, Arena.ofShared())

            Arena.ofConfined().use { arena ->
                val action = arena.allocate(LinuxNative.SIGACTION_LAYOUT)
                action.set(ValueLayout.ADDRESS, 0, stub)
                action.set(ValueLayout.JAVA_INT, LinuxNative.SIGACTION_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("sa_flags")), LinuxNative.SA_SIGINFO)

                val ret = LinuxNative.sigaction(LinuxNative.SIGSYS, action, MemorySegment.NULL)
                if (ret != 0) {
                    logger.severe("Failed to register SIGSYS handler for seccomp traps")
                }
            }
        } catch (e: Exception) {
            logger.log(Level.SEVERE, "Error setting up seccomp signal handler", e)
        }
    }

    /**
     * The native signal handler (upcall). Triggered by the kernel when a seccomp
     * filter returns SECCOMP_RET_TRAP.
     * 
     * This handler MUST be extremely minimal. It reads the blocked syscall number
     * from the siginfo_t structure and records it in the VIOLATION_MAP.
     */
    @JvmStatic
    private fun handleSigSys(sig: Int, info: MemorySegment, ucontext: MemorySegment) {
        val safeInfo = info.reinterpret(128)
        val siCode = safeInfo.get(ValueLayout.JAVA_INT, 8) 
        
        // We need TID. gettid() is async-signal-safe.
        val tid = LinuxNative.gettid()
        val slot = (tid and 0xFFFF).toLong() * 4
        
        if (siCode == 1) { // SYS_SECCOMP
            // si_syscall is at offset 24 on x86_64
            val syscall = safeInfo.get(ValueLayout.JAVA_INT, 24) 
            VIOLATION_MAP.set(ValueLayout.JAVA_INT, slot, syscall)
        } else {
            VIOLATION_MAP.set(ValueLayout.JAVA_INT, slot, 8888)
        }
    }

    internal fun clearViolation() {
        if (!Platform.isSupported()) return
        val tid = LinuxNative.gettid()
        val slot = (tid and 0xFFFF).toLong() * 4
        VIOLATION_MAP.set(ValueLayout.JAVA_INT, slot, -1)
    }

    internal fun getLastViolationSyscall(): Int {
        if (!Platform.isSupported()) return -1
        val tid = LinuxNative.gettid()
        val slot = (tid and 0xFFFF).toLong() * 4
        return VIOLATION_MAP.get(ValueLayout.JAVA_INT, slot)
    }

    private fun checkViolation() {
        val syscall = getLastViolationSyscall()
        if (syscall != -1) {
            throw ContainmentViolationException("Task triggered a blocked syscall: $syscall")
        }
    }

    // Tracks which syscalls are already blocked on this thread via seccomp filters.
    private val THREAD_BLOCKED = ThreadLocal.withInitial { emptySet<Syscall>() }
    
    // Tracks the number of filters installed on this thread. Linux limit is 32.
    private val FILTER_DEPTH = ThreadLocal.withInitial { 0 }

    fun installOnCurrentThread(vararg policies: Policy) {
        if (Thread.currentThread().isVirtual) {
            throw IllegalStateException(
                "Attempted to apply seccomp containment inside a virtual thread. " +
                "This would poison the shared carrier thread and affect other virtual threads. " +
                "Use a dedicated platform thread pool and install containment on its carrier threads instead. " +
                "See the Virtual Threads section in the README for the correct pattern."
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
                logger.warning("Thread ${Thread.currentThread().name} has $depth seccomp filters. High filter depth can degrade performance.")
            }

            val deltaPolicy = Policy.builder().block(*newBlocks.toTypedArray()).build()
            SeccompInstaller.install(deltaPolicy)
            THREAD_BLOCKED.set(currentlyBlocked + newBlocks)
            FILTER_DEPTH.set(depth + 1)
        }
    }

    fun wrap(delegate: ExecutorService, vararg policies: Policy): ExecutorService {
        val combinedPolicy = Policy.combine(*policies)
        val fallback = Platform.configuredFallback()
        val supported = Platform.isSupported()
        
        return ContainedExecutorWrapper(delegate, combinedPolicy, supported, fallback)
    }

    internal fun isContainmentViolation(t: Throwable): Boolean {
        if (getLastViolationSyscall() != -1) {
            return true
        }
        return isDirectContainmentViolation(t) || isViolationInCauseChain(t) || isViolationInSuppressed(t)
    }

    internal fun findViolationCause(t: Throwable): Throwable? {
        if (getLastViolationSyscall() != -1) return t
        
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

    internal class ContainedExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val supported: Boolean,
        private val fallback: Platform.FallbackBehavior
    ) : ExecutorService by delegate {
        
        private fun <T> wrapCallable(task: Callable<T>): Callable<T> = Callable {
            clearViolation()
            applyContainment()
            try {
                val result = task.call()
                checkViolation()
                result
            } catch (e: Exception) {
                if (isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

        private fun wrapRunnable(task: Runnable): Runnable = Runnable {
            clearViolation()
            applyContainment()
            try {
                task.run()
                checkViolation()
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
