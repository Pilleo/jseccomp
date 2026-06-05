package io.mazewall.profiler

import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.profiler.compiler.BobCompiler
import io.mazewall.profiler.engine.DescriptorPassing
import io.mazewall.profiler.engine.ProfilerInstaller
import io.mazewall.profiler.engine.TraceEvent
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicReference
import java.util.logging.Logger

// SUPPRESSION JUSTIFICATION: This class is the central coordinator for the unprivileged system call profiler.
// Keeping the socket setup, trace compilation, daemon life cycle, and thread registering functions together
// maintains the architectural cohesion of the diagnostic engine.

/**
 * High-performance Out-of-Process USER_NOTIF Profiler API.
 */
@Suppress("TooManyFunctions")
object Profiler {
    private val logger = Logger.getLogger(Profiler::class.java.name)
    val threadRegistry = ConcurrentHashMap<Int, Thread>()

    private val daemonLock = Any()
    private var sharedDaemonContext: DaemonContext? = null

    private const val AF_UNIX = 1
    private const val SOCK_STREAM = 1
    private const val ADDR_UN_SIZE = 110
    private const val SOCKADDR_UN_PATH_SIZE = 108
    private const val CMSG_LEN_VAL = 20L
    private const val CMSG_LEN_OFF = 0L
    private const val CMSG_LEVEL_OFF = 8L
    private const val CMSG_TYPE_OFF = 12L
    private const val CMSG_DATA_OFF = 16L
    private const val SOL_SOCKET_VAL = 1
    private const val SCM_RIGHTS_VAL = 1
    private const val DEDUPLICATION_WINDOW_MS = 500L
    private const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
    private const val SHUTDOWN_COMMAND_BYTE = 0x53.toByte() // 'S'
    private const val SHUTDOWN_WAIT_MS = 100L
    private const val DAEMON_CONNECT_MAX_RETRIES = 30
    private const val DAEMON_CONNECT_RETRY_DELAY_MS = 100L
    private const val IO_BUFFER_SIZE = 8192
    private const val BYTE_MASK = 0xFF
    private const val SHUTDOWN_TIMEOUT_MINUTES = 1L

    /**
     * Profiles [block] on a dedicated OS platform thread under a seccomp
     * USER_NOTIF filter and returns both the block's return value and the
     * complete [BillOfBehavior].
     *
     * The lambda runs synchronously — the caller blocks until it completes.
     *
     * ## Thread isolation
     * A fresh OS thread is created for each call. Syscalls from any threads
     * spawned *inside* the lambda are not captured — seccomp USER_NOTIF is
     * per-thread, and profiling child threads requires explicit opt-in not
     * yet provided by this API.
     *
     * ## Stack traces
     * Per-syscall JVM stack traces are captured on a best-effort basis.
     * When the kernel pauses the worker for USER_NOTIF, its Java stack is
     * frozen. The trace listener captures it via [Thread.stackTrace] before
     * the daemon sends FLAG_CONTINUE. Frames are Java-only. There is a brief
     * window between the daemon sending the TraceEvent and the JVM listener
     * reading it; in practice the worker is still in-kernel during this
     * window, but this is not a formal JMM guarantee. Treat traces as
     * diagnostic, not as hard security evidence.
     *
     * @throws IllegalStateException if the profiling infrastructure cannot
     *         be initialised (e.g. PR_SET_NO_NEW_PRIVS failed).
     * @throws IllegalStateException if called from a Loom virtual thread
     *         (would poison the ForkJoinPool carrier — see AGENTS.md Rule B).
     */
    fun <T> profile(block: () -> T): ProfilingResult<T> {
        if (Thread.currentThread().isVirtual) {
            throw IllegalStateException("Seccomp profiling is not supported on Loom virtual threads.")
        }

        val context = getOrSpawnSharedDaemon()

        val localLogs = CopyOnWriteArrayList<TraceEvent>()
        val localStackProfile =
            ConcurrentHashMap<TraceEvent, MutableList<Array<StackTraceElement>>>()
        val localPathCache = ConcurrentHashMap<String, Long>()

        var workerThread: Thread? = null

        try {
            val blockResult = AtomicReference<Any?>(null)
            val blockError = AtomicReference<Throwable?>(null)

            // Dedicated OS platform thread for block
            val thread =
                Thread {
                    val spid = LinuxNative.gettid()
                    threadRegistry[spid] = Thread.currentThread()
                    // SUPPRESSION JUSTIFICATION: We are executing an arbitrary, untrusted user block.
                    // We MUST catch Throwable to ensure we capture any Error or Exception thrown
                    // by the user's workload so we can bubble it up to the calling thread safely.
                    @Suppress("TooGenericExceptionCaught")
                    try {
                        installProfilingFilterForThread(
                            context.socketPath,
                            Policy.PURE_COMPUTE_UNSAFE,
                            localLogs,
                            localStackProfile,
                            localPathCache,
                        ) { workerThread }

                        val res = block()
                        blockResult.set(res)
                    } catch (e: Throwable) {
                        blockError.set(e)
                    } finally {
                        threadRegistry.remove(spid)
                    }
                }

            workerThread = thread
            thread.start()
            thread.join()

            val err = blockError.get()
            if (err != null) throw err

            val behavior =
                BobCompiler.compile(localLogs).copy(
                    stackProfile = localStackProfile.toMap(),
                )

            // SUPPRESSION JUSTIFICATION: blockResult holds the result of the generic `block: () -> T` closure.
            // Because it is stored in an AtomicReference<Any?> to pass across the worker thread boundary,
            // type erasure requires an unchecked cast when retrieving it. This cast is statically safe.
            @Suppress("UNCHECKED_CAST")
            val finalResult = blockResult.get()
            if (finalResult == null) {
                 logger.warning("Profiler.profile: blockResult is null! localLogs size: ${localLogs.size}")
            }
            return ProfilingResult(finalResult as T, behavior)
        } finally {
            // No cleanup here — the shared daemon stays alive until JVM shutdown
        }
    }

    private fun getOrSpawnSharedDaemon(): DaemonContext {
        synchronized(daemonLock) {
            val existing = sharedDaemonContext
            if (existing != null && existing.daemonProcess.isAlive) {
                // Ensure the daemon remains authorized as the tracer for this process.
                // prctl(PR_SET_PTRACER) is process-wide, but calling it multiple times
                // with the same PID is harmless and ensures it wasn't clobbered.
                LinuxNative.prctl(LinuxNative.PR_SET_PTRACER, existing.daemonProcess.pid(), 0, 0, 0)
                return existing
            }
            val newContext = spawnDaemon()
            sharedDaemonContext = newContext
            return newContext
        }
    }

    private fun cleanupDaemon(context: DaemonContext) {
        try {
            Runtime.getRuntime().removeShutdownHook(context.shutdownHook)
        } catch (e: IllegalStateException) {
            // Shutdown already in progress - ignore
            logger.log(java.util.logging.Level.FINE, "Shutdown hook removal skipped: shutdown in progress", e)
        } catch (e: SecurityException) {
            logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
        }
        triggerDaemonShutdown(context.socketPath)
        context.daemonProcess.destroyForcibly()
        try {
            Files.deleteIfExists(context.socketDir.resolve("profiler.sock"))
            Files.deleteIfExists(context.socketDir)
        } catch (e: IOException) {
            logger.log(
                java.util.logging.Level.WARNING,
                "Failed to delete secure socket directory at ${context.socketDir}",
                e,
            )
        }
    }

    private fun triggerDaemonShutdown(socketPath: String) {
        try {
            Arena.ofConfined().use { arena ->
                val fdRes = LinuxNative.socket(AF_UNIX, SOCK_STREAM, 0)
                if (fdRes.returnValue < 0) return
                val fd = fdRes.returnValue.toInt()
                try {
                    val addr = setupSockAddrUn(arena, socketPath)

                    if (LinuxNative.connect(fd, addr, ADDR_UN_SIZE).returnValue == 0L) {
                        val cmd = arena.allocate(1)
                        cmd.set(ValueLayout.JAVA_BYTE, 0L, SHUTDOWN_COMMAND_BYTE)
                        LinuxNative.write(fd, cmd, 1)
                        // Give the daemon a moment to process the shutdown
                        Thread.sleep(SHUTDOWN_WAIT_MS)
                    }
                } finally {
                    LinuxNative.close(fd)
                }
            }
        } catch (e: InterruptedException) {
            // Shutdown errors are harmless as the daemonProcess.destroyForcibly() is called next
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal interrupted (harmless)", e)
            Thread.currentThread().interrupt()
        } catch (e: IllegalArgumentException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        } catch (e: IllegalStateException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        } catch (e: UnsupportedOperationException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        }
    }

    fun wrap(
        delegate: ExecutorService,
        vararg policies: Policy,
    ): ProfilerExecutorWrapper {
        val policy = Policy.combine(*policies)
        val context = getOrSpawnSharedDaemon()
        return ProfilerExecutorWrapper(delegate, policy, context)
    }

    private fun connectWithRetry(
        socketPath: String,
        maxRetries: Int = DAEMON_CONNECT_MAX_RETRIES,
        delayMs: Long = DAEMON_CONNECT_RETRY_DELAY_MS,
    ): Int {
        Arena.ofConfined().use { arena ->
            val addr = setupSockAddrUn(arena, socketPath)

            var lastErrno = 0
            for (retry in 0 until maxRetries) {
                val fdRes = LinuxNative.socket(AF_UNIX, SOCK_STREAM, 0)
                if (fdRes.returnValue < 0) {
                    throw IllegalStateException("Failed to create socket: errno=${fdRes.errno}")
                }
                val fd = fdRes.returnValue.toInt()
                val connRes = LinuxNative.connect(fd, addr, ADDR_UN_SIZE)
                if (connRes.returnValue == 0L) {
                    return fd
                }
                lastErrno = connRes.errno
                LinuxNative.close(fd)

                Thread.sleep(delayMs)
            }
            throw IllegalStateException(
                "Failed to connect to daemon socket at $socketPath after $maxRetries retries. Last errno=$lastErrno",
            )
        }
    }

    private fun sendDescriptor(
        socketFd: Int,
        fdToSend: Int,
    ): Boolean {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            dummyByte.set(ValueLayout.JAVA_BYTE, 0, 0.toByte())

            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            controlBuf.set(ValueLayout.JAVA_LONG, CMSG_LEN_OFF, CMSG_LEN_VAL) // cmsg_len
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_LEVEL_OFF, SOL_SOCKET_VAL) // cmsg_level (SOL_SOCKET = 1)
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_TYPE_OFF, SCM_RIGHTS_VAL) // cmsg_type (SCM_RIGHTS = 1)
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_DATA_OFF, fdToSend)

            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)

            val res = LinuxNative.sendmsg(socketFd, msg, 0)
            return res.returnValue >= 0
        }
    }

    private fun installProfilingFilterForThread(
        socketPath: String,
        policy: Policy,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
    ) {
        ProfilerInstaller.installProfilingFilterForThread(
            socketPath,
            policy,
            accumulatedLogs,
            stackTracesMap,
            pathCache,
            workerThreadProvider,
            { path -> connectWithRetry(path) },
            { fd, logs, traces, cache, provider -> startTraceListener(fd, logs, traces, cache, provider) },
        )
    }

    internal fun sendDescriptorInternal(
        socketFd: Int,
        fdToSend: Int,
    ): Boolean = sendDescriptor(socketFd, fdToSend)

    private fun startTraceListener(
        socketFd: Int,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
    ) {
        val arena = Arena.ofShared()
        val readBuf = arena.allocate(1)
        val multiBuf = arena.allocate(IO_BUFFER_SIZE.toLong())

        val inputStream =
            object : InputStream() {
                override fun read(): Int {
                    val res = LinuxNative.read(socketFd, readBuf, 1)
                    val value =
                        if (res.returnValue <= 0) {
                            -1
                        } else {
                            readBuf.get(ValueLayout.JAVA_BYTE, 0L).toInt() and BYTE_MASK
                        }
                    return value
                }

                override fun read(
                    b: ByteArray,
                    off: Int,
                    len: Int,
                ): Int {
                    if (len == 0) return 0
                    val count = Math.min(len.toLong(), IO_BUFFER_SIZE.toLong())
                    val res = LinuxNative.read(socketFd, multiBuf, count)
                    val readLen =
                        if (res.returnValue <= 0) {
                            -1
                        } else {
                            val actualLen = res.returnValue.toInt()
                            MemorySegment.copy(multiBuf, ValueLayout.JAVA_BYTE, 0L, b, off, actualLen)
                            actualLen
                        }
                    return readLen
                }

                override fun close() {
                    LinuxNative.close(socketFd)
                }
            }

        Thread {
            try {
                val ackBuf = arena.allocate(1)
                ackBuf.set(ValueLayout.JAVA_BYTE, 0L, PROTOCOL_ACK_BYTE) // 0xAC is the protocol ACK byte

                // Wrap in BufferedInputStream to avoid per-byte Arena/FMM allocations in DataInputStream
                val dis = DataInputStream(BufferedInputStream(inputStream))
                while (true) {
                    val pid = dis.readInt()
                    val syscallNameLen = dis.readInt()
                    val syscallNameBytes = ByteArray(syscallNameLen)
                    dis.readFully(syscallNameBytes)
                    val syscallName = String(syscallNameBytes, Charsets.UTF_8)

                    val argsCount = dis.readInt()
                    val args = LongArray(argsCount)
                    for (i in 0 until argsCount) {
                        args[i] = dis.readLong()
                    }

                    val pathsCount = dis.readInt()
                    val paths = mutableListOf<String>()
                    for (i in 0 until pathsCount) {
                        val pathLen = dis.readInt()
                        val pathBytes = ByteArray(pathLen)
                        dis.readFully(pathBytes)
                        paths.add(String(pathBytes, Charsets.UTF_8))
                    }

                    // Now capture the stack trace safely without deadlocking the JVM
                    val threadToProfile = threadRegistry[pid] ?: workerThreadProvider()
                    val stackTrace = threadToProfile?.stackTrace?.map { it.toString() }
                    val event = TraceEvent(pid, syscallName, args, paths, stackTrace)

                    // Deduplicate synchronous events that trigger both Seccomp and Landlock Audit
                    if (paths.isNotEmpty()) {
                        val cacheKey = "$syscallName:${paths.sorted().joinToString(",")}"
                        val now = System.currentTimeMillis()
                        val lastSeen = pathCache[cacheKey] ?: 0L
                        if (now - lastSeen < DEDUPLICATION_WINDOW_MS) {
                            println("[PROFILER] Deduplicated duplicate event for $cacheKey")
                            // Send ACK back to the daemon even for deduplicated events to release the daemon's read()!
                            // ONLY if it's a Seccomp event (pid != 0). Audit events (pid=0) don't expect ACKs.
                            if (pid != 0) {
                                LinuxNative.write(socketFd, ackBuf, 1)
                            }
                            continue // Skip duplicate within 500ms window
                        }
                        pathCache[cacheKey] = now
                    }

                    // Capture stack trace while the worker thread is blocked in-kernel
                    if (stackTracesMap != null) {
                        if (threadToProfile != null) {
                            val frames = threadToProfile.stackTrace
                            stackTracesMap
                                .computeIfAbsent(event) {
                                    CopyOnWriteArrayList<Array<StackTraceElement>>()
                                }.add(frames)
                        }
                    }

                    accumulatedLogs.add(event)

                    // Send ACK back to the daemon so it can release the worker thread!
                    // ONLY if it's a Seccomp event (pid != 0). Audit events (pid=0) don't expect ACKs.
                    if (pid != 0) {
                        LinuxNative.write(socketFd, ackBuf, 1)
                    }
                }
            } catch (e: java.io.IOException) {
                logger.log(java.util.logging.Level.WARNING, "Trace listener error or socket closed", e)
            } finally {
                arena.close()
                inputStream.close()
            }
        }.apply {
            isDaemon = true
            name = "trace-listener-$socketFd"
        }.start()
    }

    class ProfilerExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val context: DaemonContext,
    ) : ExecutorService by delegate {
        private val threadApplied = ThreadLocal.withInitial { false }
        val recentLogs = CopyOnWriteArrayList<TraceEvent>()
        val recentStackProfiles =
            ConcurrentHashMap<TraceEvent, MutableList<Array<StackTraceElement>>>()
        private val sharedPathCache = ConcurrentHashMap<String, Long>()

        /**
         * Compiles the captured logs and stack traces into a [BillOfBehavior].
         */
        fun compileBillOfBehavior(): BillOfBehavior =
            BobCompiler.compile(recentLogs).copy(
                stackProfile = recentStackProfiles.toMap(),
            )

        override fun execute(command: Runnable) {
            delegate.execute {
                val spid = LinuxNative.gettid()
                threadRegistry[spid] = Thread.currentThread()
                try {
                    ensureApplied()
                    command.run()
                } finally {
                    threadRegistry.remove(spid)
                }
            }
        }

        override fun <T> submit(task: Callable<T>): Future<T> =
            delegate.submit(
                Callable {
                    val spid = LinuxNative.gettid()
                    threadRegistry[spid] = Thread.currentThread()
                    try {
                        ensureApplied()
                        task.call()
                    } finally {
                        threadRegistry.remove(spid)
                    }
                },
            )

        override fun <T> submit(
            task: Runnable,
            result: T,
        ): Future<T> =
            delegate.submit({
                val spid = LinuxNative.gettid()
                threadRegistry[spid] = Thread.currentThread()
                try {
                    ensureApplied()
                    task.run()
                } finally {
                    threadRegistry.remove(spid)
                }
            }, result)

        override fun submit(task: Runnable): Future<*> =
            delegate.submit {
                val spid = LinuxNative.gettid()
                threadRegistry[spid] = Thread.currentThread()
                try {
                    ensureApplied()
                    task.run()
                } finally {
                    threadRegistry.remove(spid)
                }
            }

        override fun close() {
            delegate.close()
        }

        private fun ensureApplied() {
            if (Thread.currentThread().isVirtual) {
                throw IllegalStateException("Seccomp profiling is not supported on Loom virtual threads.")
            }
            if (!threadApplied.get()) {
                val currentThread = Thread.currentThread()
                installProfilingFilterForThread(
                    context.socketPath,
                    policy,
                    recentLogs,
                    recentStackProfiles,
                    sharedPathCache,
                ) { currentThread }

                threadApplied.set(true)
            }
        }

        override fun shutdown() {
            delegate.shutdown()
        }

        override fun shutdownNow(): List<Runnable> {
            return delegate.shutdownNow()
        }
    }

    /**
     * Internal context for the profiler daemon.
     */
    data class DaemonContext(
        val socketPath: String,
        val socketDir: Path,
        val daemonProcess: Process,
        val shutdownHook: Thread,
    )

    private fun spawnDaemon(): DaemonContext {
        // Setup secure socket directory with restricted permissions (700)
        val perms = PosixFilePermissions.fromString("rwx------")
        val socketDir = Files.createTempDirectory("mazewall-profiler-", PosixFilePermissions.asFileAttribute(perms))
        val socketPath = socketDir.resolve("profiler.sock").toAbsolutePath().toString()

        // Spawn Daemon
        val javaBin = System.getProperty("java.home") + "/bin/java"
        val classpath = System.getProperty("java.class.path")

        val jvmArgs = java.lang.management.ManagementFactory
            .getRuntimeMXBean()
            .inputArguments
        val jacocoAgent = jvmArgs.find { it.startsWith("-javaagent:") && it.contains("jacoco") }

        val pbArgs = mutableListOf<String>()
        pbArgs.add(javaBin)
        pbArgs.add("--enable-native-access=ALL-UNNAMED")
        if (jacocoAgent != null) {
            pbArgs.add(jacocoAgent)
        }
        pbArgs.add("-cp")
        pbArgs.add(classpath)
        pbArgs.add("io.mazewall.profiler.engine.ProfilerDaemon")
        pbArgs.add(socketPath)

        val pb = ProcessBuilder(pbArgs)
        val daemonProcess = pb.start()
        val daemonPid = daemonProcess.pid()

        // Set the daemon process as our allowed ptrace tracer under Yama ptrace_scope = 1
        LinuxNative.prctl(LinuxNative.PR_SET_PTRACER, daemonPid, 0, 0, 0)

        // Stream daemon errorStream to System.err
        Thread {
            daemonProcess.errorStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    System.err.println("[DAEMON ERR] $line")
                    System.err.flush()
                }
            }
        }.apply {
            isDaemon = true
            name = "profiler-daemon-stderr"
        }.start()

        // Ensure daemon process is cleaned up on JVM exit
        val shutdownHook =
            Thread {
                daemonProcess.destroyForcibly()
            }
        Runtime.getRuntime().addShutdownHook(shutdownHook)

        return DaemonContext(socketPath, socketDir, daemonProcess, shutdownHook)
    }

    private fun setupSockAddrUn(
        arena: Arena,
        socketPath: String,
    ): MemorySegment {
        val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
        addr.fill(0)
        addr.set(ValueLayout.JAVA_SHORT, 0L, AF_UNIX.toShort())
        val pathBytes = socketPath.toByteArray(Charsets.UTF_8)
        val pathSeg = addr.asSlice(2, SOCKADDR_UN_PATH_SIZE.toLong())
        MemorySegment.copy(pathBytes, 0, pathSeg, ValueLayout.JAVA_BYTE, 0L, pathBytes.size)
        return addr
    }
}
