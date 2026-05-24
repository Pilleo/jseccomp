package io.mazewall.profiler

import io.mazewall.Arch
import io.mazewall.BpfFilter
import io.mazewall.LinuxNative
import io.mazewall.Policy
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.logging.Logger

/**
 * High-performance Out-of-Process USER_NOTIF Profiler API.
 */
object Profiler {
    private val logger = Logger.getLogger(Profiler::class.java.name)

    private const val ADDR_UN_SIZE = 110
    private const val CMSG_LEN_VAL = 20L
    private const val CMSG_LEN_OFF = 0L
    private const val CMSG_LEVEL_OFF = 8L
    private const val CMSG_TYPE_OFF = 12L
    private const val CMSG_DATA_OFF = 16L
    private const val SOL_SOCKET_VAL = 1
    private const val SCM_RIGHTS_VAL = 1
    private const val DEDUPLICATION_WINDOW_MS = 500L

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

        val (socketPath, daemonProcess, shutdownHook) = spawnDaemon()

        val localLogs = CopyOnWriteArrayList<TraceEvent>()
        val localStackProfile =
            ConcurrentHashMap<TraceEvent, MutableList<Array<StackTraceElement>>>()
        val localPathCache = ConcurrentHashMap<String, Long>()

        var workerThread: Thread? = null

        try {
            var blockResult: Any? = null
            var blockError: Throwable? = null

            // Dedicated OS platform thread for block
            val thread =
                Thread {
                    installProfilingFilterForThread(
                        socketPath,
                        Policy.PURE_COMPUTE,
                        localLogs,
                        localStackProfile,
                        localPathCache,
                    ) { workerThread }

                    blockResult = block()
                }

            thread.uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, e ->
                blockError = e
            }

            workerThread = thread
            thread.start()
            thread.join()

            val err = blockError
            if (err != null) throw err

            val behavior =
                BobCompiler.compile(localLogs).copy(
                    stackProfile = localStackProfile.toMap(),
                )

            @Suppress("UNCHECKED_CAST")
            return ProfilingResult(blockResult as T, behavior)
        } finally {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook)
            } catch (e: IllegalStateException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
            } catch (e: SecurityException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
            }
            triggerDaemonShutdown(socketPath)
            daemonProcess.destroyForcibly()
            try {
                File(socketPath).delete()
            } catch (e: SecurityException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to delete socket file at $socketPath", e)
            }
        }
    }

    private fun triggerDaemonShutdown(socketPath: String) {
        try {
            Arena.ofConfined().use { arena ->
                val fdRes = LinuxNative.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0)
                if (fdRes.returnValue < 0) return
                val fd = fdRes.returnValue.toInt()
                try {
                    val addr = setupSockAddrUn(arena, socketPath)

                    if (LinuxNative.connect(fd, addr, ADDR_UN_SIZE).returnValue == 0L) {
                        val cmd = arena.allocate(1)
                        cmd.set(ValueLayout.JAVA_BYTE, 0L, 0x53.toByte()) // 'S' for Shutdown
                        LinuxNative.write(fd, cmd, 1)
                        // Give the daemon a moment to process the shutdown
                        Thread.sleep(100)
                    }
                } finally {
                    LinuxNative.close(fd)
                }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    fun wrap(
        delegate: ExecutorService,
        vararg policies: Policy,
    ): ProfilerExecutorWrapper {
        val policy = Policy.combine(*policies)

        val (socketPath, daemonProcess, shutdownHook) = spawnDaemon()

        return ProfilerExecutorWrapper(delegate, policy, socketPath, daemonProcess, shutdownHook)
    }

    private fun connectWithRetry(
        socketPath: String,
        maxRetries: Int = 30,
        delayMs: Long = 100,
    ): Int {
        Arena.ofConfined().use { arena ->
            val addr = setupSockAddrUn(arena, socketPath)

            var lastErrno = 0
            for (retry in 0 until maxRetries) {
                val fdRes = LinuxNative.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0)
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
            { fd, logs, traces, cache, provider -> startTraceListener(fd, logs, traces, cache, provider) }
        )
    }

    internal fun sendDescriptorInternal(socketFd: Int, fdToSend: Int): Boolean =
        sendDescriptor(socketFd, fdToSend)

    private fun startTraceListener(
        socketFd: Int,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
    ) {
        val arena = Arena.ofShared()
        val readBuf = arena.allocate(1)
        val ackBuf = arena.allocate(1)
        ackBuf.set(ValueLayout.JAVA_BYTE, 0L, 0x41.toByte()) // ACK byte
        val multiBuf = arena.allocate(8192)

        val inputStream =
            object : InputStream() {
                override fun read(): Int {
                    val res = LinuxNative.read(socketFd, readBuf, 1)
                    val value =
                        if (res.returnValue <= 0) {
                            -1
                        } else {
                            readBuf.get(ValueLayout.JAVA_BYTE, 0L).toInt() and 0xFF
                        }
                    return value
                }

                override fun read(
                    b: ByteArray,
                    off: Int,
                    len: Int,
                ): Int {
                    if (len == 0) return 0
                    val count = Math.min(len.toLong(), 8192L)
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

                    val event = TraceEvent(pid, syscallName, args, paths)

                    // Deduplicate synchronous events that trigger both Seccomp and Landlock Audit
                    if (paths.isNotEmpty()) {
                        val cacheKey = "$syscallName:${paths.sorted().joinToString(",")}"
                        val now = System.currentTimeMillis()
                        val lastSeen = pathCache[cacheKey] ?: 0L
                        if (now - lastSeen < DEDUPLICATION_WINDOW_MS) {
                            println("[PROFILER] Deduplicated duplicate event for $cacheKey")
                            // Write ACK to daemon so the daemon doesn't hang!
                            // ONLY if it's a Seccomp event (pid != 0).
                            if (pid != 0) {
                                LinuxNative.write(socketFd, ackBuf, 1)
                            }
                            continue // Skip duplicate within 500ms window
                        }
                        pathCache[cacheKey] = now
                    }

                    // Capture stack trace while the worker thread is blocked in-kernel
                    if (stackTracesMap != null) {
                        val workerThread = workerThreadProvider()
                        if (workerThread != null) {
                            val frames = workerThread.stackTrace
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
        private val socketPath: String,
        private val daemonProcess: Process,
        private val shutdownHook: Thread,
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
                ensureApplied()
                command.run()
            }
        }

        override fun <T> submit(task: Callable<T>): Future<T> =
            delegate.submit(
                Callable {
                    ensureApplied()
                    task.call()
                },
            )

        override fun <T> submit(
            task: Runnable,
            result: T,
        ): Future<T> =
            delegate.submit({
                ensureApplied()
                task.run()
            }, result)

        override fun submit(task: Runnable): Future<*> =
            delegate.submit {
                ensureApplied()
                task.run()
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
                    socketPath,
                    policy,
                    recentLogs,
                    recentStackProfiles,
                    sharedPathCache,
                ) { currentThread }

                threadApplied.set(true)
            }
        }

        override fun shutdown() {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook)
            } catch (e: IllegalStateException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
            } catch (e: SecurityException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
            } finally {
                delegate.shutdown()
                // Do NOT destroy daemon immediately, as worker threads may still be in-kernel!
                // Instead, wait for termination in a separate daemon thread to release resources cleanly.
                Thread {
                    try {
                        delegate.awaitTermination(1, TimeUnit.MINUTES)
                    } finally {
                        daemonProcess.destroy()
                    }
                }.apply {
                    isDaemon = true
                    name = "profiler-shutdown-waiter"
                }.start()
            }
        }

        override fun shutdownNow(): List<Runnable> {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook)
            } catch (e: IllegalStateException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook during shutdownNow", e)
            } catch (e: SecurityException) {
                logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook during shutdownNow", e)
            } finally {
                val tasks = delegate.shutdownNow()
                triggerDaemonShutdown(socketPath)
                daemonProcess.destroyForcibly()
                return tasks
            }
        }
    }

    private data class DaemonContext(
        val socketPath: String,
        val daemonProcess: Process,
        val shutdownHook: Thread,
    )

    private fun spawnDaemon(): DaemonContext {
        // Setup socket path
        val socketFile = File.createTempFile("mazewall-profiler-", ".sock")
        socketFile.delete() // delete so bind can create it
        val socketPath = socketFile.absolutePath

        // Spawn Daemon
        val javaBin = System.getProperty("java.home") + "/bin/java"
        val classpath = System.getProperty("java.class.path")
        val pb =
            ProcessBuilder(
                javaBin,
                "--enable-native-access=ALL-UNNAMED",
                "-cp",
                classpath,
                "io.mazewall.profiler.ProfilerDaemon",
                socketPath,
            )
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

        return DaemonContext(socketPath, daemonProcess, shutdownHook)
    }

    private fun setupSockAddrUn(
        arena: Arena,
        socketPath: String,
    ): MemorySegment {
        val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
        addr.fill(0)
        addr.set(ValueLayout.JAVA_SHORT, 0L, 1.toShort()) // AF_UNIX = 1
        val pathBytes = socketPath.toByteArray(Charsets.UTF_8)
        val pathSeg = addr.asSlice(2, 108)
        MemorySegment.copy(pathBytes, 0, pathSeg, ValueLayout.JAVA_BYTE, 0L, pathBytes.size)
        return addr
    }
}
