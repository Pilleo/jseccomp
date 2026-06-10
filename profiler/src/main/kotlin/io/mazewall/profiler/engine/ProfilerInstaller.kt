package io.mazewall.profiler.engine

import io.mazewall.BpfFilter
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.ffi.NativeConstants
import io.mazewall.profiler.Profiler
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Internal helper for installing seccomp profiling filters.
 */
internal object ProfilerInstaller {
    fun installProfilingFilterForThread(
        socketPath: String,
        policy: Policy,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
        connectWithRetry: (String) -> Int,
        startTraceListener: (Int, MutableList<TraceEvent>, MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?, MutableMap<String, Long>, () -> Thread?) -> Unit,
    ) {
        val installLatch = CountDownLatch(1)
        val proceedLatch = CountDownLatch(1)
        val listenerFd = AtomicInteger(-1)
        val installError = AtomicReference<Throwable?>(null)

        val coordinatorThread =
            Thread {
                runCoordinatorLogic(
                    installLatch,
                    listenerFd,
                    installError,
                    socketPath,
                    accumulatedLogs,
                    stackTracesMap,
                    pathCache,
                    workerThreadProvider,
                    connectWithRetry,
                    startTraceListener,
                    proceedLatch,
                )
            }.apply {
                isDaemon = true
                name = "profiler-coordinator"
                uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, e ->
                    installError.set(e)
                    proceedLatch.countDown()
                }
            }

        coordinatorThread.start()

        try {
            ensureNoNewPrivs()
            val filters = BpfFilter.build(Arch.current(), policy, profilingMode = true)
            installProfilingBpf(filters, listenerFd)
        } catch (e: IOException) {
            installError.set(e)
            proceedLatch.countDown()
        } catch (e: IllegalStateException) {
            installError.set(e)
            proceedLatch.countDown()
        } finally {
            installLatch.countDown()
        }

        proceedLatch.await()
        installError.get()?.let { throw it }
    }

    private fun runCoordinatorLogic(
        installLatch: CountDownLatch,
        listenerFd: AtomicInteger,
        installError: AtomicReference<Throwable?>,
        socketPath: String,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
        connectWithRetry: (String) -> Int,
        startTraceListener: (Int, MutableList<TraceEvent>, MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?, MutableMap<String, Long>, () -> Thread?) -> Unit,
        proceedLatch: CountDownLatch,
    ) {
        installLatch.await()
        val fd = listenerFd.get()
        if (fd < 0) {
            val err = installError.get() ?: IllegalStateException("Failed to install seccomp filter")
            throw err
        }

        var socketFd = -1
        var success = false
        try {
            socketFd = connectWithRetry(socketPath)
            val sent = Profiler.sendDescriptorInternal(socketFd, fd)
            if (!sent) {
                throw IllegalStateException("Failed to send seccomp listener FD to daemon")
            }

            verifyDaemonAck(socketFd)

            // Start listener thread for this socket to receive TraceEvents
            startTraceListener(socketFd, accumulatedLogs, stackTracesMap, pathCache, workerThreadProvider)
            success = true
            proceedLatch.countDown()
        } finally {
            if (!success) {
                if (socketFd != -1) {
                    LinuxNative.close(socketFd)
                }
            }
            LinuxNative.close(fd)
        }
    }

    private fun verifyDaemonAck(socketFd: Int) {
        // Wait for ACK byte from daemon
        Arena.ofConfined().use { arena ->
            val ackBuf = arena.allocate(1)
            val res = LinuxNative.read(socketFd, ackBuf, 1)
            if (res.returnValue != 1L || ackBuf.get(ValueLayout.JAVA_BYTE, 0) != 0xAC.toByte()) {
                throw IllegalStateException("Daemon failed to ACK listener receipt")
            }
        }
    }

    private fun ensureNoNewPrivs() {
        val r = LinuxNative.prctl(NativeConstants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if (r.returnValue != 0L) {
            throw IllegalStateException("prctl(PR_SET_NO_NEW_PRIVS) failed with errno ${r.errno}")
        }
    }

    private fun installProfilingBpf(
        filters: Array<io.mazewall.SockFilter>,
        listenerFd: AtomicInteger,
    ) {
        val arch = Arch.current()
        Arena.ofConfined().use { arena ->
            val prog = LinuxNative.newSockFProg(arena, filters)
            val r =
                LinuxNative.syscall(
                    arch.seccompSyscallNumber.toLong(),
                    NativeConstants.SECCOMP_SET_MODE_FILTER.toLong(),
                    NativeConstants.SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    prog,
                )

            if (r.returnValue < 0) {
                throw IllegalStateException("Failed to install seccomp profiling listener: errno=${r.errno}")
            }

            listenerFd.set(r.returnValue.toInt())
        }
    }
}
