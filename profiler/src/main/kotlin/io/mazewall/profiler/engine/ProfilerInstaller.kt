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

/**
 * Internal helper for installing seccomp profiling filters.
 */
internal object ProfilerInstaller {
    fun installProfilingFilterForThread(
        socketPath: String,
        policy: Policy<*, *>,
        accumulatedLogs: MutableList<TraceEvent>,
        stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
        pathCache: MutableMap<String, Long>,
        workerThreadProvider: () -> Thread?,
        connectWithRetry: (String) -> Int,
        startTraceListener: (Int, MutableList<TraceEvent>, MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?, MutableMap<String, Long>, () -> Thread?) -> Unit,
    ) {
        val session = ProfilerInstallerSession(
            socketPath = socketPath,
            policy = policy,
            accumulatedLogs = accumulatedLogs,
            stackTracesMap = stackTracesMap,
            pathCache = pathCache,
            workerThreadProvider = workerThreadProvider,
            connectWithRetry = connectWithRetry,
            startTraceListener = startTraceListener,
        )
        session.install()
    }
}

internal class ProfilerInstallerSession(
    private val socketPath: String,
    private val policy: Policy<*, *>,
    private val accumulatedLogs: MutableList<TraceEvent>,
    private val stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
    private val pathCache: MutableMap<String, Long>,
    private val workerThreadProvider: () -> Thread?,
    private val connectWithRetry: (String) -> Int,
    private val startTraceListener: (Int, MutableList<TraceEvent>, MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?, MutableMap<String, Long>, () -> Thread?) -> Unit,
) {
    private val installLatch = CountDownLatch(1)
    private val proceedLatch = CountDownLatch(1)
    private val listenerFd = AtomicInteger(-1)

    @Volatile
    var state: ProfilerInstallerState = ProfilerInstallerState.Uninitialized
        private set

    fun install() {
        state = ProfilerInstallerState.InstallingBpf

        val coordinatorThread =
            Thread {
                runCoordinatorLogic()
            }.apply {
                isDaemon = true
                name = "profiler-coordinator"
                uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, e ->
                    this@ProfilerInstallerSession.state = ProfilerInstallerState.Failed(e)
                    proceedLatch.countDown()
                }
            }

        coordinatorThread.start()

        try {
            ensureNoNewPrivs()
            val filters = BpfFilter.build(Arch.current(), policy, profilingMode = true)
            installProfilingBpf(filters, listenerFd)
        } catch (e: IOException) {
            state = ProfilerInstallerState.Failed(e)
            proceedLatch.countDown()
        } catch (e: IllegalStateException) {
            state = ProfilerInstallerState.Failed(e)
            proceedLatch.countDown()
        } finally {
            installLatch.countDown()
        }

        proceedLatch.await()
        val finalState = state
        if (finalState is ProfilerInstallerState.Failed) {
            throw finalState.error
        }
    }

    private fun runCoordinatorLogic() {
        installLatch.await()
        val fd = listenerFd.get()
        if (fd < 0) {
            val finalState = state
            val err = if (finalState is ProfilerInstallerState.Failed) {
                finalState.error
            } else {
                IllegalStateException("Failed to install seccomp filter")
            }
            throw err
        }

        state = ProfilerInstallerState.Connecting(fd)
        var socketFd = -1
        var success = false
        try {
            socketFd = connectWithRetry(socketPath)
            state = ProfilerInstallerState.SendingDescriptor(fd, socketFd)
            val sent = Profiler.sendDescriptorInternal(socketFd, fd)
            if (!sent) {
                throw IllegalStateException("Failed to send seccomp listener FD to daemon")
            }

            state = ProfilerInstallerState.VerifyingAck(fd, socketFd)
            verifyDaemonAck(socketFd)

            // Start listener thread for this socket to receive TraceEvents
            startTraceListener(socketFd, accumulatedLogs, stackTracesMap, pathCache, workerThreadProvider)
            state = ProfilerInstallerState.Active(fd, socketFd)
            success = true
            proceedLatch.countDown()
        } catch (e: IOException) {
            state = ProfilerInstallerState.Failed(e)
            proceedLatch.countDown()
        } catch (e: IllegalStateException) {
            state = ProfilerInstallerState.Failed(e)
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
            while (true) {
                val res = LinuxNative.read(socketFd, ackBuf, 1)
                if (res.returnValue == 1L && ackBuf.get(ValueLayout.JAVA_BYTE, 0) == 0xAC.toByte()) {
                    return
                }
                if (res.returnValue < 0 && res.errno == EINTR) {
                    continue
                }
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
            val prog = with(arena) { LinuxNative.newSockFProg(filters) }
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
