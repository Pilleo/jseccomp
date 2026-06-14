package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import io.mazewall.core.Arch
import io.mazewall.core.Syscall
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Standalone Profiler Daemon Engine.
 *
 * Communicates with the parent JVM via a [ProfilerTransport], sending binary [TraceEvent]
 * structures and resolving memory using [ProfilerMemoryReader].
 */
internal class ProfilerDaemonEngine(
    private val socketPath: String,
    private val transport: ProfilerTransport = RealProfilerTransport,
    private val memoryReader: ProfilerMemoryReader = RealMemoryReader,
) {
    private val syscallMap = mutableMapOf<Int, String>()
    private val clientSockets = CopyOnWriteArrayList<LinuxNative.FileDescriptor>()
    private val activeListeners = CopyOnWriteArrayList<LinuxNative.FileDescriptor>()
    private val stateRef = java.util.concurrent.atomic
        .AtomicReference<ProfilerDaemonState>(ProfilerDaemonState.Uninitialized)

    var state: ProfilerDaemonState
        get() = stateRef.get()
        private set(value) = stateRef.set(value)

    companion object {
        private const val DAEMON_READY_SENTINEL = "MAZEWALL_DAEMON_READY"
        private const val POLL_TIMEOUT_MS = 1000
        private const val POLLFD_FD_OFF = 0L
        private const val POLLFD_EVENTS_OFF = 4L
        private const val ACK_BUF_SIZE = 1L
        private const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
        private const val POLLFD_STRUCT_SIZE = 8L
    }

    init {
        val arch = Arch.current()
        for (s in Syscall.entries) {
            val nr = s.numberFor(arch)
            if (nr >= 0) syscallMap[nr] = s.name
        }
    }

    fun run() {
        val serverFd = transport.createServer(socketPath)
        state = ProfilerDaemonState.Listening(serverFd, socketPath)
        System.err.println("[DAEMON] Listening on $socketPath (fd=$serverFd)")

        // Signal readiness to parent process via stdout sentinel
        println(DAEMON_READY_SENTINEL)
        System.out.flush()

        try {
            Arena.ofConfined().use { arena ->
                state = ProfilerDaemonState.Active(serverFd)
                acceptConnections(serverFd, arena)
            }
        } finally {
            state = ProfilerDaemonState.Terminated
            transport.close(serverFd)
        }
    }

    fun triggerGlobalShutdown(source: String = "unknown") {
        while (true) {
            val curr = stateRef.get()
            if (curr is ProfilerDaemonState.ShuttingDown || curr is ProfilerDaemonState.Terminated) return
            if (stateRef.compareAndSet(curr, ProfilerDaemonState.ShuttingDown)) {
                System.err.println("[DAEMON] Initiating graceful shutdown. Source: $source. Releasing tracee threads...")
                break
            }
        }
    }

    private fun isGlobalShutdown(): Boolean {
        val curr = state
        return curr is ProfilerDaemonState.ShuttingDown || curr is ProfilerDaemonState.Terminated
    }

    @Suppress("LoopWithTooManyJumpStatements")
    private fun acceptConnections(
        serverFd: LinuxNative.FileDescriptor,
        arena: Arena,
    ) {
        val pollFd = arena.allocate(Layouts.POLLFD)
        pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, serverFd.value)
        pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, NativeConstants.POLLIN.toShort())

        while (!isGlobalShutdown()) {
            val pollRes = transport.poll(pollFd, 1L, POLL_TIMEOUT_MS)
            when (pollRes) {
                is LinuxNative.SyscallResult.Success -> {
                    if (pollRes.value <= 0) continue
                }

                is LinuxNative.SyscallResult.Error -> {
                    if (pollRes.errno != EINTR) break // Not EINTR
                    continue
                }
            }
            handleNewConnection(serverFd)
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun handleNewConnection(serverFd: LinuxNative.FileDescriptor) {
        try {
            val clientFd = transport.accept(serverFd)
            clientSockets.add(clientFd)
            Thread { handleConnection(clientFd) }.apply {
                name = "conn-handler-${clientFd.value}"
                start()
            }
        } catch (e: Exception) {
            // Socket closed or accept failed during shutdown
        }
    }

    @Suppress("NestedBlockDepth", "LoopWithTooManyJumpStatements")
    private fun handleConnection(socketFd: LinuxNative.FileDescriptor) {
        try {
            Arena.ofConfined().use { arena ->
                val pollFd = arena.allocate(Layouts.POLLFD)
                pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, socketFd.value)
                pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, NativeConstants.POLLIN.toShort())

                while (!isGlobalShutdown()) {
                    val pollRes = transport.poll(pollFd, 1L, POLL_TIMEOUT_MS)
                    when (pollRes) {
                        is LinuxNative.SyscallResult.Success -> {
                            if (pollRes.value <= 0) continue
                        }

                        is LinuxNative.SyscallResult.Error -> {
                            if (pollRes.errno != EINTR) break // Not EINTR
                            continue
                        }
                    }
                    if (!receiveAndHandleListener(socketFd)) break
                }
            }
        } finally {
            clientSockets.remove(socketFd)
            transport.close(socketFd)
        }
    }

    private fun receiveAndHandleListener(socketFd: LinuxNative.FileDescriptor): Boolean {
        val listenerFd = transport.recvDescriptor(socketFd) ?: return false
        activeListeners.add(listenerFd)

        // Send ACK byte to notify receipt of listener FD
        Arena.ofConfined().use { arena ->
            val ackBuf = arena.allocate(ACK_BUF_SIZE)
            ackBuf.set(ValueLayout.JAVA_BYTE, 0L, PROTOCOL_ACK_BYTE)
            transport.write(socketFd, ackBuf, ACK_BUF_SIZE)
        }

        Thread { handleSession(socketFd, listenerFd) }
            .apply {
                name = "listener-handler-${listenerFd.value}"
                start()
            }.join() // Process one session per connection sequentially for simplicity
        return true
    }

    @Suppress("NestedBlockDepth", "LoopWithTooManyJumpStatements")
    private fun handleSession(
        socketFd: LinuxNative.FileDescriptor,
        listenerFd: LinuxNative.FileDescriptor,
    ) {
        val sessionHandler = ProfilerSessionHandler(
            socketFd,
            listenerFd,
            transport,
            memoryReader,
            syscallMap,
            this::triggerGlobalShutdown,
        )
        try {
            Arena.ofConfined().use { arena ->
                val pollFds = setupSessionPoll(arena, socketFd, listenerFd)
                val notif = arena.allocate(Layouts.SECCOMP_NOTIF)
                val resp = arena.allocate(Layouts.SECCOMP_NOTIF_RESP)
                val ackBuf = arena.allocate(ACK_BUF_SIZE)
                val socketPollFd = arena.allocate(Layouts.POLLFD)

                while (!isGlobalShutdown()) {
                    val pollRes = transport.poll(pollFds, 2L, POLL_TIMEOUT_MS)
                    when (pollRes) {
                        is LinuxNative.SyscallResult.Success -> {
                            if (pollRes.value <= 0) continue
                        }

                        is LinuxNative.SyscallResult.Error -> {
                            if (pollRes.errno != EINTR) break // Not EINTR
                            continue
                        }
                    }

                    val action = sessionHandler.handleActiveListener(pollFds, ackBuf, notif, resp, socketPollFd)
                    if (action !is LoopAction.Continue) break
                }
            }
        } finally {
            activeListeners.remove(listenerFd)
            transport.close(listenerFd)
        }
    }

    private fun setupSessionPoll(
        arena: Arena,
        socketFd: LinuxNative.FileDescriptor,
        listenerFd: LinuxNative.FileDescriptor,
    ): MemorySegment {
        val pollFds = arena.allocate(MemoryLayout.sequenceLayout(2, Layouts.POLLFD))
        // [0]: Seccomp listener FD
        pollFds.set(ValueLayout.JAVA_INT, 0L, listenerFd.value)
        pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, NativeConstants.POLLIN.toShort())
        // [1]: UNIX socket FD (for parent shutdown/ACK)
        pollFds.set(ValueLayout.JAVA_INT, POLLFD_STRUCT_SIZE, socketFd.value)
        pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_STRUCT_SIZE + POLLFD_EVENTS_OFF, NativeConstants.POLLIN.toShort())
        return pollFds
    }
}
