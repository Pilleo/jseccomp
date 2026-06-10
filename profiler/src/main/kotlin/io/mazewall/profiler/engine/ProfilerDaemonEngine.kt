package io.mazewall.profiler.engine

import io.mazewall.Arch
import io.mazewall.LinuxNative
import io.mazewall.Syscall
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

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
    private val clientSockets = CopyOnWriteArrayList<Int>()
    private val activeListeners = CopyOnWriteArrayList<Int>()
    private val isGlobalShutdown = AtomicBoolean(false)

    init {
        val arch = Arch.current()
        for (s in Syscall.entries) {
            val nr = s.numberFor(arch)
            if (nr >= 0) syscallMap[nr] = s.name
        }
    }

    fun run() {
        Arena.ofConfined().use { arena ->
            val serverFd = createServerSocket()
            try {
                val addr = prepareSocketAddr(arena, socketPath)
                bindAndListen(serverFd, addr)
                acceptConnections(serverFd, arena)
            } finally {
                LinuxNative.close(serverFd)
            }
        }
    }

    fun triggerGlobalShutdown(source: String = "unknown") {
        if (isGlobalShutdown.getAndSet(true)) return
        System.err.println("[DAEMON] Initiating graceful shutdown. Source: $source. Releasing tracee threads...")
    }

    private fun createServerSocket(): Int {
        val bindRes = LinuxNative.socket(AF_UNIX, SOCK_STREAM, 0)
        if (bindRes.returnValue < 0) {
            throw IllegalStateException("Failed to create daemon socket: errno=${bindRes.errno}")
        }
        return bindRes.returnValue.toInt()
    }

    private fun prepareSocketAddr(
        arena: Arena,
        socketPath: String,
    ): MemorySegment {
        val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
        addr.fill(0)
        addr.set(ValueLayout.JAVA_SHORT, 0L, AF_UNIX.toShort())

        val pathBytes = socketPath.toByteArray(StandardCharsets.UTF_8)
        val pathSeg = addr.asSlice(2, SOCKADDR_UN_PATH_SIZE.toLong())
        MemorySegment.copy(pathBytes, 0, pathSeg, ValueLayout.JAVA_BYTE, 0L, pathBytes.size)
        return addr
    }

    private fun bindAndListen(
        serverFd: Int,
        addr: MemorySegment,
    ) {
        val bindRes = LinuxNative.bind(serverFd, addr, ADDR_UN_SIZE)
        if (bindRes.returnValue < 0) {
            throw IllegalStateException("Failed to bind daemon socket: errno=${bindRes.errno}")
        }

        val listenRes = LinuxNative.listen(serverFd, BACKLOG_SIZE)
        if (listenRes.returnValue < 0) {
            throw IllegalStateException("Failed to listen on daemon socket: errno=${listenRes.errno}")
        }
        System.err.println("[DAEMON] Listening on $socketPath (fd=$serverFd)")
    }

    private fun acceptConnections(
        serverFd: Int,
        arena: Arena,
    ) {
        val pollFd = arena.allocate(LinuxNative.POLLFD_LAYOUT)
        pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, serverFd)
        pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, LinuxNative.POLLIN)

        while (!isGlobalShutdown.get()) {
            val pollRes = transport.poll(pollFd, 1L, POLL_TIMEOUT_MS)
            if (pollRes.returnValue <= 0) {
                if (pollRes.returnValue < 0L && pollRes.errno != EINTR) break
                continue
            }
            handleNewConnection(serverFd)
        }
    }

    private fun handleNewConnection(serverFd: Int) {
        val clientRes = LinuxNative.accept(serverFd, MemorySegment.NULL, MemorySegment.NULL)
        if (clientRes.returnValue >= 0) {
            val clientFd = clientRes.returnValue.toInt()
            clientSockets.add(clientFd)
            Thread { handleConnection(clientFd) }.apply {
                name = "conn-handler-$clientFd"
                start()
            }
        }
    }

    @Suppress("NestedBlockDepth", "LoopWithTooManyJumpStatements")
    private fun handleConnection(socketFd: Int) {
        try {
            Arena.ofConfined().use { arena ->
                val pollFd = arena.allocate(LinuxNative.POLLFD_LAYOUT)
                pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, socketFd)
                pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, LinuxNative.POLLIN)

                while (!isGlobalShutdown.get()) {
                    val pollRes = transport.poll(pollFd, 1L, POLL_TIMEOUT_MS)
                    if (pollRes.returnValue <= 0) {
                        if (pollRes.returnValue < 0L && pollRes.errno != EINTR) break
                        continue
                    }
                    if (!receiveAndHandleListener(socketFd)) break
                }
            }
        } finally {
            clientSockets.remove(socketFd)
            LinuxNative.close(socketFd)
        }
    }

    private fun receiveAndHandleListener(socketFd: Int): Boolean {
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
                name = "listener-handler-$listenerFd"
                start()
            }.join() // Process one session per connection sequentially for simplicity
        return true
    }

    @Suppress("NestedBlockDepth", "LoopWithTooManyJumpStatements")
    private fun handleSession(
        socketFd: Int,
        listenerFd: Int,
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
                val notif = arena.allocate(LinuxNative.SECCOMP_NOTIF_LAYOUT)
                val resp = arena.allocate(LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT)
                val ackBuf = arena.allocate(ACK_BUF_SIZE)

                while (!isGlobalShutdown.get()) {
                    val pollRes = transport.poll(pollFds, 2L, POLL_TIMEOUT_MS)
                    if (pollRes.returnValue <= 0) {
                        if (pollRes.returnValue < 0L && pollRes.errno != EINTR) break
                        continue
                    }

                    val action = sessionHandler.handleActiveListener(pollFds, ackBuf, notif, resp)
                    if (action !is LoopAction.Continue) break
                }
            }
        } finally {
            activeListeners.remove(listenerFd)
            LinuxNative.close(listenerFd)
        }
    }

    private fun setupSessionPoll(
        arena: Arena,
        socketFd: Int,
        listenerFd: Int,
    ): MemorySegment {
        val pollFds = arena.allocate(MemoryLayout.sequenceLayout(2, LinuxNative.POLLFD_LAYOUT))
        // [0]: Seccomp listener FD
        pollFds.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, listenerFd)
        pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, LinuxNative.POLLIN)
        // [1]: UNIX socket FD (for parent shutdown/ACK)
        pollFds.set(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG.byteSize(), socketFd)
        pollFds.set(ValueLayout.JAVA_SHORT, ValueLayout.JAVA_LONG.byteSize() + POLLFD_EVENTS_OFF, LinuxNative.POLLIN)
        return pollFds
    }
}
