package io.mazewall.profiler.engine

import io.mazewall.Arch
import io.mazewall.LinuxNative
import io.mazewall.Syscall
import java.io.DataOutputStream
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.system.exitProcess

// SUPPRESSION JUSTIFICATION: This class manages the out-of-process daemon loop, descriptor-passing,
// socket connections, and signal notifications. Breaking this highly cohesive daemon engine into
// smaller, arbitrary helper files would obscure its synchronous protocol lifecycle.

/**
 * Standalone Profiler Daemon Process.
 *
 * Communicates with the parent JVM via a Unix Domain Socket, sending binary [TraceEvent]
 * structures.
 */
@Suppress("TooManyFunctions")
object ProfilerDaemon {
    private val logger = Logger.getLogger(ProfilerDaemon::class.java.name)
    private val syscallMap = mutableMapOf<Int, String>()
    private val clientSockets = CopyOnWriteArrayList<Int>()
    private val socketLocks = java.util.concurrent.ConcurrentHashMap<Int, Any>()
    private val activeListeners = CopyOnWriteArrayList<Int>()
    private val isGlobalShutdown = AtomicBoolean(false)

    private const val ADDR_UN_SIZE = 110
    private const val SOCKADDR_UN_PATH_SIZE = 108
    private const val BACKLOG_SIZE = 128
    private const val AF_UNIX = 1
    private const val SOCK_STREAM = 1
    private const val MSG_PEEK = 2
    private const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
    private const val SHUTDOWN_COMMAND_BYTE = 0x53.toByte() // 'S'
    private const val ACK_BUF_SIZE = 1L
    private const val NOTIF_ID_OFF = 0L
    private const val NOTIF_PID_OFF = 8L
    private const val NOTIF_NR_OFF = 16L
    private const val NOTIF_ARGS_OFF = 32L
    private const val F_SETFL_VAL = 4
    private const val O_NONBLOCK_VAL = 2048L
    private const val CMSG_DATA_OFF = 16L
    private const val IOV_LEN_OFF = 8L
    private const val AT_FDCWD_VAL = -100L
    private const val AT_FDCWD_UNSIGNED_VAL = 4294967196L
    private const val AT_FDCWD_INT_VAL = -100
    private const val PATH_MAX_VAL = 4096L
    private const val RESP_ID_OFF = 0L
    private const val RESP_VAL_OFF = 8L
    private const val RESP_ERR_OFF = 16L
    private const val RESP_FLAGS_OFF = 20L
    private const val POLLFD_FD_OFF = 0L
    private const val POLLFD_EVENTS_OFF = 4L
    private const val POLLFD_REVENTS_OFF = 6L

    private const val EINTR = 4
    private const val EAGAIN = 11
    private const val POLL_TIMEOUT_MS = 100
    private const val SHUTDOWN_WAIT_MS = 100L
    private const val RETRY_DELAY_MS = 1L

    private const val MAX_SYSCALL_ARGS = 6
    private const val ARG_DIR_FD = 0
    private const val ARG_PATH = 1
    private const val ARG_OLD_DIR_FD = 0
    private const val ARG_OLD_PATH = 1
    private const val ARG_NEW_DIR_FD = 2
    private const val ARG_NEW_PATH = 3

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) {
            System.err.println("Usage: ProfilerDaemon <socket_path>")
            exitProcess(1)
        }
        val socketPath = args[0]

        val arch = Arch.current()
        for (s in Syscall.entries) {
            val nr = s.numberFor(arch)
            if (nr >= 0) syscallMap[nr] = s.name
        }

        // Shutdown hook for the daemon itself
        Runtime.getRuntime().addShutdownHook(
            Thread {
                triggerGlobalShutdown("JVM Shutdown Hook")
            },
        )

        startStdinMonitor()
        run(socketPath)
    }

    private fun startStdinMonitor() {
        Thread {
            try {
                monitorStdin()
            } catch (e: IOException) {
                triggerGlobalShutdown("Stdin monitor error: ${e.message}")
            }
            exitProcess(0)
        }.apply {
            isDaemon = true
            name = "stdin-monitor"
        }.start()
    }

    private fun monitorStdin() {
        var status = 0
        while (status == 0) {
            try {
                if (System.`in`.read() == -1) {
                    triggerGlobalShutdown("Stdin EOF")
                    status = 1
                }
            } catch (e: IOException) {
                if (e.message?.contains("Interrupted system call") == true) {
                    continue
                }
                throw e
            }
        }
    }

    private fun triggerGlobalShutdown(source: String = "unknown") {
        if (isGlobalShutdown.getAndSet(true)) return
        System.err.println("[DAEMON] Initiating graceful shutdown. Source: $source. Releasing tracee threads...")
    }

    private fun run(socketPath: String) {
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
        if (LinuxNative.bind(serverFd, addr, ADDR_UN_SIZE).returnValue < 0) {
            throw IllegalStateException("Failed to bind")
        }
        if (LinuxNative.listen(serverFd, BACKLOG_SIZE).returnValue < 0) {
            throw IllegalStateException("Failed to listen")
        }
    }

    private fun acceptConnections(
        serverFd: Int,
        arena: Arena,
    ) {
        val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
        val addrLen = arena.allocate(ValueLayout.JAVA_INT)
        addrLen.set(ValueLayout.JAVA_INT, 0L, ADDR_UN_SIZE)

        var shouldContinue = true
        while (shouldContinue && !isGlobalShutdown.get()) {
            val acceptRes = LinuxNative.accept(serverFd, addr, addrLen)
            if (acceptRes.returnValue < 0) {
                if (acceptRes.errno == EINTR) continue
                shouldContinue = false
            } else {
                val clientFd = acceptRes.returnValue.toInt()
                shouldContinue = handleAcceptedClient(clientFd)
            }
        }
    }

    private fun handleAcceptedClient(clientFd: Int): Boolean {
        if (isShutdownCommand(clientFd)) {
            LinuxNative.close(clientFd)
            triggerGlobalShutdown("Shutdown Command")
            return false
        }

        Thread {
            try {
                handleConnection(clientFd)
            } catch (e: IOException) {
                System.err.println("[DAEMON] Connection I/O error: ${e.message}")
            } catch (e: IllegalStateException) {
                System.err.println("[DAEMON] Connection state error: ${e.message}")
            } finally {
                LinuxNative.close(clientFd)
            }
        }.start()
        return true
    }

    private fun isShutdownCommand(socketFd: Int): Boolean {
        Arena.ofConfined().use { arena ->
            val buf = arena.allocate(ACK_BUF_SIZE)
            var status = 0
            while (status == 0) {
                val res = LinuxNative.recv(socketFd, buf, ACK_BUF_SIZE, MSG_PEEK)
                val check = checkShutdownPeek(res, buf)
                if (check != 0) return check == 1
            }
            return false
        }
    }

    private fun checkShutdownPeek(
        res: LinuxNative.SyscallResult,
        buf: MemorySegment,
    ): Int {
        var result = -1
        if (res.returnValue == ACK_BUF_SIZE) {
            result = if (buf.get(ValueLayout.JAVA_BYTE, 0L) == SHUTDOWN_COMMAND_BYTE) 1 else -1
        } else if (res.returnValue < 0 && res.errno == EINTR) {
            result = 0
        }
        return result
    }

    private fun handleConnection(socketFd: Int) {
        clientSockets.add(socketFd)
        var listenerFd = -1
        try {
            val fd = recvDescriptor(socketFd) ?: return
            listenerFd = fd
            activeListeners.add(listenerFd)
            sendAck(socketFd)
            runNotificationLoop(listenerFd, socketFd)
        } finally {
            cleanupConnection(socketFd, listenerFd)
        }
    }

    private fun sendAck(socketFd: Int) {
        Arena.ofConfined().use { arena ->
            val ack = arena.allocate(ACK_BUF_SIZE)
            ack.set(ValueLayout.JAVA_BYTE, 0L, PROTOCOL_ACK_BYTE)
            var status = 0
            while (status == 0) {
                val res = LinuxNative.write(socketFd, ack, ACK_BUF_SIZE)
                status = checkAckResult(res)
            }
        }
    }

    private fun checkAckResult(res: LinuxNative.SyscallResult): Int {
        var status = -1
        if (res.returnValue == 1L) {
            status = 1
        } else if (res.returnValue < 0 && (res.errno == EINTR || res.errno == EAGAIN)) {
            Thread.sleep(RETRY_DELAY_MS)
            status = 0
        }
        return status
    }

    private fun runNotificationLoop(
        listenerFd: Int,
        socketFd: Int,
    ) {
        Arena.ofConfined().use { arena ->
            val notif = arena.allocate(LinuxNative.SECCOMP_NOTIF_LAYOUT)
            val resp = arena.allocate(LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT)
            val ackBuf = arena.allocate(ACK_BUF_SIZE)
            val pollFd = arena.allocate(LinuxNative.POLLFD_LAYOUT)

            pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, socketFd)
            pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, LinuxNative.POLLIN)

            while (!isGlobalShutdown.get()) {
                if (!processSingleNotification(listenerFd, socketFd, notif, resp, ackBuf, pollFd)) break
            }

            if (isGlobalShutdown.get()) {
                drainNotifications(listenerFd, resp, notif)
            }
        }
    }

    private fun cleanupConnection(
        socketFd: Int,
        listenerFd: Int,
    ) {
        if (listenerFd != -1) {
            activeListeners.remove(listenerFd)
            LinuxNative.close(listenerFd)
        }
        clientSockets.remove(socketFd)
        socketLocks.remove(socketFd)
        LinuxNative.close(socketFd)
    }

    private fun drainNotifications(
        listenerFd: Int,
        resp: MemorySegment,
        notif: MemorySegment,
    ) {
        LinuxNative.fcntl(listenerFd, F_SETFL_VAL, O_NONBLOCK_VAL)
        var status = 0
        while (status == 0) {
            notif.fill(0)
            val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
            status = handleDrainResult(ioctlRes, listenerFd, resp, notif)
        }
    }

    private fun handleDrainResult(
        res: LinuxNative.SyscallResult,
        listenerFd: Int,
        resp: MemorySegment,
        notif: MemorySegment,
    ): Int {
        var status = 0
        if (res.returnValue < 0) {
            status = if (res.errno == EINTR) 0 else 1
        } else {
            val id = notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
            sendContinueResponse(listenerFd, id, resp)
        }
        return status
    }

    private fun processSingleNotification(
        listenerFd: Int,
        socketFd: Int,
        notif: MemorySegment,
        resp: MemorySegment,
        ackBuf: MemorySegment,
        pollFd: MemorySegment,
    ): Boolean {
        val id = receiveNotification(listenerFd, notif)
        if (id == -1L) return false

        try {
            val event = extractTraceEvent(notif)
            sendTraceEvent(socketFd, event)

            // Wait for ACK from parent JVM
            return waitForAck(socketFd, ackBuf, pollFd)
        } finally {
            sendContinueResponse(listenerFd, id, resp)
        }
    }

    private fun receiveNotification(
        listenerFd: Int,
        notif: MemorySegment,
    ): Long {
        var status = 0
        while (status == 0) {
            notif.fill(0)
            val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
            if (ioctlRes.returnValue < 0) {
                if (ioctlRes.errno == EINTR) continue
                return -1L
            }
            status = 1
        }
        return notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
    }

    private fun extractTraceEvent(notif: MemorySegment): TraceEvent {
        val pid = notif.get(ValueLayout.JAVA_INT, NOTIF_PID_OFF)
        val nr = notif.get(ValueLayout.JAVA_INT, NOTIF_NR_OFF)
        val args = LongArray(MAX_SYSCALL_ARGS)
        for (i in 0 until MAX_SYSCALL_ARGS) {
            args[i] = notif.get(ValueLayout.JAVA_LONG, NOTIF_ARGS_OFF + i * ValueLayout.JAVA_LONG.byteSize())
        }

        val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
        val paths = getPathArgs(syscallName, args, pid)
        return TraceEvent(pid, syscallName, args, paths)
    }

    private fun waitForAck(
        socketFd: Int,
        ackBuf: MemorySegment,
        pollFd: MemorySegment,
    ): Boolean {
        pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, 0.toShort())
        var result = false
        var stop = false
        while (!isGlobalShutdown.get() && !stop) {
            val pollRes = LinuxNative.poll(pollFd, 1L, POLL_TIMEOUT_MS)
            if (pollRes.returnValue > 0) {
                result = handlePollIn(socketFd, ackBuf, pollFd)
                stop = true
            } else if (pollRes.returnValue < 0L && pollRes.errno != EINTR) {
                stop = true
            }
        }
        return result
    }

    private fun handlePollIn(
        socketFd: Int,
        ackBuf: MemorySegment,
        pollFd: MemorySegment,
    ): Boolean {
        val revents = pollFd.get(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF)
        return if ((revents.toInt() and LinuxNative.POLLIN.toInt()) != 0) {
            readAckWithRetry(socketFd, ackBuf)
        } else {
            false
        }
    }

    private fun readAckWithRetry(
        socketFd: Int,
        ackBuf: MemorySegment,
    ): Boolean {
        var status = 0
        while (status == 0) {
            val readRes = LinuxNative.read(socketFd, ackBuf, ACK_BUF_SIZE)
            status = checkReadAckResult(readRes, ackBuf)
        }
        return status == 1
    }

    private fun checkReadAckResult(
        res: LinuxNative.SyscallResult,
        ackBuf: MemorySegment,
    ): Int {
        var status = -1
        if (res.returnValue > 0) {
            val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
            if (command == SHUTDOWN_COMMAND_BYTE) {
                triggerGlobalShutdown("Shutdown Command (inline)")
            }
            status = 1
        } else if (res.returnValue < 0 && (res.errno == EINTR || res.errno == EAGAIN)) {
            Thread.sleep(RETRY_DELAY_MS)
            status = 0
        }
        return status
    }

    private fun sendTraceEvent(
        socketFd: Int,
        event: TraceEvent,
    ) {
        val bytes = serializeTraceEvent(event)
        if (bytes.isEmpty()) return

        val lock = socketLocks.computeIfAbsent(socketFd) { Any() }
        synchronized(lock) {
            Arena.ofConfined().use { arena ->
                val buf = arena.allocate(bytes.size.toLong())
                MemorySegment.copy(bytes, 0, buf, ValueLayout.JAVA_BYTE, 0L, bytes.size)
                writeAll(socketFd, buf, bytes.size.toLong())
            }
        }
    }

    private fun serializeTraceEvent(event: TraceEvent): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.writeInt(event.pid)
        val syscallBytes = event.syscallName.toByteArray(StandardCharsets.UTF_8)
        dos.writeInt(syscallBytes.size)
        dos.write(syscallBytes)
        dos.writeInt(event.args.size)
        for (arg in event.args) {
            dos.writeLong(arg)
        }
        dos.writeInt(event.paths.size)
        for (path in event.paths) {
            val pBytes = path.toByteArray(StandardCharsets.UTF_8)
            dos.writeInt(pBytes.size)
            dos.write(pBytes)
        }
        dos.flush()
        return baos.toByteArray()
    }

    private fun writeAll(
        socketFd: Int,
        buf: MemorySegment,
        size: Long,
    ) {
        var written = 0L
        while (written < size) {
            val res = LinuxNative.write(socketFd, buf.asSlice(written), size - written)
            if (res.returnValue > 0) {
                written += res.returnValue
            } else if (res.returnValue < 0) {
                val errno = res.errno
                if (errno == EINTR || errno == EAGAIN) {
                    Thread.sleep(RETRY_DELAY_MS)
                    continue
                }
                throw IOException("Native write failed with errno $errno")
            } else {
                throw IOException("Native write returned 0 (broken pipe?)")
            }
        }
    }

    private fun recvDescriptor(socketFd: Int): Int? {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)
            var status = 0
            while (status == 0) {
                val res = LinuxNative.recvmsg(socketFd, msg, 0)
                if (res.returnValue >= 0) {
                    return controlBuf.get(ValueLayout.JAVA_INT, CMSG_DATA_OFF)
                }
                if (res.errno == EINTR) continue
                status = -1
            }
            return null
        }
    }

    internal fun readStringFromProcess(
        pid: Int,
        remoteAddress: Long,
        maxLen: Int = 4096,
    ): String? {
        Arena.ofConfined().use { arena ->
            val localBuf = arena.allocate(maxLen.toLong())
            localBuf.fill(0)
            val localIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            localIov.set(ValueLayout.ADDRESS, 0L, localBuf)
            localIov.set(ValueLayout.JAVA_LONG, IOV_LEN_OFF, maxLen.toLong())
            val remoteIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            remoteIov.set(ValueLayout.ADDRESS, 0L, MemorySegment.ofAddress(remoteAddress))
            remoteIov.set(ValueLayout.JAVA_LONG, IOV_LEN_OFF, maxLen.toLong())

            val res = LinuxNative.processVmReadv(pid, localIov, 1, remoteIov, 1, 0)
            return handleVmReadResult(res, localBuf, pid)
        }
    }

    private val warnedPids = java.util.concurrent.ConcurrentHashMap
        .newKeySet<Int>()

    private fun handleVmReadResult(
        res: LinuxNative.SyscallResult,
        localBuf: MemorySegment,
        pid: Int,
    ): String? {
        if (res.returnValue < 0) {
            if (res.errno == 1 && warnedPids.add(pid)) {
                logger.log(Level.WARNING, "Permission denied reading memory from PID $pid. (Yama ptrace_scope?)")
            }
            return null
        }

        val bytesRead = res.returnValue.toInt()
        var len = 0
        while (len < bytesRead && localBuf.get(ValueLayout.JAVA_BYTE, len.toLong()) != 0.toByte()) {
            len++
        }
        // If no null terminator is found, we return the best-effort string (all bytes read)
        return localBuf.copyToString(len)
    }

    private fun getPathArgs(
        syscallName: String,
        args: LongArray,
        pid: Int,
    ): List<String> =
        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK", "CHROOT", "UTIME", "UTIMES" ->
                listOfNotNull(tryRead(pid, args[0]))

            "FCHMOD", "FCHOWN", "FSTAT" ->
                listOfNotNull(resolveFdPath(pid, args[0].toInt()))

            "SYMLINK", "LINK", "RENAME" ->
                listOfNotNull(tryRead(pid, args[0]), tryRead(pid, args[1]))

            "OPENAT", "EXECVEAT", "OPENAT2", "MKDIRAT", "UNLINKAT", "FCHMODAT", "FCHOWNAT", "UTIMENSAT", "FSTATAT", "READLINKAT" ->
                listOfNotNull(tryRead(pid, args[ARG_PATH], args[ARG_DIR_FD]))

            "RENAMEAT", "RENAMEAT2", "LINKAT", "SYMLINKAT" ->
                listOfNotNull(
                    tryRead(pid, args[ARG_OLD_PATH], args[ARG_OLD_DIR_FD]),
                    tryRead(pid, args[ARG_NEW_PATH], args[ARG_NEW_DIR_FD]),
                )

            else -> emptyList()
        }

    private fun resolveCwd(pid: Int): String? = resolveLink(pid, "cwd")

    private fun resolveFdPath(
        pid: Int,
        fd: Int,
    ): String? = resolveLink(pid, "fd/$fd")

    private fun resolveLink(
        pid: Int,
        link: String,
    ): String? {
        val procPath = "/proc/$pid/$link"
        Arena.ofConfined().use { arena ->
            val pathSeg = arena.allocateFrom(procPath)
            val buf = arena.allocate(PATH_MAX_VAL)
            var status = 0
            while (status == 0) {
                val res = LinuxNative.readlink(pathSeg, buf, PATH_MAX_VAL)
                if (res.returnValue >= 0) {
                    return buf.copyToString(res.returnValue.toInt())
                }
                if (res.errno == EINTR) continue
                if (res.errno == 1) { // EPERM
                    if (warnedPids.add(pid)) {
                        logger.log(Level.WARNING, "Permission denied reading link $procPath. (Yama ptrace_scope?)")
                    }
                }
                status = -1
            }
            return null
        }
    }

    private fun isAtFdcwd(fd: Long): Boolean = fd == AT_FDCWD_VAL || fd == AT_FDCWD_UNSIGNED_VAL || fd.toInt() == AT_FDCWD_INT_VAL

    private fun tryRead(
        pid: Int,
        addr: Long,
        dirfd: Long = AT_FDCWD_VAL,
    ): String? {
        var result: String? = null
        if (addr != 0L) {
            val path = readStringFromProcess(pid, addr)
            if (path != null) {
                result = if (path.startsWith("/")) {
                    path
                } else {
                    resolveRelativePath(pid, path, dirfd)
                }
            }
        }
        return result
    }

    private fun resolveRelativePath(
        pid: Int,
        path: String,
        dirfd: Long,
    ): String? {
        val dirPath =
            if (isAtFdcwd(dirfd)) {
                resolveCwd(pid)
            } else if (dirfd >= 0) {
                resolveFdPath(pid, dirfd.toInt())
            } else {
                null
            }

        return if (dirPath != null) {
            if (dirPath.endsWith("/")) "$dirPath$path" else "$dirPath/$path"
        } else {
            path
        }
    }

    private fun sendContinueResponse(
        listenerFd: Int,
        id: Long,
        resp: MemorySegment,
    ) {
        resp.fill(0)
        resp.set(ValueLayout.JAVA_LONG, RESP_ID_OFF, id)
        resp.set(ValueLayout.JAVA_LONG, RESP_VAL_OFF, 0L)
        resp.set(ValueLayout.JAVA_INT, RESP_ERR_OFF, 0)
        resp.set(ValueLayout.JAVA_INT, RESP_FLAGS_OFF, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
        var status = 0
        while (status == 0) {
            val res = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
            if (res.returnValue < 0 && res.errno == EINTR) continue
            status = 1
        }
    }

    private fun MemorySegment.copyToString(len: Int): String {
        val bytes = this.asSlice(0L, len.toLong()).toArray(ValueLayout.JAVA_BYTE)
        return String(bytes, StandardCharsets.UTF_8)
    }
}
