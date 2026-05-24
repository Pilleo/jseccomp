package io.mazewall.profiler

import io.mazewall.Arch
import io.mazewall.LinuxNative
import io.mazewall.Syscall
import java.io.DataOutputStream
import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.system.exitProcess

/**
 * Standalone Profiler Daemon Process.
 *
 * Communicates with the parent JVM via a Unix Domain Socket, sending binary [TraceEvent]
 * structures.
 */
object ProfilerDaemon {
    private val syscallMap = mutableMapOf<Int, String>()
    private val clientSockets = CopyOnWriteArrayList<Int>()
    private val socketLocks = java.util.concurrent.ConcurrentHashMap<Int, Any>()
    private val activeListeners = CopyOnWriteArrayList<Int>()
    private val isGlobalShutdown = AtomicBoolean(false)

    private const val ADDR_UN_SIZE = 110
    private const val BACKLOG_SIZE = 128
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
                triggerGlobalShutdown()
            },
        )

        Thread {
            try {
                // Listen for parent JVM exit via stdin closure
                System.`in`.read()
            } catch (e: java.io.IOException) {
                e.printStackTrace()
            }
            triggerGlobalShutdown()
            exitProcess(0)
        }.apply { isDaemon = true }.start()

        run(socketPath)
    }

    private fun triggerGlobalShutdown() {
        if (isGlobalShutdown.getAndSet(true)) return
        System.err.println("[DAEMON] Initiating graceful shutdown. Releasing tracee threads...")
        // Actual cleanup (sending CONTINUE and closing fds) is handled by the handleConnection loops
        // which break out of their waiting state or drain when isGlobalShutdown becomes true.
    }

    private fun run(socketPath: String) {
        Arena.ofConfined().use { arena ->
            val bindRes = LinuxNative.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0)
            if (bindRes.returnValue < 0) throw IllegalStateException("Failed to create daemon socket: errno=${bindRes.errno}")
            val serverFd = bindRes.returnValue.toInt()

            val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
            addr.fill(0)
            addr.set(ValueLayout.JAVA_SHORT, 0L, 1.toShort()) // AF_UNIX = 1

            val pathBytes = socketPath.toByteArray(StandardCharsets.UTF_8)
            val pathSeg = addr.asSlice(2, 108)
            for (i in pathBytes.indices) pathSeg.set(ValueLayout.JAVA_BYTE, i.toLong(), pathBytes[i])

            File(socketPath).delete()
            if (LinuxNative.bind(serverFd, addr, ADDR_UN_SIZE).returnValue < 0) throw IllegalStateException("Failed to bind")
            if (LinuxNative.listen(serverFd, BACKLOG_SIZE).returnValue < 0) throw IllegalStateException("Failed to listen")

            val addrLen = arena.allocate(ValueLayout.JAVA_INT)
            addrLen.set(ValueLayout.JAVA_INT, 0L, ADDR_UN_SIZE)

            var shouldContinue = true
            while (shouldContinue && !isGlobalShutdown.get()) {
                val acceptRes = LinuxNative.accept(serverFd, addr, addrLen)
                if (acceptRes.returnValue < 0) {
                    shouldContinue = false
                } else {
                    val clientFd = acceptRes.returnValue.toInt()

                    // Check for a "Shutdown Command" connection (no FD sent, just 0x53)
                    if (isShutdownCommand(clientFd)) {
                        LinuxNative.close(clientFd)
                        triggerGlobalShutdown()
                        shouldContinue = false
                    } else {
                        Thread {
                            try {
                                handleConnection(clientFd)
                            } catch (e: Exception) {
                                e.printStackTrace()
                            } finally {
                                LinuxNative.close(clientFd)
                            }
                        }.start()
                    }
                }
            }
            LinuxNative.close(serverFd)
        }
    }

    private fun isShutdownCommand(socketFd: Int): Boolean {
        // Peek the first byte. If it's 0x53 ('S'), it's a shutdown command.
        // Profiler.installProfilingFilterForThread sends a descriptor, which
        // usually starts with SCM_RIGHTS header.
        Arena.ofConfined().use { arena ->
            val buf = arena.allocate(1)
            val res = LinuxNative.recv(socketFd, buf, 1, 2 /* MSG_PEEK */)
            return res.returnValue == 1L && buf.get(ValueLayout.JAVA_BYTE, 0L) == 0x53.toByte()
        }
    }

    private fun handleConnection(socketFd: Int) {
        clientSockets.add(socketFd)
        var listenerFd = -1
        try {
            val fd = recvDescriptor(socketFd) ?: return
            listenerFd = fd
            activeListeners.add(listenerFd)
            Arena.ofConfined().use { arena ->
                val ack = arena.allocate(1)
                ack.set(ValueLayout.JAVA_BYTE, 0L, 0xAC.toByte())
                LinuxNative.write(socketFd, ack, 1)
            }

            Arena.ofConfined().use { arena ->
                val notif = arena.allocate(LinuxNative.SECCOMP_NOTIF_LAYOUT)
                val resp = arena.allocate(LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT)

                var continueLoop = true
                while (continueLoop && !isGlobalShutdown.get()) {
                    continueLoop = processSingleNotification(listenerFd, socketFd, notif, resp, arena)
                }

                if (isGlobalShutdown.get()) {
                    // Drain notifications
                    LinuxNative.fcntl(listenerFd, F_SETFL_VAL, O_NONBLOCK_VAL)
                    while (true) {
                        notif.fill(0)
                        val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
                        if (ioctlRes.returnValue < 0) break
                        val id = notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
                        sendContinueResponse(listenerFd, id, resp)
                    }
                }
            }
        } finally {
            if (listenerFd != -1) {
                activeListeners.remove(listenerFd)
                LinuxNative.close(listenerFd)
            }
            clientSockets.remove(socketFd)
            socketLocks.remove(socketFd)
        }
    }

    private fun processSingleNotification(
        listenerFd: Int,
        socketFd: Int,
        notif: MemorySegment,
        resp: MemorySegment,
        arena: Arena,
    ): Boolean {
        notif.fill(0)
        val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
        if (ioctlRes.returnValue < 0) return false

        val id = notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
        val pid = notif.get(ValueLayout.JAVA_INT, NOTIF_PID_OFF)
        val nr = notif.get(ValueLayout.JAVA_INT, NOTIF_NR_OFF)
        val args = LongArray(MAX_SYSCALL_ARGS)
        for (i in 0 until MAX_SYSCALL_ARGS) {
            args[i] = notif.get(ValueLayout.JAVA_LONG, NOTIF_ARGS_OFF + i * ValueLayout.JAVA_LONG.byteSize())
        }

        val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
        val paths = getPathArgs(syscallName, args, pid)

        var success = false
        try {
            sendTraceEvent(socketFd, TraceEvent(pid, syscallName, args, paths))

            // Wait for ACK from parent JVM
            val ackBuf = arena.allocate(1)
            val readRes = LinuxNative.read(socketFd, ackBuf, 1)
            if (readRes.returnValue > 0) {
                val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
                if (command == 0x53.toByte()) { // 'S' for Shutdown
                    triggerGlobalShutdown()
                }
                success = true
            }
        } finally {
            sendContinueResponse(listenerFd, id, resp)
        }
        return success
    }

    private fun sendTraceEvent(
        socketFd: Int,
        event: TraceEvent,
    ) {
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

        val bytes = baos.toByteArray()
        if (bytes.isEmpty()) return

        val lock = socketLocks.computeIfAbsent(socketFd) { Any() }
        synchronized(lock) {
            // Synchronize on lock object to prevent interleaved writes
            Arena.ofConfined().use { arena ->
                val buf = arena.allocate(bytes.size.toLong())
                MemorySegment.copy(bytes, 0, buf, ValueLayout.JAVA_BYTE, 0L, bytes.size)
                LinuxNative.write(socketFd, buf, bytes.size.toLong())
            }
        }
    }

    private fun recvDescriptor(socketFd: Int): Int? {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)
            if (LinuxNative.recvmsg(socketFd, msg, 0).returnValue < 0) return null
            return controlBuf.get(ValueLayout.JAVA_INT, CMSG_DATA_OFF)
        }
    }

    private fun readStringFromProcess(
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
            if (res.returnValue < 0) {
                if (res.errno == 1) { // EPERM
                    System.err.println("[DAEMON] WARN: Permission denied reading memory from PID $pid. (Yama ptrace_scope?)")
                }
                return null
            }
            val bytesRead = res.returnValue.toInt()
            var len = 0
            while (len < bytesRead && localBuf.get(ValueLayout.JAVA_BYTE, len.toLong()) != 0.toByte()) len++
            return localBuf.copyToString(len)
        }
    }

    private fun getPathArgs(
        syscallName: String,
        args: LongArray,
        pid: Int,
    ): List<String> {
        val paths = mutableListOf<String>()

        fun isAtFdcwd(fd: Long): Boolean = fd == AT_FDCWD_VAL || fd == AT_FDCWD_UNSIGNED_VAL || fd.toInt() == AT_FDCWD_INT_VAL

        fun tryRead(
            addr: Long,
            dirfd: Long = AT_FDCWD_VAL,
        ): String? {
            if (addr == 0L) return null
            val path = readStringFromProcess(pid, addr) ?: return null
            if (path.startsWith("/")) return path

            // Resolve relative paths
            val dirPath =
                if (isAtFdcwd(dirfd)) {
                    // AT_FDCWD
                    resolveCwd(pid)
                } else if (dirfd >= 0) {
                    resolveFdPath(pid, dirfd.toInt())
                } else {
                    null
                }

            if (dirPath != null) {
                return if (dirPath.endsWith("/")) "$dirPath$path" else "$dirPath/$path"
            }
            return path
        }
        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK", "CHROOT", "UTIME", "UTIMES" ->
                tryRead(args[0], AT_FDCWD_VAL)?.let { paths.add(it) }

            "FCHMOD", "FCHOWN", "FSTAT" ->
                resolveFdPath(pid, args[0].toInt())?.let { paths.add(it) }

            "SYMLINK", "LINK", "RENAME" -> {
                tryRead(args[0], AT_FDCWD_VAL)?.let { paths.add(it) }
                tryRead(args[1], AT_FDCWD_VAL)?.let { paths.add(it) }
            }

            "OPENAT", "EXECVEAT", "OPENAT2", "MKDIRAT", "UNLINKAT", "FCHMODAT", "FCHOWNAT", "UTIMENSAT", "FSTATAT", "READLINKAT" ->
                tryRead(args[ARG_PATH], args[ARG_DIR_FD])?.let { paths.add(it) }

            "RENAMEAT", "RENAMEAT2", "LINKAT", "SYMLINKAT" -> {
                tryRead(args[ARG_OLD_PATH], args[ARG_OLD_DIR_FD])?.let { paths.add(it) }
                tryRead(args[ARG_NEW_PATH], args[ARG_NEW_DIR_FD])?.let { paths.add(it) }
            }
        }
        return paths
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
            val res = LinuxNative.readlink(pathSeg, buf, PATH_MAX_VAL)
            if (res.returnValue < 0) return null
            return buf.copyToString(res.returnValue.toInt())
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
        LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
    }

    private fun MemorySegment.copyToString(len: Int): String {
        val bytes = this.asSlice(0L, len.toLong()).toArray(ValueLayout.JAVA_BYTE)
        return String(bytes, StandardCharsets.UTF_8)
    }
}
