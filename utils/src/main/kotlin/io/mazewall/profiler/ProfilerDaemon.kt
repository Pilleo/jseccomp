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

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) {
            System.err.println("Usage: ProfilerDaemon <socket_path>")
            System.exit(1)
        }
        val socketPath = args[0]

        val arch = Arch.current()
        for (s in Syscall.entries) {
            val nr = s.numberFor(arch)
            if (nr >= 0) syscallMap[nr] = s.name
        }

        // Shutdown hook for the daemon itself
        Runtime.getRuntime().addShutdownHook(Thread {
            triggerGlobalShutdown()
        })

        Thread {
            try {
                // Listen for parent JVM exit via stdin closure
                System.`in`.read()
            } catch (e: Exception) {
                e.printStackTrace()
            }
            triggerGlobalShutdown()
            System.exit(0)
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
            if (LinuxNative.bind(serverFd, addr, 110).returnValue < 0) throw IllegalStateException("Failed to bind")
            if (LinuxNative.listen(serverFd, 128).returnValue < 0) throw IllegalStateException("Failed to listen")

            val addrLen = arena.allocate(ValueLayout.JAVA_INT)
            addrLen.set(ValueLayout.JAVA_INT, 0L, 110)

            while (!isGlobalShutdown.get()) {
                val acceptRes = LinuxNative.accept(serverFd, addr, addrLen)
                if (acceptRes.returnValue < 0) break
                val clientFd = acceptRes.returnValue.toInt()

                // Check for a "Shutdown Command" connection (no FD sent, just 0x53)
                if (isShutdownCommand(clientFd)) {
                    LinuxNative.close(clientFd)
                    triggerGlobalShutdown()
                    break
                }

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
                val ack = arena.allocate(1); ack.set(ValueLayout.JAVA_BYTE, 0L, 0xAC.toByte())
                LinuxNative.write(socketFd, ack, 1)
            }

            Arena.ofConfined().use { arena ->
                val notif = arena.allocate(LinuxNative.SECCOMP_NOTIF_LAYOUT)
                val resp = arena.allocate(LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT)

                while (!isGlobalShutdown.get()) {
                    notif.fill(0)
                    val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
                    if (ioctlRes.returnValue < 0) break

                    val id = notif.get(ValueLayout.JAVA_LONG, 0L)
                    val pid = notif.get(ValueLayout.JAVA_INT, 8L)
                    val nr = notif.get(ValueLayout.JAVA_INT, 16L)
                    val args = LongArray(6)
                    for (i in 0..5) args[i] = notif.get(ValueLayout.JAVA_LONG, 32L + i * 8L)

                    val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
                    val paths = getPathArgs(syscallName, args, pid)

                    try {
                        sendTraceEvent(socketFd, TraceEvent(pid, syscallName, args, paths))

                        // Wait for ACK from parent JVM
                        val ackBuf = arena.allocate(1)
                        val readRes = LinuxNative.read(socketFd, ackBuf, 1)
                        if (readRes.returnValue <= 0) break

                        val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
                        if (command == 0x53.toByte()) { // 'S' for Shutdown
                            triggerGlobalShutdown()
                        }
                    } finally {
                        resp.fill(0)
                        resp.set(ValueLayout.JAVA_LONG, 0L, id)
                        resp.set(ValueLayout.JAVA_LONG, 8L, 0L)
                        resp.set(ValueLayout.JAVA_INT, 16L, 0)
                        resp.set(ValueLayout.JAVA_INT, 20L, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
                        LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
                    }
                }

                if (isGlobalShutdown.get()) {
                    // Drain notifications
                    LinuxNative.fcntl(listenerFd, 4 /* F_SETFL */, 2048 /* O_NONBLOCK */)
                    while (true) {
                        notif.fill(0)
                        val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
                        if (ioctlRes.returnValue < 0) break
                        val id = notif.get(ValueLayout.JAVA_LONG, 0L)
                        resp.fill(0)
                        resp.set(ValueLayout.JAVA_LONG, 0L, id)
                        resp.set(ValueLayout.JAVA_LONG, 8L, 0L)
                        resp.set(ValueLayout.JAVA_INT, 16L, 0)
                        resp.set(ValueLayout.JAVA_INT, 20L, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
                        LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
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

    private fun sendTraceEvent(socketFd: Int, event: TraceEvent) {
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
        synchronized(lock) { // Synchronize on lock object to prevent interleaved writes
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
            val iov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            iov.set(ValueLayout.ADDRESS, 0L, dummyByte); iov.set(ValueLayout.JAVA_LONG, 8L, 1L)
            val controlBuf = arena.allocate(24); controlBuf.fill(0)
            val msg = arena.allocate(LinuxNative.MSGHDR_LAYOUT)
            msg.fill(0)
            msg.set(ValueLayout.ADDRESS, 16L, iov); msg.set(ValueLayout.JAVA_LONG, 24L, 1L)
            msg.set(ValueLayout.ADDRESS, 32L, controlBuf); msg.set(ValueLayout.JAVA_LONG, 40L, 24L)
            if (LinuxNative.recvmsg(socketFd, msg, 0).returnValue < 0) return null
            return controlBuf.get(ValueLayout.JAVA_INT, 16L)
        }
    }

    private fun readStringFromProcess(pid: Int, remoteAddress: Long, maxLen: Int = 4096): String? {
        Arena.ofConfined().use { arena ->
            val localBuf = arena.allocate(maxLen.toLong()); localBuf.fill(0)
            val localIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            localIov.set(ValueLayout.ADDRESS, 0L, localBuf); localIov.set(ValueLayout.JAVA_LONG, 8L, maxLen.toLong())
            val remoteIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            remoteIov.set(ValueLayout.ADDRESS, 0L, MemorySegment.ofAddress(remoteAddress))
            remoteIov.set(ValueLayout.JAVA_LONG, 8L, maxLen.toLong())
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
            val bytes = ByteArray(len)
            for (i in 0 until len) bytes[i] = localBuf.get(ValueLayout.JAVA_BYTE, i.toLong())
            return String(bytes, StandardCharsets.UTF_8)
        }
    }

    private fun getPathArgs(syscallName: String, args: LongArray, pid: Int): List<String> {
        val paths = mutableListOf<String>()
        fun isAtFdcwd(fd: Long): Boolean = fd == -100L || fd == 4294967196L || fd.toInt() == -100

        fun tryRead(addr: Long, dirfd: Long = -100L): String? {
            if (addr == 0L) return null
            val path = readStringFromProcess(pid, addr) ?: return null
            if (path.startsWith("/")) return path

            // Resolve relative paths
            val dirPath = if (isAtFdcwd(dirfd)) {
                // AT_FDCWD
                resolveCwd(pid)
            } else if (dirfd >= 0) {
                resolveFdPath(pid, dirfd.toInt())
            } else null

            if (dirPath != null) {
                return if (dirPath.endsWith("/")) "$dirPath$path" else "$dirPath/$path"
            }
            return path
        }
        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK", "CHROOT", "UTIME", "UTIMES" ->
                tryRead(args[0], -100L)?.let { paths.add(it) }

            "FCHMOD", "FCHOWN", "FSTAT" ->
                resolveFdPath(pid, args[0].toInt())?.let { paths.add(it) }

            "SYMLINK", "LINK", "RENAME" -> {
                tryRead(args[0], -100L)?.let { paths.add(it) }
                tryRead(args[1], -100L)?.let { paths.add(it) }
            }

            "OPENAT", "EXECVEAT", "OPENAT2", "MKDIRAT", "UNLINKAT", "FCHMODAT", "FCHOWNAT", "UTIMENSAT", "FSTATAT", "READLINKAT" ->
                tryRead(args[1], args[0])?.let { paths.add(it) }

            "RENAMEAT", "RENAMEAT2", "LINKAT", "SYMLINKAT" -> {
                tryRead(args[1], args[0])?.let { paths.add(it) }
                tryRead(args[3], args[2])?.let { paths.add(it) }
            }
        }
        return paths
    }

    private fun resolveCwd(pid: Int): String? {
        return resolveLink(pid, "cwd")
    }

    private fun resolveFdPath(pid: Int, fd: Int): String? {
        return resolveLink(pid, "fd/$fd")
    }

    private fun resolveLink(pid: Int, link: String): String? {
        val procPath = "/proc/$pid/$link"
        Arena.ofConfined().use { arena ->
            val pathSeg = arena.allocateFrom(procPath)
            val buf = arena.allocate(4096)
            val res = LinuxNative.readlink(pathSeg, buf, 4096)
            if (res.returnValue < 0) return null
            val len = res.returnValue.toInt()
            val bytes = ByteArray(len)
            for (i in 0 until len) bytes[i] = buf.get(ValueLayout.JAVA_BYTE, i.toLong())
            return String(bytes, StandardCharsets.UTF_8)
        }
    }
}
