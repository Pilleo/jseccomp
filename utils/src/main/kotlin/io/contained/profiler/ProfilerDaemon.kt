package io.contained.profiler

import io.contained.Arch
import io.contained.LinuxNative
import io.contained.Syscall
import java.io.DataOutputStream
import java.io.File
import java.io.OutputStream
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
 * structures. Ingests structured audit events from [NETLINK_AUDIT].
 */
object ProfilerDaemon {
    private val syscallMap = mutableMapOf<Int, String>()
    private val clientSockets = CopyOnWriteArrayList<Int>()
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

        startGlobalAuditListener()

        // Shutdown hook for the daemon itself
        Runtime.getRuntime().addShutdownHook(Thread {
            triggerGlobalShutdown()
        })

        Thread {
            try {
                // Listen for parent JVM exit via stdin closure
                System.`in`.read()
            } catch (e: Exception) {
            }
            triggerGlobalShutdown()
            System.exit(0)
        }.apply { isDaemon = true }.start()

        run(socketPath)
    }

    private fun triggerGlobalShutdown() {
        if (isGlobalShutdown.getAndSet(true)) return
        System.err.println("[DAEMON] Initiating graceful shutdown. Releasing tracee threads...")
        for (fd in activeListeners) {
            // We can't easily send CONTINUE from here because we don't have the IDs,
            // but closing the socket from the JVM side will trigger handleConnection to exit.
            // Actually, the most reliable way is for handleConnection to see the flag.
        }
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
                    sendTraceEvent(socketFd, TraceEvent(pid, syscallName, args, paths))

                    // Wait for ACK from parent JVM
                    val ackBuf = arena.allocate(1)
                    val readRes = LinuxNative.read(socketFd, ackBuf, 1)
                    if (readRes.returnValue <= 0) break

                    val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
                    if (command == 0x53.toByte()) { // 'S' for Shutdown
                        triggerGlobalShutdown()
                    }

                    resp.fill(0)
                    resp.set(ValueLayout.JAVA_LONG, 0L, id)
                    resp.set(ValueLayout.JAVA_LONG, 8L, 0L)
                    resp.set(ValueLayout.JAVA_INT, 16L, 0)
                    resp.set(ValueLayout.JAVA_INT, 20L, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
                    LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
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
        }
    }

    private fun startGlobalAuditListener() {
        Thread {
            Arena.ofConfined().use { arena ->
                val socketRes = LinuxNative.socket(LinuxNative.AF_NETLINK, 3 /* SOCK_RAW */, LinuxNative.NETLINK_AUDIT)

                if (socketRes.returnValue < 0) {
                    System.err.println(
                        "[DAEMON] WARN: Netlink Audit socket unavailable (errno=${socketRes.errno}). " +
                                "io_uring syscall visibility is DISABLED for this session. " +
                                "All USER_NOTIF events are still captured normally. " +
                                "To restore io_uring coverage, run with CAP_AUDIT_READ or grant the " +
                                "necessary kernel audit permissions."
                    )
                    return@Thread
                }
                val auditFd = socketRes.returnValue.toInt()

                try {
                    val addr = arena.allocate(LinuxNative.SOCKADDR_NL_LAYOUT)
                    addr.fill(0); addr.set(ValueLayout.JAVA_SHORT, 0L, LinuxNative.AF_NETLINK.toShort())
                    if (LinuxNative.bind(auditFd, addr, 12).returnValue < 0) return@Thread

                    // Enable kernel audit (AUDIT_SET = 1001)
                    val status = arena.allocate(40); status.fill(0)
                    status.set(ValueLayout.JAVA_INT, 0L, 1)
                    status.set(ValueLayout.JAVA_INT, 4L, 1)
                    sendNetlinkMsg(auditFd, 1001, status)

                    val buf = arena.allocate(32768)
                    val iov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
                    iov.set(ValueLayout.ADDRESS, 0L, buf); iov.set(ValueLayout.JAVA_LONG, 8L, 32768L)
                    val msg = arena.allocate(LinuxNative.MSGHDR_LAYOUT)
                    msg.fill(0); msg.set(ValueLayout.ADDRESS, 16L, iov); msg.set(ValueLayout.JAVA_LONG, 24L, 1L)

                    while (true) {
                        val res = LinuxNative.recvmsg(auditFd, msg, 0)
                        if (res.returnValue <= 16) continue

                        var offset = 0L
                        while (offset + 16 <= res.returnValue) {
                            val nlmsgLen = buf.get(ValueLayout.JAVA_INT, offset)
                            val nlmsgType = buf.get(ValueLayout.JAVA_SHORT, offset + 4).toInt() and 0xFFFF

                            if (nlmsgLen < 16) break

                            if (nlmsgType >= 1100) {
                                val payloadLen = nlmsgLen - 16
                                if (payloadLen > 0) {
                                    val payloadBytes =
                                        buf.asSlice(offset + 16, payloadLen.toLong()).toArray(ValueLayout.JAVA_BYTE)
                                    val payload = String(payloadBytes, StandardCharsets.UTF_8)

                                    if (payload.contains("type=LANDLOCK_ACCESS") || payload.contains("type=1423")) {
                                        val blockersIdx = payload.indexOf("blockers=")
                                        val pathIdx = payload.indexOf("path=\"")

                                        if (blockersIdx != -1 && pathIdx != -1) {
                                            val blockersStart = blockersIdx + 9
                                            val blockersEnd = payload.indexOf(' ', blockersStart)
                                                .let { if (it == -1) payload.length else it }
                                            val blockers = payload.substring(blockersStart, blockersEnd)

                                            val pathStart = pathIdx + 6
                                            val pathEnd = payload.indexOf('"', pathStart)

                                            if (pathEnd != -1) {
                                                val path = payload.substring(pathStart, pathEnd)
                                                val syscallName =
                                                    if (blockers.contains("fs.execute")) "EXECVE" else "OPENAT"
                                                val event = TraceEvent(0, syscallName, LongArray(6), listOf(path))
                                                clientSockets.firstOrNull()?.let { client ->
                                                    try {
                                                        sendTraceEvent(client, event)
                                                    } catch (e: Exception) {
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            offset += (nlmsgLen + 3) and 3.inv()
                        }
                    }
                } finally {
                    LinuxNative.close(auditFd)
                }
            }
        }.apply { isDaemon = true; name = "netlink-audit-listener" }.start()
    }

    private fun sendNetlinkMsg(fd: Int, type: Int, payload: MemorySegment) {
        Arena.ofConfined().use { arena ->
            val totalLen = 16 + payload.byteSize().toInt()
            val buf = arena.allocate(totalLen.toLong())
            buf.set(ValueLayout.JAVA_INT, 0L, totalLen)
            buf.set(ValueLayout.JAVA_SHORT, 4L, type.toShort())
            buf.set(ValueLayout.JAVA_SHORT, 6L, 1)
            buf.set(ValueLayout.JAVA_INT, 8L, 1)
            buf.set(ValueLayout.JAVA_INT, 12L, 0)
            MemorySegment.copy(payload, 0, buf, 16, payload.byteSize())
            LinuxNative.write(fd, buf, totalLen.toLong())
        }
    }

    private fun sendTraceEvent(socketFd: Int, event: TraceEvent) {
        val outputStream = object : OutputStream() {
            override fun write(b: Int) {
                Arena.ofConfined().use { arena ->
                    val buf = arena.allocate(1); buf.set(ValueLayout.JAVA_BYTE, 0L, b.toByte())
                    LinuxNative.write(socketFd, buf, 1)
                }
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                Arena.ofConfined().use { arena ->
                    val buf = arena.allocate(len.toLong())
                    for (i in 0 until len) buf.set(ValueLayout.JAVA_BYTE, i.toLong(), b[off + i])
                    LinuxNative.write(socketFd, buf, len.toLong())
                }
            }
        }
        val dos = DataOutputStream(outputStream)
        dos.writeInt(event.pid)
        val syscallBytes = event.syscallName.toByteArray(StandardCharsets.UTF_8)
        dos.writeInt(syscallBytes.size); dos.write(syscallBytes)
        dos.writeInt(event.args.size)
        for (arg in event.args) dos.writeLong(arg)
        dos.writeInt(event.paths.size)
        for (path in event.paths) {
            val pBytes = path.toByteArray(StandardCharsets.UTF_8)
            dos.writeInt(pBytes.size); dos.write(pBytes)
        }
        dos.flush()
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
        fun tryRead(addr: Long, dirfd: Long = -100L): String? {
            if (addr == 0L) return null
            val path = readStringFromProcess(pid, addr) ?: return null
            if (path.startsWith("/") || dirfd == -100L) return path
            if (dirfd >= 0) {
                val dirPath = resolveFdPath(pid, dirfd.toInt())
                if (dirPath != null) return if (dirPath.endsWith("/")) "$dirPath$path" else "$dirPath/$path"
            }
            return path
        }
        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK" -> tryRead(args[0])?.let {
                paths.add(
                    it
                )
            }

            "OPENAT", "EXECVEAT", "OPENAT2" -> tryRead(args[1], args[0])?.let { paths.add(it) }
            "RENAME", "LINK", "SYMLINK" -> {
                tryRead(args[0])?.let { paths.add(it) }; tryRead(args[1])?.let { paths.add(it) }
            }
        }
        return paths
    }

    private fun resolveFdPath(pid: Int, fd: Int): String? {
        val procPath = "/proc/$pid/fd/$fd"
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
