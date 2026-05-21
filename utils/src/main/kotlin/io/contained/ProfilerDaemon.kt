package io.contained

import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * Standalone Profiler Daemon Process.
 */
object ProfilerDaemon {
    private val syscallMap = mutableMapOf<Int, String>()

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) {
            System.err.println("Usage: ProfilerDaemon <socket_path>")
            System.exit(1)
        }
        val socketPath = args[0]

        // Map syscall numbers to names
        val arch = Arch.current()
        for (s in Syscall.values()) {
            val nr = s.numberFor(arch)
            if (nr >= 0) {
                syscallMap[nr] = s.name
            }
        }

        // Stdin closure check to auto-exit when parent terminates
        Thread {
            try {
                System.`in`.read()
            } catch (e: Exception) {
                // ignore
            }
            System.exit(0)
        }.apply { isDaemon = true }.start()

        run(socketPath)
    }

    private fun run(socketPath: String) {
        Arena.ofConfined().use { arena ->
            val bindRes = LinuxNative.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0)
            if (bindRes.returnValue < 0) {
                throw IllegalStateException("Failed to create daemon socket: errno=${bindRes.errno}")
            }
            val serverFd = bindRes.returnValue.toInt()

            val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
            addr.fill(0)
            addr.set(ValueLayout.JAVA_SHORT, 0, 1.toShort()) // AF_UNIX = 1
            
            val pathBytes = socketPath.toByteArray(StandardCharsets.UTF_8)
            if (pathBytes.size >= 108) {
                throw IllegalArgumentException("Unix socket path too long")
            }
            val pathSeg = addr.asSlice(2, 108)
            for (i in pathBytes.indices) {
                pathSeg.set(ValueLayout.JAVA_BYTE, i.toLong(), pathBytes[i])
            }

            File(socketPath).delete()
            val bindRes2 = LinuxNative.bind(serverFd, addr, 110)
            if (bindRes2.returnValue < 0) {
                throw IllegalStateException("Failed to bind to socket at $socketPath: errno=${bindRes2.errno}")
            }

            val listenRes = LinuxNative.listen(serverFd, 128)
            if (listenRes.returnValue < 0) {
                throw IllegalStateException("Failed to listen: errno=${listenRes.errno}")
            }

            val addrLen = arena.allocate(ValueLayout.JAVA_INT)
            addrLen.set(ValueLayout.JAVA_INT, 0, 110)

            while (true) {
                val acceptRes = LinuxNative.accept(serverFd, addr, addrLen)
                if (acceptRes.returnValue < 0) {
                    break
                }
                val clientFd = acceptRes.returnValue.toInt()
                Thread {
                    try {
                        handleConnection(clientFd)
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }.start()
            }
        }
    }

    private fun recvDescriptor(socketFd: Int): Int {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)

            val iov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            iov.set(ValueLayout.ADDRESS, LinuxNative.IOVEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("iov_base")), dummyByte)
            iov.set(ValueLayout.JAVA_LONG, LinuxNative.IOVEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("iov_len")), 1L)

            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)

            val msg = arena.allocate(LinuxNative.MSGHDR_LAYOUT)
            msg.fill(0)
            msg.set(ValueLayout.ADDRESS, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_iov")), iov)
            msg.set(ValueLayout.JAVA_LONG, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_iovlen")), 1L)
            msg.set(ValueLayout.ADDRESS, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_control")), controlBuf)
            msg.set(ValueLayout.JAVA_LONG, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_controllen")), 24L)

            val res = LinuxNative.recvmsg(socketFd, msg, 0)
            if (res.returnValue < 0) {
                return -1
            }

            return controlBuf.get(ValueLayout.JAVA_INT, 16)
        }
    }

    private fun handleConnection(socketFd: Int) {
        val listenerFd = recvDescriptor(socketFd)
        LinuxNative.close(socketFd)
        if (listenerFd < 0) {
            return
        }

        Arena.ofConfined().use { arena ->
            val notif = arena.allocate(LinuxNative.SECCOMP_NOTIF_LAYOUT)
            val resp = arena.allocate(LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT)

            while (true) {
                notif.fill(0)
                val ioctlRes = LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_RECV, notif)
                if (ioctlRes.returnValue < 0) {
                    break
                }

                val id = notif.get(ValueLayout.JAVA_LONG, 0)
                val pid = notif.get(ValueLayout.JAVA_INT, 8)
                
                val nr = notif.get(ValueLayout.JAVA_INT, 16)
                val args = LongArray(6)
                for (i in 0..5) {
                    args[i] = notif.get(ValueLayout.JAVA_LONG, 32 + i * 8L)
                }

                val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
                val paths = getPathArgs(syscallName, args, pid)

                val pathStr = if (paths.isNotEmpty()) " paths=${paths.joinToString(", ")}" else ""
                println("[PROFILER] pid=$pid syscall=$syscallName args=[${args.joinToString(", ")}]$pathStr")
                System.out.flush()

                resp.fill(0)
                resp.set(ValueLayout.JAVA_LONG, 0, id)
                resp.set(ValueLayout.JAVA_LONG, 8, 0L)
                resp.set(ValueLayout.JAVA_INT, 16, 0)
                resp.set(ValueLayout.JAVA_INT, 20, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE)

                LinuxNative.ioctl(listenerFd, LinuxNative.SECCOMP_IOCTL_NOTIF_SEND, resp)
            }
        }
    }

    private fun readStringFromProcess(pid: Int, remoteAddress: Long, maxLen: Int = 4096): String? {
        Arena.ofConfined().use { arena ->
            val localBuf = arena.allocate(maxLen.toLong())
            localBuf.fill(0)

            val localIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            localIov.set(ValueLayout.ADDRESS, 0, localBuf)
            localIov.set(ValueLayout.JAVA_LONG, 8, maxLen.toLong())

            val remoteIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            remoteIov.set(ValueLayout.ADDRESS, 0, MemorySegment.ofAddress(remoteAddress))
            remoteIov.set(ValueLayout.JAVA_LONG, 8, maxLen.toLong())

            val res = LinuxNative.processVmReadv(pid, localIov, 1, remoteIov, 1, 0)
            if (res.returnValue < 0) {
                System.err.println("processVmReadv failed for pid $pid at addr 0x${java.lang.Long.toHexString(remoteAddress)}: ret=${res.returnValue}, errno=${res.errno}")
                System.err.flush()
                return null
            }

            val bytesRead = res.returnValue.toInt()
            var len = 0
            while (len < bytesRead && localBuf.get(ValueLayout.JAVA_BYTE, len.toLong()) != 0.toByte()) {
                len++
            }
            val bytes = ByteArray(len)
            for (i in 0 until len) {
                bytes[i] = localBuf.get(ValueLayout.JAVA_BYTE, i.toLong())
            }
            return String(bytes, StandardCharsets.UTF_8)
        }
    }

    private fun getPathArgs(syscallName: String, args: LongArray, pid: Int): List<String> {
        val paths = mutableListOf<String>()
        
        fun tryRead(addr: Long) {
            if (addr != 0L) {
                val path = readStringFromProcess(pid, addr)
                if (path != null) {
                    paths.add(path)
                }
            }
        }

        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK" -> {
                tryRead(args[0])
            }
            "OPENAT", "OPENAT2", "EXECVEAT" -> {
                tryRead(args[1])
            }
            "RENAME", "LINK", "SYMLINK" -> {
                tryRead(args[0])
                tryRead(args[1])
            }
        }
        return paths
    }
}
