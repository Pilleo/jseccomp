package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Result of a reactor loop iteration.
 */
internal sealed class LoopAction {
    object Continue : LoopAction()

    object Break : LoopAction()

    object Shutdown : LoopAction()
}

/**
 * Internal logic for handling active seccomp listeners and shutdown requests.
 */
internal class ProfilerSessionHandler(
    private val socketFd: Int,
    private val listenerFd: Int,
    private val transport: ProfilerTransport,
    private val memoryReader: ProfilerMemoryReader,
    private val syscallMap: Map<Int, String>,
    private val onShutdown: (String) -> Unit,
) {
    fun handleActiveListener(
        pollFds: MemorySegment,
        ackBuf: MemorySegment,
        notif: MemorySegment,
        resp: MemorySegment,
    ): LoopAction {
        val socketRevents = pollFds.get(ValueLayout.JAVA_SHORT, POLLFD_REVENT_DATA_OFF)
        if ((socketRevents.toInt() and LinuxNative.POLLIN.toInt()) != 0) {
            if (handleShutdownRequest(ackBuf)) return LoopAction.Shutdown
        }

        val listenerRevents = pollFds.get(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF)
        if ((listenerRevents.toInt() and LinuxNative.POLLIN.toInt()) != 0) {
            notif.fill(0)
            val recvRes = transport.ioctl(listenerFd, SECCOMP_IOCTL_NOTIF_RECV, notif)
            if (recvRes.returnValue == 0L) {
                if (!processNotification(notif, resp, ackBuf)) {
                    return LoopAction.Break
                }
            }
        }
        return LoopAction.Continue
    }

    private fun handleShutdownRequest(ackBuf: MemorySegment): Boolean {
        val res = transport.recv(socketFd, ackBuf, ACK_BUF_SIZE, MSG_PEEK)
        if (res.returnValue > 0 && ackBuf.get(ValueLayout.JAVA_BYTE, 0L) == SHUTDOWN_COMMAND_BYTE) {
            onShutdown("Parent Command")
            return true
        } else if (res.returnValue == 0L) {
            return true // parent socket closed
        }
        return false
    }

    internal fun processNotification(
        notif: MemorySegment,
        resp: MemorySegment,
        ackBuf: MemorySegment,
    ): Boolean {
        Arena.ofConfined().use { arena ->
            val pollFd = arena.allocate(LinuxNative.POLLFD_LAYOUT)
            pollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, socketFd)
            pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, LinuxNative.POLLIN)

            val id = notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
            val pid = notif.get(ValueLayout.JAVA_INT, NOTIF_PID_OFF)
            val nr = notif.get(ValueLayout.JAVA_INT, NOTIF_NR_OFF)
            val args = LongArray(MAX_SYSCALL_ARGS)
            for (i in 0 until MAX_SYSCALL_ARGS) {
                args[i] = notif.get(ValueLayout.JAVA_LONG, NOTIF_ARGS_OFF + i * ValueLayout.JAVA_LONG.byteSize())
            }

            val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
            val paths = SyscallPathResolver(memoryReader, pid).getPathArgs(syscallName, args)

            return try {
                transport.sendTraceEvent(socketFd, TraceEvent(pid, syscallName, args, paths))
                waitForParentAck(pollFd, ackBuf)
            } finally {
                sendContinueResponse(id, resp)
            }
        }
    }

    private fun waitForParentAck(
        pollFd: MemorySegment,
        ackBuf: MemorySegment,
    ): Boolean {
        pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, 0.toShort())

        while (true) {
            val pollRes = transport.poll(pollFd, 1L, POLL_ACK_TIMEOUT_MS)
            if (pollRes.returnValue <= 0) {
                if (pollRes.returnValue < 0L && pollRes.errno != EINTR) return false
                continue
            }
            val revents = pollFd.get(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF)
            if ((revents.toInt() and LinuxNative.POLLIN.toInt()) != 0) {
                val readRes = transport.read(socketFd, ackBuf, ACK_BUF_SIZE)
                if (readRes.returnValue > 0) {
                    val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
                    if (command == SHUTDOWN_COMMAND_BYTE) {
                        onShutdown("Shutdown Command (inline)")
                    }
                    return true
                }
            }
            return false
        }
    }

    private fun sendContinueResponse(
        id: Long,
        resp: MemorySegment,
    ) {
        resp.fill(0)
        resp.set(ValueLayout.JAVA_LONG, RESP_ID_OFF, id)
        resp.set(ValueLayout.JAVA_LONG, RESP_VAL_OFF, 0L)
        resp.set(ValueLayout.JAVA_INT, RESP_ERR_OFF, 0)
        resp.set(ValueLayout.JAVA_INT, RESP_FLAGS_OFF, LinuxNative.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
        transport.ioctl(listenerFd, SECCOMP_IOCTL_NOTIF_SEND, resp)
    }
}

private class SyscallPathResolver(
    private val memoryReader: ProfilerMemoryReader,
    private val pid: Int,
) {
    fun getPathArgs(
        syscallName: String,
        args: LongArray,
    ): List<String> =
        when (syscallName) {
            "OPEN", "EXECVE", "MKDIR", "RMDIR", "CHMOD", "CHOWN", "LCHOWN", "UNLINK", "READLINK", "CHROOT", "UTIME", "UTIMES" ->
                listOfNotNull(tryRead(args[0]))

            "FCHMOD", "FCHOWN", "FSTAT" ->
                listOfNotNull(resolveFdPath(args[0].toInt()))

            "SYMLINK", "LINK", "RENAME" ->
                listOfNotNull(tryRead(args[0]), tryRead(args[1]))

            "OPENAT", "EXECVEAT", "OPENAT2", "MKDIRAT", "UNLINKAT", "FCHMODAT", "FCHOWNAT", "UTIMENSAT", "FSTATAT", "READLINKAT" ->
                listOfNotNull(tryRead(args[ARG_PATH], args[ARG_DIR_FD]))

            "RENAMEAT", "RENAMEAT2", "LINKAT", "SYMLINKAT" ->
                listOfNotNull(
                    tryRead(args[ARG_OLD_PATH], args[ARG_OLD_DIR_FD]),
                    tryRead(args[ARG_NEW_PATH], args[ARG_NEW_DIR_FD]),
                )

            else -> emptyList()
        }

    private fun resolveCwd(): String? = memoryReader.resolveLink(pid, "cwd")

    private fun resolveFdPath(fd: Int): String? = memoryReader.resolveLink(pid, "fd/$fd")

    private fun isAtFdcwd(fd: Long): Boolean = fd == AT_FDCWD_VAL || fd == AT_FDCWD_UNSIGNED_VAL || fd.toInt() == AT_FDCWD_INT_VAL

    private fun tryRead(
        addr: Long,
        dirfd: Long = AT_FDCWD_VAL,
    ): String? {
        if (addr == 0L) return null
        val path = memoryReader.readStringFromProcess(pid, addr) ?: return null
        return if (path.startsWith("/")) path else resolveRelativePath(path, dirfd)
    }

    private fun resolveRelativePath(
        path: String,
        dirfd: Long,
    ): String? {
        val dirPath = if (isAtFdcwd(dirfd)) {
            resolveCwd()
        } else if (dirfd >= 0) {
            resolveFdPath(dirfd.toInt())
        } else {
            null
        }
        return if (dirPath != null) {
            if (dirPath.endsWith("/")) "$dirPath$path" else "$dirPath/$path"
        } else {
            path
        }
    }
}
