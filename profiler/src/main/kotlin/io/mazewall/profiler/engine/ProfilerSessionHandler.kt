package io.mazewall.profiler.engine

import io.mazewall.ffi.NativeConstants
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
    val ledger = SessionEventLedger()

    var state: ProfilerState = ProfilerState.ActiveSession(socketFd, listenerFd)
        private set

    @Suppress("ReturnCount")
    fun handleActiveListener(
        pollFds: MemorySegment,
        ackBuf: MemorySegment,
        notif: MemorySegment,
        resp: MemorySegment,
        socketPollFd: MemorySegment,
    ): LoopAction {
        val currentState = state
        if (currentState is ProfilerState.Terminated) {
            return LoopAction.Break
        }

        val socketRevents = pollFds.get(ValueLayout.JAVA_SHORT, POLLFD_REVENT_DATA_OFF)
        if ((socketRevents.toInt() and NativeConstants.POLLIN.toInt()) != 0) {
            if (handleShutdownRequest(ackBuf)) {
                state = ProfilerState.Terminated
                return LoopAction.Shutdown
            }
        }

        val listenerRevents = pollFds.get(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF)
        if ((listenerRevents.toInt() and NativeConstants.POLLIN.toInt()) != 0) {
            notif.fill(0)
            val recvRes = transport.ioctl(listenerFd, SECCOMP_IOCTL_NOTIF_RECV, notif)
            if (recvRes.returnValue == 0L) {
                if (!processNotification(notif, resp, ackBuf, socketPollFd)) {
                    state = ProfilerState.Terminated
                    return LoopAction.Break
                }
            }
        }
        return LoopAction.Continue
    }

    @Suppress("ReturnCount")
    private fun handleShutdownRequest(ackBuf: MemorySegment): Boolean {
        val res = transport.recv(socketFd, ackBuf, 1L, 0)
        if (res.returnValue > 0) {
            val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
            if (command == SHUTDOWN_COMMAND_BYTE) {
                onShutdown("Parent Command")
                return true
            }
            // Discard any other byte (e.g. delayed PROTOCOL_ACK_BYTE) to prevent infinite poll spin
            return false
        } else if (res.returnValue == 0L) {
            return true // parent socket closed
        }
        return false
    }

    internal fun processNotification(
        notif: MemorySegment,
        resp: MemorySegment,
        ackBuf: MemorySegment,
        socketPollFd: MemorySegment,
    ): Boolean {
        val id = notif.get(ValueLayout.JAVA_LONG, NOTIF_ID_OFF)
        val pid = notif.get(ValueLayout.JAVA_INT, NOTIF_PID_OFF)
        val nr = notif.get(ValueLayout.JAVA_INT, NOTIF_NR_OFF)
        ledger.record(SessionEvent.Notified(System.nanoTime(), pid.toLong(), nr.toLong()))

        val args = LongArray(MAX_SYSCALL_ARGS)
        for (i in 0 until MAX_SYSCALL_ARGS) {
            args[i] = notif.get(ValueLayout.JAVA_LONG, NOTIF_ARGS_OFF + i * ValueLayout.JAVA_LONG.byteSize())
        }

        val syscallName = syscallMap[nr] ?: "SYSCALL_$nr"
        val paths = SyscallPathResolver(memoryReader, pid, ledger).getPathArgs(syscallName, args)
        val event = TraceEvent(pid, syscallName, args, paths)

        // Transition to Notified state
        state = ProfilerState.Notified(socketFd, listenerFd, id, event)

        socketPollFd.set(ValueLayout.JAVA_INT, POLLFD_FD_OFF, socketFd)
        socketPollFd.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFF, NativeConstants.POLLIN)

        // Transition to WaitingForAck state
        state = ProfilerState.WaitingForAck(socketFd, listenerFd, id)

        @Suppress("TooGenericExceptionCaught")
        return try {
            transport.sendTraceEvent(socketFd, event)
            ledger.record(SessionEvent.EventSent(System.nanoTime(), pid.toLong()))
            val success = waitForParentAck(socketPollFd, ackBuf)
            if (success) {
                ledger.record(SessionEvent.AckReceived(System.nanoTime(), pid.toLong()))
                state = ProfilerState.ActiveSession(socketFd, listenerFd)
            } else {
                logger.warning {
                    "ACK wait failed (timeout or error). Dumping SessionEventLedger:\n" +
                        ledger.dump().joinToString("\n")
                }
                state = ProfilerState.Terminated
            }
            success
        } catch (e: Throwable) {
            logger.severe {
                "Exception in processNotification: ${e.message}. Dumping SessionEventLedger:\n" +
                    ledger.dump().joinToString("\n")
            }
            throw e
        } finally {
            sendContinueResponse(id, resp, pid.toLong())
        }
    }

    @Suppress("ReturnCount", "NestedBlockDepth")
    private fun waitForParentAck(
        pollFd: MemorySegment,
        ackBuf: MemorySegment,
    ): Boolean {
        pollFd.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, 0.toShort())

        while (true) {
            val pollRes = transport.poll(pollFd, 1L, POLL_ACK_TIMEOUT_MS)
            if (pollRes.returnValue <= 0) {
                if (pollRes.returnValue == 0L) return false
                if (pollRes.errno != EINTR) return false
                continue
            }
            val revents = pollFd.get(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF)
            if ((revents.toInt() and NativeConstants.POLLIN.toInt()) != 0) {
                while (true) {
                    val readRes = transport.read(socketFd, ackBuf, ACK_BUF_SIZE)
                    if (readRes.returnValue > 0) {
                        val command = ackBuf.get(ValueLayout.JAVA_BYTE, 0L)
                        if (command == SHUTDOWN_COMMAND_BYTE) {
                            onShutdown("Shutdown Command (inline)")
                        }
                        return true
                    }
                    if (readRes.returnValue < 0 && readRes.errno == EINTR) {
                        continue
                    }
                    return false
                }
            }
            return false
        }
    }

    private fun sendContinueResponse(
        id: Long,
        resp: MemorySegment,
        pid: Long,
    ) {
        resp.fill(0)
        resp.set(ValueLayout.JAVA_LONG, RESP_ID_OFF, id)
        resp.set(ValueLayout.JAVA_LONG, RESP_VAL_OFF, 0L)
        resp.set(ValueLayout.JAVA_INT, RESP_ERR_OFF, 0)
        resp.set(ValueLayout.JAVA_INT, RESP_FLAGS_OFF, NativeConstants.SECCOMP_USER_NOTIF_FLAG_CONTINUE.toInt())
        transport.ioctl(listenerFd, SECCOMP_IOCTL_NOTIF_SEND, resp)
        ledger.record(SessionEvent.ContinueReplied(System.nanoTime(), pid, 0L))
    }

    companion object {
        private val logger = java.util.logging.Logger.getLogger(ProfilerSessionHandler::class.java.name)
    }
}

private class SyscallPathResolver(
    private val memoryReader: ProfilerMemoryReader,
    private val pid: Int,
    private val ledger: SessionEventLedger,
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
        val path = memoryReader.readStringFromProcess(pid, addr)
        ledger.record(SessionEvent.VmReadvResolved(System.nanoTime(), pid.toLong(), path != null))
        if (path == null) return null
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
