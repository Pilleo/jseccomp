package io.mazewall.profiler.internal

import io.mazewall.LinuxNative
import io.mazewall.ffi.Layouts
import io.mazewall.profiler.engine.DescriptorPassing
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

internal object ProfilerSocket {
    const val AF_UNIX = 1
    const val SOCK_STREAM = 1
    const val ADDR_UN_SIZE = 110
    const val SOCKADDR_UN_PATH_SIZE = 108
    private const val CMSG_LEN_VAL = 20L
    private const val CMSG_LEN_OFF = 0L
    private const val CMSG_LEVEL_OFF = 8L
    private const val CMSG_TYPE_OFF = 12L
    private const val CMSG_DATA_OFF = 16L
    private const val SOL_SOCKET_VAL = 1
    private const val SCM_RIGHTS_VAL = 1

    fun connectWithRetry(
        socketPath: String,
        maxRetries: Int = 300,
        delayMs: Long = 100L,
    ): Int {
        Arena.ofConfined().use { arena ->
            val addr = setupSockAddrUn(arena, socketPath)

            var lastErrno = 0
            for (retry in 0 until maxRetries) {
                val fdRes = LinuxNative.socket(AF_UNIX, SOCK_STREAM, 0)
                if (fdRes.returnValue < 0) {
                    throw IllegalStateException("Failed to create socket: errno=${fdRes.errno}")
                }
                val fd = fdRes.returnValue.toInt()
                val connRes = LinuxNative.connect(fd, addr, ADDR_UN_SIZE)
                if (connRes.returnValue == 0L) {
                    return fd
                }
                lastErrno = connRes.errno
                LinuxNative.close(fd)

                Thread.sleep(delayMs)
            }
            throw IllegalStateException(
                "Failed to connect to daemon socket at $socketPath after $maxRetries retries. Last errno=$lastErrno",
            )
        }
    }

    fun sendDescriptor(
        socketFd: Int,
        fdToSend: Int,
    ): Boolean {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            dummyByte.set(ValueLayout.JAVA_BYTE, 0, 0.toByte())

            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            controlBuf.set(ValueLayout.JAVA_LONG, CMSG_LEN_OFF, CMSG_LEN_VAL) // cmsg_len
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_LEVEL_OFF, SOL_SOCKET_VAL) // cmsg_level (SOL_SOCKET = 1)
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_TYPE_OFF, SCM_RIGHTS_VAL) // cmsg_type (SCM_RIGHTS = 1)
            controlBuf.set(ValueLayout.JAVA_INT, CMSG_DATA_OFF, fdToSend)

            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)

            val res = LinuxNative.sendmsg(socketFd, msg, 0)
            return res.returnValue >= 0
        }
    }

    fun setupSockAddrUn(
        arena: Arena,
        socketPath: String,
    ): MemorySegment {
        val addr = arena.allocate(Layouts.SOCKADDR_UN)
        addr.fill(0)
        addr.set(ValueLayout.JAVA_SHORT, 0L, AF_UNIX.toShort())
        val pathBytes = socketPath.toByteArray(Charsets.UTF_8)
        val pathSeg = addr.asSlice(2, SOCKADDR_UN_PATH_SIZE.toLong())
        MemorySegment.copy(pathBytes, 0, pathSeg, ValueLayout.JAVA_BYTE, 0L, pathBytes.size)
        return addr
    }
}
