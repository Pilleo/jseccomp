package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import io.mazewall.ffi.Layouts
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * Interface for communicating with the parent JVM and receiving file descriptors.
 */
interface ProfilerTransport {
    fun sendTraceEvent(
        socketFd: Int,
        event: TraceEvent,
    )

    fun recvDescriptor(socketFd: Int): Int?

    fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ): LinuxNative.SyscallResult

    fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult

    fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult

    fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ): LinuxNative.SyscallResult

    fun createServer(socketPath: String): Int

    fun accept(serverFd: Int): Int

    fun close(fd: Int)
}

/**
 * Real implementation of [ProfilerTransport] using standard Linux syscalls.
 */
@Suppress("MagicNumber", "ReturnCount", "ThrowsCount")
object RealProfilerTransport : ProfilerTransport {
    private const val CMSG_LEN_VAL = 20L
    private const val CMSG_LEN_OFF = 0L
    private const val CMSG_LEVEL_OFF = 8L
    private const val CMSG_TYPE_OFF = 12L
    private const val CMSG_DATA_OFF = 16L
    private const val SOL_SOCKET_VAL = 1
    private const val SCM_RIGHTS_VAL = 1

    private val JAVA_INT_BE_UNALIGNED = ValueLayout.JAVA_INT.withOrder(java.nio.ByteOrder.BIG_ENDIAN).withByteAlignment(1)
    private val JAVA_LONG_BE_UNALIGNED = ValueLayout.JAVA_LONG.withOrder(java.nio.ByteOrder.BIG_ENDIAN).withByteAlignment(1)

    override fun sendTraceEvent(
        socketFd: Int,
        event: TraceEvent,
    ) {
        Arena.ofConfined().use { arena ->
            val syscallNameBytes = event.syscallName.toByteArray(StandardCharsets.UTF_8)
            val pathBytesList = event.paths.map { it.toByteArray(StandardCharsets.UTF_8) }

            var totalSize = 4 + 4 + syscallNameBytes.size + 4 + (event.args.size * 8) + 4
            for (p in pathBytesList) {
                totalSize += 4 + p.size
            }

            val buf = arena.allocate(totalSize.toLong())
            var offset = 0L
            buf.set(JAVA_INT_BE_UNALIGNED, offset, event.pid)
            offset += 4
            buf.set(JAVA_INT_BE_UNALIGNED, offset, syscallNameBytes.size)
            offset += 4
            MemorySegment.copy(syscallNameBytes, 0, buf, ValueLayout.JAVA_BYTE, offset, syscallNameBytes.size)
            offset += syscallNameBytes.size

            buf.set(JAVA_INT_BE_UNALIGNED, offset, event.args.size)
            offset += 4
            for (arg in event.args) {
                buf.set(JAVA_LONG_BE_UNALIGNED, offset, arg)
                offset += 8
            }

            buf.set(JAVA_INT_BE_UNALIGNED, offset, pathBytesList.size)
            offset += 4
            for (p in pathBytesList) {
                buf.set(JAVA_INT_BE_UNALIGNED, offset, p.size)
                offset += 4
                MemorySegment.copy(p, 0, buf, ValueLayout.JAVA_BYTE, offset, p.size)
                offset += p.size
            }

            val res = LinuxNative.write(socketFd, buf, totalSize.toLong())
            if (res.returnValue < 0) {
                throw java.io.IOException("Failed to send TraceEvent: errno=${res.errno}")
            }
        }
    }

    override fun recvDescriptor(socketFd: Int): Int? {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)

            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)

            while (true) {
                val res = LinuxNative.recvmsg(socketFd, msg, 0)
                if (res.returnValue < 0) {
                    if (res.errno == 4) { // EINTR
                        continue
                    }
                    return null
                }
                if (res.returnValue == 0L) {
                    return null // EOF
                }

                val cmsgLen = controlBuf.get(ValueLayout.JAVA_LONG, CMSG_LEN_OFF)
                val cmsgLevel = controlBuf.get(ValueLayout.JAVA_INT, CMSG_LEVEL_OFF)
                val cmsgType = controlBuf.get(ValueLayout.JAVA_INT, CMSG_TYPE_OFF)
                if (cmsgLen >= CMSG_LEN_VAL && cmsgLevel == SOL_SOCKET_VAL && cmsgType == SCM_RIGHTS_VAL) {
                    return controlBuf.get(ValueLayout.JAVA_INT, CMSG_DATA_OFF)
                }
                return null
            }
        }
    }

    override fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ): LinuxNative.SyscallResult = LinuxNative.poll(fds, nfds, timeout)

    override fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult = LinuxNative.read(fd, buf, count)

    override fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult = LinuxNative.write(fd, buf, count)

    override fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ): LinuxNative.SyscallResult = LinuxNative.recv(sockfd, buf, len, flags)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ): LinuxNative.SyscallResult = LinuxNative.ioctl(fd, request, arg)

    override fun createServer(socketPath: String): Int {
        val res = LinuxNative.socket(AF_UNIX, SOCK_STREAM, 0)
        if (res.returnValue < 0) {
            throw IllegalStateException("Failed to create daemon socket: errno=${res.errno}")
        }
        val fd = res.returnValue.toInt()

        Arena.ofConfined().use { arena ->
            val addr = arena.allocate(Layouts.SOCKADDR_UN)
            addr.fill(0)
            addr.set(ValueLayout.JAVA_SHORT, 0L, AF_UNIX.toShort())
            val pathBytes = socketPath.toByteArray(StandardCharsets.UTF_8)
            val pathSeg = addr.asSlice(2, SOCKADDR_UN_PATH_SIZE.toLong())
            MemorySegment.copy(pathBytes, 0, pathSeg, ValueLayout.JAVA_BYTE, 0L, pathBytes.size)

            val bindRes = LinuxNative.bind(fd, addr, ADDR_UN_SIZE)
            if (bindRes.returnValue < 0) {
                LinuxNative.close(fd)
                throw IllegalStateException("Failed to bind daemon socket: errno=${bindRes.errno}")
            }
        }

        val listenRes = LinuxNative.listen(fd, BACKLOG_SIZE)
        if (listenRes.returnValue < 0) {
            LinuxNative.close(fd)
            throw IllegalStateException("Failed to listen on daemon socket: errno=${listenRes.errno}")
        }
        return fd
    }

    override fun accept(serverFd: Int): Int {
        val res = LinuxNative.accept(serverFd, MemorySegment.NULL, MemorySegment.NULL)
        if (res.returnValue < 0) {
            throw IllegalStateException("Failed to accept client connection: errno=${res.errno}")
        }
        return res.returnValue.toInt()
    }

    override fun close(fd: Int) {
        LinuxNative.close(fd)
    }
}
