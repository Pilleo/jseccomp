package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import java.io.DataOutputStream
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

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
}

/**
 * Real implementation of [ProfilerTransport] using UNIX sockets and SCM_RIGHTS.
 */
object RealProfilerTransport : ProfilerTransport {
    private val socketLocks = ConcurrentHashMap<Int, Any>()
    private const val CMSG_DATA_OFF = 16L

    override fun sendTraceEvent(
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
            Arena.ofConfined().use { arena ->
                val buf = arena.allocate(bytes.size.toLong())
                MemorySegment.copy(bytes, 0, buf, ValueLayout.JAVA_BYTE, 0L, bytes.size)
                LinuxNative.write(socketFd, buf, bytes.size.toLong())
            }
        }
    }

    override fun recvDescriptor(socketFd: Int): Int? {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            val msg = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)
            if (LinuxNative.recvmsg(socketFd, msg, 0).returnValue < 0) return null
            return controlBuf.get(ValueLayout.JAVA_INT, CMSG_DATA_OFF)
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
    ) = LinuxNative.read(fd, buf, count)

    override fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ) = LinuxNative.write(fd, buf, count)

    override fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ) = LinuxNative.recv(sockfd, buf, len, flags)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ) = LinuxNative.ioctl(fd, request, arg)
}
