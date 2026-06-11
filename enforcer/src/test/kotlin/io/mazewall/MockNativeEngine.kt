package io.mazewall

import io.mazewall.ffi.Layouts
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment

/**
 * A mock implementation of [NativeEngine] for testing fault injection.
 */
open class MockNativeEngine : NativeEngine {
    var prctlResult = LinuxNative.SyscallResult(0, 0)
    var syscallResult = LinuxNative.SyscallResult(0, 0)
    var closeResult = LinuxNative.SyscallResult(0, 0)

    override fun prctl(
        option: Int,
        arg2: Any?,
        arg3: Any?,
        arg4: Any?,
        arg5: Any?,
    ) = prctlResult

    override fun syscall(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
        a5: Any?,
        a6: Any?,
    ) = syscallResult

    override fun syscall4(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
    ) = syscallResult

    override fun open(
        path: MemorySegment,
        flags: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun close(fd: Int) = closeResult

    override fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun bind(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun listen(
        sockfd: Int,
        backlog: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun accept(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun connect(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun sendmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun recvmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun processVmReadv(
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun fcntl(
        fd: Int,
        cmd: Int,
        arg: Long,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun gettid() = 1234

    override fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ) = LinuxNative.SyscallResult(0, 0)

    override fun newSockFProg(
        arena: Arena,
        filters: Array<SockFilter>,
    ): MemorySegment {
        return arena.allocate(Layouts.SOCK_FPROG)
    }
}
