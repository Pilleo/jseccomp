package io.mazewall

import io.mazewall.ffi.Layouts
import io.mazewall.seccomp.BpfInstruction
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment

/**
 * A mock implementation of [NativeEngine] for testing fault injection.
 */
open class MockNativeEngine : NativeEngine {
    var prctlResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var syscallResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var closeResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var openResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var bindResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var listenResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var acceptResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var connectResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var sendmsgResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var recvmsgResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var ioctlResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var readResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var writeResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var recvResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var fcntlResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var pollResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)
    var readlinkResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(0)

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
    ) = openResult

    override fun close(fd: LinuxNative.FileDescriptor) = closeResult

    override fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ) = LinuxNative.SyscallResult.Success(0)

    override fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ) = LinuxNative.SyscallResult.Success(0)

    override fun bind(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: Int,
    ) = bindResult

    override fun listen(
        sockfd: LinuxNative.FileDescriptor,
        backlog: Int,
    ) = listenResult

    override fun accept(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ) = acceptResult

    override fun connect(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: Int,
    ) = connectResult

    override fun sendmsg(
        sockfd: LinuxNative.FileDescriptor,
        msg: MemorySegment,
        flags: Int,
    ) = sendmsgResult

    override fun recvmsg(
        sockfd: LinuxNative.FileDescriptor,
        msg: MemorySegment,
        flags: Int,
    ) = recvmsgResult

    override fun ioctl(
        fd: LinuxNative.FileDescriptor,
        request: Long,
        arg: MemorySegment,
    ) = ioctlResult

    override fun ioctl(
        fd: LinuxNative.FileDescriptor,
        request: Long,
        arg: Long,
    ) = ioctlResult

    override fun processVmReadv(
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ) = LinuxNative.SyscallResult.Success(0)

    override fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ) = readlinkResult

    override fun read(
        fd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        count: Long,
    ) = readResult

    override fun write(
        fd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        count: Long,
    ) = writeResult

    override fun recv(
        sockfd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ) = recvResult

    override fun fcntl(
        fd: LinuxNative.FileDescriptor,
        cmd: Int,
        arg: Long,
    ) = fcntlResult

    override fun gettid() = 1234

    override fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ) = pollResult

    context(arena: Arena)
    override fun newSockFProg(
        filters: List<BpfInstruction>,
    ): MemorySegment {
        return arena.allocate(Layouts.SOCK_FPROG)
    }
}
