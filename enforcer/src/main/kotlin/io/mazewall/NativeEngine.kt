package io.mazewall

import io.mazewall.seccomp.BpfInstruction
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment

/**
 * Interface for Linux native system calls and utility functions.
 * Decoupling this allows for mocking and fault injection in tests.
 */
interface NativeEngine :
    NativeFileSystem,
    NativeNetworking,
    NativeProcess,
    NativeMemory {
    fun syscall(
        nr: Long,
        a1: Any? = 0L,
        a2: Any? = 0L,
        a3: Any? = 0L,
        a4: Any? = 0L,
        a5: Any? = 0L,
        a6: Any? = 0L,
    ): LinuxNative.SyscallResult

    fun syscall4(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
    ): LinuxNative.SyscallResult

    fun ioctl(
        fd: LinuxNative.FileDescriptor,
        request: Long,
        arg: MemorySegment,
    ): LinuxNative.SyscallResult

    fun ioctl(
        fd: LinuxNative.FileDescriptor,
        request: Long,
        arg: Long,
    ): LinuxNative.SyscallResult

    fun fcntl(
        fd: LinuxNative.FileDescriptor,
        cmd: Int,
        arg: Long,
    ): LinuxNative.SyscallResult

    fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ): LinuxNative.SyscallResult
}

interface NativeFileSystem {
    fun open(
        path: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ): LinuxNative.SyscallResult

    fun close(fd: LinuxNative.FileDescriptor): LinuxNative.SyscallResult
}

interface NativeNetworking {
    fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ): LinuxNative.SyscallResult

    fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ): LinuxNative.SyscallResult

    fun bind(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult

    fun listen(
        sockfd: LinuxNative.FileDescriptor,
        backlog: Int,
    ): LinuxNative.SyscallResult

    fun accept(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ): LinuxNative.SyscallResult

    fun connect(
        sockfd: LinuxNative.FileDescriptor,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult

    fun sendmsg(
        sockfd: LinuxNative.FileDescriptor,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun recvmsg(
        sockfd: LinuxNative.FileDescriptor,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun recv(
        sockfd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ): LinuxNative.SyscallResult
}

interface NativeProcess {
    fun gettid(): Int

    fun prctl(
        option: Int,
        arg2: Any? = 0L,
        arg3: Any? = 0L,
        arg4: Any? = 0L,
        arg5: Any? = 0L,
    ): LinuxNative.SyscallResult
}

interface NativeMemory {
    fun processVmReadv(
        pid: Int, localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ): LinuxNative.SyscallResult

    fun read(
        fd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult

    fun write(
        fd: LinuxNative.FileDescriptor,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult

    context(arena: Arena)
    fun newSockFProg(
        filters: List<BpfInstruction>,
    ): MemorySegment
}
