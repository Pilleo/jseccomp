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
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ): LinuxNative.SyscallResult

    fun ioctl(
        fd: Int,
        request: Long,
        arg: Long,
    ): LinuxNative.SyscallResult

    fun fcntl(
        fd: Int,
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

    fun close(fd: Int): LinuxNative.SyscallResult
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
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult

    fun listen(
        sockfd: Int,
        backlog: Int,
    ): LinuxNative.SyscallResult

    fun accept(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ): LinuxNative.SyscallResult

    fun connect(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult

    fun sendmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun recvmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult

    fun recv(
        sockfd: Int,
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
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
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

    context(arena: Arena)
    fun newSockFProg(
        filters: List<BpfInstruction>,
    ): MemorySegment
}
