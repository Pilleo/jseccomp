package io.mazewall

import io.mazewall.ffi.Layouts
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.lang.invoke.MethodHandles

// Corresponds to struct sock_filter
data class SockFilter(
    val code: Short,
    val jt: Short,
    val jf: Short,
    val k: Int,
) {
    init {
        require(jt in 0..255) { "jt offset must be an unsigned 8-bit value (0-255), got $jt" }
        require(jf in 0..255) { "jf offset must be an unsigned 8-bit value (0-255), got $jf" }
    }
}

object LinuxNative : NativeEngine {
    @Volatile
    private var engine: NativeEngine = RealNativeEngine

    /**
     * Swaps the active native engine. Used for testing and fault injection.
     */
    @Suppress("spotbugs:ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")
    fun setEngine(newEngine: NativeEngine) {
        engine = newEngine
    }

    /**
     * Restores the default RealNativeEngine.
     */
    @Suppress("spotbugs:ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")
    fun resetToDefault() {
        engine = RealNativeEngine
    }

    fun getFileSystem(): NativeFileSystem = engine

    fun getNetworking(): NativeNetworking = engine

    fun getProcess(): NativeProcess = engine

    fun getMemory(): NativeMemory = engine

    override fun prctl(
        option: Int,
        arg2: Any?,
        arg3: Any?,
        arg4: Any?,
        arg5: Any?,
    ) = engine.prctl(option, arg2, arg3, arg4, arg5)

    override fun syscall(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
        a5: Any?,
        a6: Any?,
    ) = engine.syscall(nr, a1, a2, a3, a4, a5, a6)

    override fun syscall4(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
    ) = engine.syscall4(nr, a1, a2, a3, a4)

    override fun open(
        path: MemorySegment,
        flags: Int,
    ) = engine.open(path, flags)

    override fun close(fd: Int) = engine.close(fd)

    override fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ) = engine.socketpair(domain, type, protocol, sv)

    override fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ) = engine.socket(domain, type, protocol)

    override fun bind(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ) = engine.bind(sockfd, addr, addrlen)

    override fun listen(
        sockfd: Int,
        backlog: Int,
    ) = engine.listen(sockfd, backlog)

    override fun accept(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ) = engine.accept(sockfd, addr, addrlen)

    override fun connect(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ) = engine.connect(sockfd, addr, addrlen)

    override fun sendmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ) = engine.sendmsg(sockfd, msg, flags)

    override fun recvmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ) = engine.recvmsg(sockfd, msg, flags)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ) = engine.ioctl(fd, request, arg)

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: Long,
    ) = engine.ioctl(fd, request, arg)

    override fun processVmReadv(
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ) = engine.processVmReadv(pid, localIov, liovcnt, remoteIov, riovcnt, flags)

    override fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ) = engine.readlink(path, buf, bufsiz)

    override fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ) = engine.read(fd, buf, count)

    override fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ) = engine.write(fd, buf, count)

    override fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ) = engine.recv(sockfd, buf, len, flags)

    override fun fcntl(
        fd: Int,
        cmd: Int,
        arg: Long,
    ) = engine.fcntl(fd, cmd, arg)

    override fun gettid() = engine.gettid()

    override fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ) = engine.poll(fds, nfds, timeout)

    override fun newSockFProg(
        arena: Arena,
        filters: Array<SockFilter>,
    ) = engine.newSockFProg(arena, filters)

    data class SyscallResult(
        val returnValue: Long,
        val errno: Int,
    )
}

/**
 * Real implementation of NativeEngine using FFM to call Linux system calls.
 */
internal object RealNativeEngine : NativeEngine {
    private val linker: Linker = Linker.nativeLinker()
    private val stdlib: SymbolLookup = linker.defaultLookup()

    private val PRCTL: MethodHandle
    private val SYSCALL: MethodHandle
    private val OPEN: MethodHandle
    private val CLOSE: MethodHandle
    private val SOCKETPAIR: MethodHandle
    private val SOCKET: MethodHandle
    private val BIND: MethodHandle
    private val LISTEN: MethodHandle
    private val ACCEPT: MethodHandle
    private val CONNECT: MethodHandle
    private val SENDMSG: MethodHandle
    private val RECVMSG: MethodHandle
    private val IOCTL_ADDR: MethodHandle
    private val IOCTL_LONG: MethodHandle
    private val PROCESS_VM_READV: MethodHandle
    private val READLINK: MethodHandle
    private val READ: MethodHandle
    private val WRITE: MethodHandle
    private val RECV: MethodHandle
    private val FCNTL: MethodHandle
    private val GETTID: MethodHandle
    private val POLL: MethodHandle

    init {
        PRCTL =
            downcall(
                "prctl",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        SYSCALL =
            downcall(
                "syscall",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        OPEN =
            downcall(
                "open",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
                Linker.Option.captureCallState("errno"),
            )
        CLOSE =
            downcall(
                "close",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
                Linker.Option.captureCallState("errno"),
            )
        SOCKETPAIR =
            downcall(
                "socketpair",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                ),
                Linker.Option.captureCallState("errno"),
            )
        SOCKET =
            downcall(
                "socket",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        BIND =
            downcall(
                "bind",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        LISTEN =
            downcall(
                "listen",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
                Linker.Option.captureCallState("errno"),
            )
        ACCEPT =
            downcall(
                "accept",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                Linker.Option.captureCallState("errno"),
            )
        CONNECT =
            downcall(
                "connect",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        SENDMSG =
            downcall(
                "sendmsg",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        RECVMSG =
            downcall(
                "recvmsg",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        IOCTL_ADDR =
            downcall(
                "ioctl",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS,
                ),
                Linker.Option.captureCallState("errno"),
            )
        IOCTL_LONG =
            downcall(
                "ioctl",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        PROCESS_VM_READV =
            downcall(
                "process_vm_readv",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        READLINK =
            downcall(
                "readlink",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        READ =
            downcall(
                "read",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        WRITE =
            downcall(
                "write",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        RECV =
            downcall(
                "recv",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
        FCNTL =
            downcall(
                "fcntl",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_LONG,
                ),
                Linker.Option.captureCallState("errno"),
            )
        GETTID =
            downcall(
                "gettid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT),
                Linker.Option.captureCallState("errno"),
            )
        POLL =
            downcall(
                "poll",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                ),
                Linker.Option.captureCallState("errno"),
            )
    }

    private fun Any?.toLong(): Long =
        when (this) {
            is Number -> this.toLong()
            is MemorySegment -> this.address()
            null -> 0L
            else -> throw IllegalArgumentException("Unsupported native call argument type: ${this.javaClass.name}")
        }

    override fun prctl(
        option: Int,
        arg2: Any?,
        arg3: Any?,
        arg4: Any?,
        arg5: Any?,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret =
                PRCTL.invokeExact(
                    capturedState,
                    option,
                    arg2.toLong(),
                    arg3.toLong(),
                    arg4.toLong(),
                    arg5.toLong(),
                ) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun syscall(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
        a5: Any?,
        a6: Any?,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret =
                SYSCALL.invokeExact(
                    capturedState,
                    nr,
                    a1.toLong(),
                    a2.toLong(),
                    a3.toLong(),
                    a4.toLong(),
                    a5.toLong(),
                    a6.toLong(),
                ) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun syscall4(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
    ): LinuxNative.SyscallResult = syscall(nr, a1, a2, a3, a4)

    override fun open(
        path: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = OPEN.invokeExact(capturedState, path, flags) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun close(fd: Int): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = CLOSE.invokeExact(capturedState, fd) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = SOCKETPAIR.invokeExact(capturedState, domain, type, protocol, sv) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = SOCKET.invokeExact(capturedState, domain, type, protocol) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun bind(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = BIND.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun listen(
        sockfd: Int,
        backlog: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = LISTEN.invokeExact(capturedState, sockfd, backlog) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun accept(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = ACCEPT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun connect(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = CONNECT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun sendmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = SENDMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun recvmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = RECVMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = IOCTL_ADDR.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun ioctl(
        fd: Int,
        request: Long,
        arg: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = IOCTL_LONG.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun processVmReadv(
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret =
                PROCESS_VM_READV.invokeExact(capturedState, pid, localIov, liovcnt, remoteIov, riovcnt, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = READLINK.invokeExact(capturedState, path, buf, bufsiz) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = READ.invokeExact(capturedState, fd, buf, count) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = WRITE.invokeExact(capturedState, fd, buf, count) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = RECV.invokeExact(capturedState, sockfd, buf, len, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret, errno)
        }
    }

    override fun fcntl(
        fd: Int,
        cmd: Int,
        arg: Long,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = FCNTL.invokeExact(capturedState, fd, cmd, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun gettid(): Int {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = GETTID.invokeExact(capturedState) as Int
            return ret
        }
    }

    override fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ): LinuxNative.SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(Layouts.ERRNO)
            val ret = POLL.invokeExact(capturedState, fds, nfds, timeout) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, Layouts.ERRNO_OFFSET)
            return LinuxNative.SyscallResult(ret.toLong(), errno)
        }
    }

    override fun newSockFProg(
        arena: Arena,
        filters: Array<SockFilter>,
    ): MemorySegment {
        val filterArraySeg = arena.allocate(MemoryLayout.sequenceLayout(filters.size.toLong(), Layouts.SOCK_FILTER))
        for (i in filters.indices) {
            val f = filters[i]
            val offset = i * Layouts.SOCK_FILTER_SIZE
            filterArraySeg.set(ValueLayout.JAVA_SHORT, offset, f.code)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 2, f.jt.toByte())
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 3, f.jf.toByte())
            filterArraySeg.set(ValueLayout.JAVA_INT, offset + 4, f.k)
        }
        val prog = arena.allocate(Layouts.SOCK_FPROG)
        prog.set(ValueLayout.JAVA_SHORT, Layouts.SOCK_FPROG_LEN_OFFSET, filters.size.toShort())
        prog.set(ValueLayout.ADDRESS, Layouts.SOCK_FPROG_FILTER_OFFSET, filterArraySeg)
        return prog
    }

    private fun downcall(
        name: String,
        fd: FunctionDescriptor,
        vararg options: Linker.Option,
    ): MethodHandle {
        val symbol =
            stdlib.find(name).orElse(null) ?: run {
                val ex = UnsupportedOperationException("Symbol $name not found in libc")
                val throwingHandle =
                    MethodHandles.insertArguments(
                        MethodHandles.throwException(Int::class.java, UnsupportedOperationException::class.java),
                        0,
                        ex,
                    )
                return MethodHandles.dropArguments(
                    throwingHandle,
                    0,
                    *fd.argumentLayouts().map { it.javaType() }.toTypedArray(),
                )
            }
        return linker.downcallHandle(symbol, fd, *options)
    }

    private fun MemoryLayout.javaType(): Class<*> =
        when (this) {
            is ValueLayout.OfByte -> Byte::class.java
            is ValueLayout.OfShort -> Short::class.java
            is ValueLayout.OfInt -> Int::class.java
            is ValueLayout.OfLong -> Long::class.java
            is ValueLayout.OfFloat -> Float::class.java
            is ValueLayout.OfDouble -> Double::class.java
            else -> MemorySegment::class.java
        }
}
