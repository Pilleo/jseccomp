package io.mazewall

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.StructLayout
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

object LinuxNative {
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

    val ERRNO_LAYOUT: StructLayout = Linker.Option.captureStateLayout()
    private val ERRNO_OFFSET: Long = ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno"))

    val SOCK_FILTER_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_SHORT.withName("code"),
            ValueLayout.JAVA_BYTE.withName("jt"),
            ValueLayout.JAVA_BYTE.withName("jf"),
            ValueLayout.JAVA_INT.withName("k"),
        )
    private val SOCK_FILTER_SIZE: Long = SOCK_FILTER_LAYOUT.byteSize()

    val SOCK_FPROG_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_SHORT.withName("len"),
            MemoryLayout.paddingLayout(6), // Align pointer to 8 bytes
            ValueLayout.ADDRESS.withName("filter"),
        )
    private val SOCK_FPROG_LEN_OFFSET: Long = SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("len"))
    private val SOCK_FPROG_FILTER_OFFSET: Long =
        SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("filter"))

    // Socket message layouts
    val IOVEC_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("iov_base"),
            ValueLayout.JAVA_LONG.withName("iov_len"),
        )

    val MSGHDR_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("msg_name"),
            ValueLayout.JAVA_INT.withName("msg_namelen"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("msg_iov"),
            ValueLayout.JAVA_LONG.withName("msg_iovlen"),
            ValueLayout.ADDRESS.withName("msg_control"),
            ValueLayout.JAVA_LONG.withName("msg_controllen"),
            ValueLayout.JAVA_INT.withName("msg_flags"),
            MemoryLayout.paddingLayout(4),
        )

    val CMSGHDR_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("cmsg_len"),
            ValueLayout.JAVA_INT.withName("cmsg_level"),
            ValueLayout.JAVA_INT.withName("cmsg_type"),
        )

    val SOCKADDR_UN_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_SHORT.withName("sun_family"),
            MemoryLayout.sequenceLayout(108, ValueLayout.JAVA_BYTE).withName("sun_path"),
        )

    // Seccomp User Notification Layouts
    val SECCOMP_DATA_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("nr"),
            ValueLayout.JAVA_INT.withName("arch"),
            ValueLayout.JAVA_LONG.withName("instruction_pointer"),
            MemoryLayout.sequenceLayout(6, ValueLayout.JAVA_LONG).withName("args"),
        )

    val SECCOMP_NOTIF_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("id"),
            ValueLayout.JAVA_INT.withName("pid"),
            ValueLayout.JAVA_INT.withName("flags"),
            SECCOMP_DATA_LAYOUT.withName("data"),
        )

    val SECCOMP_NOTIF_RESP_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("id"),
            ValueLayout.JAVA_LONG.withName("val"),
            ValueLayout.JAVA_INT.withName("error"),
            ValueLayout.JAVA_INT.withName("flags"),
        )

    val POLLFD_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("fd"),
            ValueLayout.JAVA_SHORT.withName("events"),
            ValueLayout.JAVA_SHORT.withName("revents"),
        )
    const val POLLIN: Short = 1

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
        // Correct syscall(2) downcall: fixed signature with 7 long arguments.
        // number + 6 args. This is more reliable for kernel calls than variadic FFM.
        SYSCALL =
            downcall(
                "syscall",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG, // nr
                    ValueLayout.JAVA_LONG, // a1
                    ValueLayout.JAVA_LONG, // a2
                    ValueLayout.JAVA_LONG, // a3
                    ValueLayout.JAVA_LONG, // a4
                    ValueLayout.JAVA_LONG, // a5
                    ValueLayout.JAVA_LONG, // a6
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

    data class SyscallResult(
        val returnValue: Long,
        val errno: Int,
    )

    private fun Any?.toLong(): Long =
        when (this) {
            is Number -> this.toLong()
            is MemorySegment -> this.address()
            null -> 0L
            else -> throw IllegalArgumentException("Unsupported native call argument type: ${this.javaClass.name}")
        }

    fun prctl(
        option: Int,
        arg2: Any? = 0L,
        arg3: Any? = 0L,
        arg4: Any? = 0L,
        arg5: Any? = 0L,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret =
                PRCTL.invokeExact(
                    capturedState,
                    option,
                    arg2.toLong(),
                    arg3.toLong(),
                    arg4.toLong(),
                    arg5.toLong(),
                ) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun syscall(
        nr: Long,
        a1: Any? = 0L,
        a2: Any? = 0L,
        a3: Any? = 0L,
        a4: Any? = 0L,
        a5: Any? = 0L,
        a6: Any? = 0L,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
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
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun syscall4(
        nr: Long,
        a1: Any?,
        a2: Any?,
        a3: Any?,
        a4: Any?,
    ): SyscallResult = syscall(nr, a1, a2, a3, a4)

    fun open(
        path: MemorySegment,
        flags: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = OPEN.invokeExact(capturedState, path, flags) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun close(fd: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = CLOSE.invokeExact(capturedState, fd) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun socketpair(
        domain: Int,
        type: Int,
        protocol: Int,
        sv: MemorySegment,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SOCKETPAIR.invokeExact(capturedState, domain, type, protocol, sv) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun socket(
        domain: Int,
        type: Int,
        protocol: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SOCKET.invokeExact(capturedState, domain, type, protocol) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun bind(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = BIND.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun listen(
        sockfd: Int,
        backlog: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = LISTEN.invokeExact(capturedState, sockfd, backlog) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun accept(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: MemorySegment,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = ACCEPT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun connect(
        sockfd: Int,
        addr: MemorySegment,
        addrlen: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = CONNECT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun sendmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SENDMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun recvmsg(
        sockfd: Int,
        msg: MemorySegment,
        flags: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = RECVMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun ioctl(
        fd: Int,
        request: Long,
        arg: MemorySegment,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = IOCTL_ADDR.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun ioctl(
        fd: Int,
        request: Long,
        arg: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = IOCTL_LONG.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun processVmReadv(
        pid: Int,
        localIov: MemorySegment,
        liovcnt: Long,
        remoteIov: MemorySegment,
        riovcnt: Long,
        flags: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret =
                PROCESS_VM_READV.invokeExact(capturedState, pid, localIov, liovcnt, remoteIov, riovcnt, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun readlink(
        path: MemorySegment,
        buf: MemorySegment,
        bufsiz: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = READLINK.invokeExact(capturedState, path, buf, bufsiz) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun read(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = READ.invokeExact(capturedState, fd, buf, count) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun write(
        fd: Int,
        buf: MemorySegment,
        count: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = WRITE.invokeExact(capturedState, fd, buf, count) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun recv(
        sockfd: Int,
        buf: MemorySegment,
        len: Long,
        flags: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = RECV.invokeExact(capturedState, sockfd, buf, len, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun fcntl(
        fd: Int,
        cmd: Int,
        arg: Long,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = FCNTL.invokeExact(capturedState, fd, cmd, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun gettid(): Int {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = GETTID.invokeExact(capturedState) as Int
            return ret
        }
    }

    fun poll(
        fds: MemorySegment,
        nfds: Long,
        timeout: Int,
    ): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = POLL.invokeExact(capturedState, fds, nfds, timeout) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun newSockFProg(
        arena: Arena,
        filters: Array<SockFilter>,
    ): MemorySegment {
        val filterArraySeg = arena.allocate(MemoryLayout.sequenceLayout(filters.size.toLong(), SOCK_FILTER_LAYOUT))
        for (i in filters.indices) {
            val f = filters[i]
            val offset = i * SOCK_FILTER_SIZE
            filterArraySeg.set(ValueLayout.JAVA_SHORT, offset, f.code)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 2, f.jt.toByte())
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 3, f.jf.toByte())
            filterArraySeg.set(ValueLayout.JAVA_INT, offset + 4, f.k)
        }
        val prog = arena.allocate(SOCK_FPROG_LAYOUT)
        prog.set(ValueLayout.JAVA_SHORT, SOCK_FPROG_LEN_OFFSET, filters.size.toShort())
        prog.set(ValueLayout.ADDRESS, SOCK_FPROG_FILTER_OFFSET, filterArraySeg)
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

    // Landlock Layouts
    val LANDLOCK_RULESET_ATTR_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("handled_access_fs"),
            ValueLayout.JAVA_LONG.withName("handled_access_net"),
        )
    val LANDLOCK_RULESET_ATTR_FS_OFFSET: Long =
        LANDLOCK_RULESET_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("handled_access_fs"))
    val LANDLOCK_RULESET_ATTR_NET_OFFSET: Long =
        LANDLOCK_RULESET_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("handled_access_net"))

    val LANDLOCK_PATH_BENEATH_ATTR_LAYOUT: StructLayout =
        MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withByteAlignment(1).withName("allowed_access"),
            ValueLayout.JAVA_INT.withByteAlignment(1).withName("parent_fd"),
            // unaligned values prevent Java from adding padding, matching kernel packed struct
        )
    val LANDLOCK_PATH_BENEATH_ATTR_ACCESS_OFFSET: Long =
        LANDLOCK_PATH_BENEATH_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("allowed_access"))
    val LANDLOCK_PATH_BENEATH_ATTR_FD_OFFSET: Long =
        LANDLOCK_PATH_BENEATH_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("parent_fd"))

    // Landlock system call numbers & constants
    const val LANDLOCK_CREATE_RULESET_NR = 444L
    const val LANDLOCK_ADD_RULE_NR = 445L
    const val LANDLOCK_RESTRICT_SELF_NR = 446L
    const val LANDLOCK_RULE_PATH_BENEATH = 1
    const val LANDLOCK_CREATE_RULESET_VERSION = (1L shl 0)

    const val PR_SET_NO_NEW_PRIVS = 38
    const val PR_SET_NAME = 15
    const val PR_GET_NAME = 16
    const val PR_SET_PTRACER = 0x59616d61
    const val SECCOMP_SET_MODE_FILTER = 1
    const val SECCOMP_FILTER_FLAG_NEW_LISTENER = (1L shl 3)
    const val SECCOMP_USER_NOTIF_FLAG_CONTINUE = (1L shl 0)

    // ioctl codes for seccomp notification
    // _IOW(0x21, 2, __u64) = 0x40082102 (size is 8 bytes = 0x08)
    const val SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100L
    const val SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101L
    const val SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102L

    const val EPERM = 1

    const val PR_SET_SECCOMP = 22
    const val PR_GET_SECCOMP = 21
    const val SECCOMP_MODE_FILTER = 2
    const val SECCOMP_FILTER_FLAG_TSYNC = 1

    const val SECCOMP_RET_ALLOW = 0x7fff0000
    const val SECCOMP_RET_ERRNO = 0x00050000
    const val SECCOMP_RET_USER_NOTIF = 0x7fc00000

    const val O_PATH = 0x01000000
    const val O_CLOEXEC = 0x00080000
    const val O_NOFOLLOW = 0x00020000
}
