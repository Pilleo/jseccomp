package io.contained

import java.lang.foreign.*
import java.lang.invoke.MethodHandle
import java.lang.invoke.MethodHandles

// Corresponds to struct sock_filter
data class SockFilter(val code: Short, val jt: Short, val jf: Short, val k: Int) {
    init {
        require(jt in 0..255) { "jt offset must be an unsigned 8-bit value (0-255), got $jt" }
        require(jf in 0..255) { "jf offset must be an unsigned 8-bit value (0-255), got $jf" }
    }
}

object LinuxNative {
    private val linker = Linker.nativeLinker()
    private val stdlib = linker.defaultLookup()

    private val PRCTL: MethodHandle
    private val SYSCALL: MethodHandle
    private val SYSCALL4: MethodHandle
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

    val ERRNO_LAYOUT: StructLayout = Linker.Option.captureStateLayout()
    private val ERRNO_OFFSET = ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno"))

    val SOCK_FILTER_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("code"),
        ValueLayout.JAVA_BYTE.withName("jt"),
        ValueLayout.JAVA_BYTE.withName("jf"),
        ValueLayout.JAVA_INT.withName("k")
    )
    private val SOCK_FILTER_SIZE = SOCK_FILTER_LAYOUT.byteSize()

    val SOCK_FPROG_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("len"),
        MemoryLayout.paddingLayout(6), // Align pointer to 8 bytes
        ValueLayout.ADDRESS.withName("filter")
    )
    private val SOCK_FPROG_LEN_OFFSET = SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("len"))
    private val SOCK_FPROG_FILTER_OFFSET = SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("filter"))

    // Socket message layouts
    val IOVEC_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.ADDRESS.withName("iov_base"),
        ValueLayout.JAVA_LONG.withName("iov_len")
    )

    val MSGHDR_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.ADDRESS.withName("msg_name"),
        ValueLayout.JAVA_INT.withName("msg_namelen"),
        MemoryLayout.paddingLayout(4),
        ValueLayout.ADDRESS.withName("msg_iov"),
        ValueLayout.JAVA_LONG.withName("msg_iovlen"),
        ValueLayout.ADDRESS.withName("msg_control"),
        ValueLayout.JAVA_LONG.withName("msg_controllen"),
        ValueLayout.JAVA_INT.withName("msg_flags"),
        MemoryLayout.paddingLayout(4)
    )

    val CMSGHDR_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("cmsg_len"),
        ValueLayout.JAVA_INT.withName("cmsg_level"),
        ValueLayout.JAVA_INT.withName("cmsg_type")
    )

    val SOCKADDR_UN_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("sun_family"),
        MemoryLayout.sequenceLayout(108, ValueLayout.JAVA_BYTE).withName("sun_path")
    )

    // Seccomp User Notification Layouts
    val SECCOMP_DATA_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_INT.withName("nr"),
        ValueLayout.JAVA_INT.withName("arch"),
        ValueLayout.JAVA_LONG.withName("instruction_pointer"),
        MemoryLayout.sequenceLayout(6, ValueLayout.JAVA_LONG).withName("args")
    )

    val SECCOMP_NOTIF_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("id"),
        ValueLayout.JAVA_INT.withName("pid"),
        ValueLayout.JAVA_INT.withName("flags"),
        SECCOMP_DATA_LAYOUT.withName("data")
    )

    val SECCOMP_NOTIF_RESP_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("id"),
        ValueLayout.JAVA_LONG.withName("val"),
        ValueLayout.JAVA_INT.withName("error"),
        ValueLayout.JAVA_INT.withName("flags")
    )

    init {
        PRCTL = downcall("prctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG), Linker.Option.captureCallState("errno"))
        SYSCALL = downcall("syscall", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"), Linker.Option.firstVariadicArg(1))
        SYSCALL4 = downcall("syscall", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"), Linker.Option.firstVariadicArg(1))
        OPEN = downcall("open", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        CLOSE = downcall("close", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        SOCKETPAIR = downcall("socketpair", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"))
        SOCKET = downcall("socket", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        BIND = downcall("bind", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        LISTEN = downcall("listen", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        ACCEPT = downcall("accept", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"))
        CONNECT = downcall("connect", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        SENDMSG = downcall("sendmsg", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        RECVMSG = downcall("recvmsg", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), Linker.Option.captureCallState("errno"))
        IOCTL_ADDR = downcall("ioctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"))
        IOCTL_LONG = downcall("ioctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG), Linker.Option.captureCallState("errno"))
        PROCESS_VM_READV = downcall("process_vm_readv", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG), Linker.Option.captureCallState("errno"))
    }

    private fun downcall(name: String, desc: FunctionDescriptor, vararg options: Linker.Option): MethodHandle {
        val symbol = stdlib.find(name).orElse(null) ?: run {
            val ex = UnsupportedOperationException("Symbol $name not found in libc")
            val throwingHandle = MethodHandles.insertArguments(
                MethodHandles.throwException(desc.returnLayout().get().javaWithFallback(), UnsupportedOperationException::class.java),
                0, ex
            )
            val argTypes = desc.argumentLayouts().map { it.javaWithFallback() }.toTypedArray()
            return MethodHandles.dropArguments(throwingHandle, 0, *argTypes)
        }
        return linker.downcallHandle(symbol, desc, *options)
    }

    private fun MemoryLayout.javaWithFallback(): Class<*> = when (this) {
        is ValueLayout.OfInt -> Int::class.javaPrimitiveType!!
        is ValueLayout.OfLong -> Long::class.javaPrimitiveType!!
        else -> MemorySegment::class.java
    }

    fun prctl(option: Int, arg2: Long, arg3: Long, arg4: Long, arg5: Long): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = PRCTL.invokeExact(capturedState, option, arg2, arg3, arg4, arg5) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun prctl(option: Int, arg2: Long, arg3ptr: MemorySegment, arg4: Long, arg5: Long): SyscallResult =
        prctl(option, arg2, arg3ptr.address(), arg4, arg5)

    fun syscall(number: Long, arg1: Long, arg2: Long, arg3: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SYSCALL.invokeExact(capturedState, number, arg1, arg2, arg3) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun syscall(number: Long, arg1: Long, arg2: Long, arg3: MemorySegment, arg4: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SYSCALL4.invokeExact(capturedState, number, arg1, arg2, arg3, arg4) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun open(path: MemorySegment, flags: Int): SyscallResult {
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

    fun socketpair(domain: Int, type: Int, protocol: Int, sv: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SOCKETPAIR.invokeExact(capturedState, domain, type, protocol, sv) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun socket(domain: Int, type: Int, protocol: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SOCKET.invokeExact(capturedState, domain, type, protocol) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun bind(sockfd: Int, addr: MemorySegment, addrlen: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = BIND.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun listen(sockfd: Int, backlog: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = LISTEN.invokeExact(capturedState, sockfd, backlog) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun accept(sockfd: Int, addr: MemorySegment, addrlen: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = ACCEPT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun connect(sockfd: Int, addr: MemorySegment, addrlen: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = CONNECT.invokeExact(capturedState, sockfd, addr, addrlen) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun sendmsg(sockfd: Int, msg: MemorySegment, flags: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SENDMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun recvmsg(sockfd: Int, msg: MemorySegment, flags: Int): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = RECVMSG.invokeExact(capturedState, sockfd, msg, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun ioctl(fd: Int, request: Long, arg: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = IOCTL_ADDR.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun ioctl(fd: Int, request: Long, arg: Long): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = IOCTL_LONG.invokeExact(capturedState, fd, request, arg) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun processVmReadv(pid: Int, localIov: MemorySegment, liovcnt: Long, remoteIov: MemorySegment, riovcnt: Long, flags: Long): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = PROCESS_VM_READV.invokeExact(capturedState, pid, localIov, liovcnt, remoteIov, riovcnt, flags) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_OFFSET)
            return SyscallResult(ret, errno)
        }
    }

    fun newSockFProg(arena: Arena, filters: Array<SockFilter>): MemorySegment {
        val filterArraySeg = arena.allocate(MemoryLayout.sequenceLayout(filters.size.toLong(), SOCK_FILTER_LAYOUT))
        for (i in filters.indices) {
            val f = filters[i]
            val offset = i * SOCK_FILTER_SIZE
            filterArraySeg.set(ValueLayout.JAVA_SHORT, offset, f.code)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 2, (f.jt.toInt() and 0xFF).toByte())
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 3, (f.jf.toInt() and 0xFF).toByte())
            filterArraySeg.set(ValueLayout.JAVA_INT, offset + 4, f.k)
        }
        
        val progSeg = arena.allocate(SOCK_FPROG_LAYOUT)
        progSeg.set(ValueLayout.JAVA_SHORT, SOCK_FPROG_LEN_OFFSET, filters.size.toShort())
        progSeg.set(ValueLayout.ADDRESS, SOCK_FPROG_FILTER_OFFSET, filterArraySeg)
        return progSeg
    }

    data class SyscallResult(val returnValue: Long, val errno: Int)

    // Landlock Layouts
    val LANDLOCK_RULESET_ATTR_LAYOUT = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("handled_access_fs"),
        ValueLayout.JAVA_LONG.withName("handled_access_net")
    )
    val LANDLOCK_RULESET_ATTR_FS_OFFSET = LANDLOCK_RULESET_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("handled_access_fs"))
    val LANDLOCK_RULESET_ATTR_NET_OFFSET = LANDLOCK_RULESET_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("handled_access_net"))

    val LANDLOCK_PATH_BENEATH_ATTR_LAYOUT = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withByteAlignment(1).withName("allowed_access"),
        ValueLayout.JAVA_INT.withByteAlignment(1).withName("parent_fd")
        // unaligned values prevent Java from adding padding, matching kernel packed struct
    )
    val LANDLOCK_PATH_BENEATH_ATTR_ACCESS_OFFSET = LANDLOCK_PATH_BENEATH_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("allowed_access"))
    val LANDLOCK_PATH_BENEATH_ATTR_FD_OFFSET = LANDLOCK_PATH_BENEATH_ATTR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("parent_fd"))

    const val LANDLOCK_CREATE_RULESET_NR = 444L
    const val LANDLOCK_ADD_RULE_NR = 445L
    const val LANDLOCK_RESTRICT_SELF_NR = 446L

    const val LANDLOCK_CREATE_RULESET_VERSION = 1L
    const val LANDLOCK_RULE_PATH_BENEATH = 1

    const val O_PATH = 2097152
    const val O_CLOEXEC = 524288
    const val O_NOFOLLOW = 131072

    const val PR_SET_NO_NEW_PRIVS = 38
    const val PR_GET_NO_NEW_PRIVS = 39
    const val PR_SET_SECCOMP = 22
    const val PR_GET_SECCOMP = 21
    const val SECCOMP_MODE_FILTER = 2
    const val SECCOMP_RET_ERRNO = 0x00050000
    const val SECCOMP_RET_ALLOW = 0x7fff0000
    const val SECCOMP_RET_KILL_THREAD = 0x00000000
    const val SECCOMP_RET_TRAP = 0x00030000
    const val SECCOMP_RET_USER_NOTIF = 0x7fc00000
    const val SECCOMP_SET_MODE_FILTER = 1
    const val SECCOMP_FILTER_FLAG_TSYNC = 1

    // Seccomp User Notification Constants
    const val SECCOMP_FILTER_FLAG_NEW_LISTENER = 8
    const val SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

    // Ioctl macros
    // SECCOMP_IOCTL_NOTIF_RECV = _IOWR('!', 0, struct seccomp_notif) = 0xc0502100 (size is 80 bytes = 0x50)
    // SECCOMP_IOCTL_NOTIF_SEND = _IOWR('!', 1, struct seccomp_notif_resp) = 0xc0182101 (size is 24 bytes = 0x18)
    // SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW('!', 2, __u64) = 0x40082102 (size is 8 bytes = 0x08)
    const val SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100L
    const val SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101L
    const val SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102L

    const val EPERM = 1
}
