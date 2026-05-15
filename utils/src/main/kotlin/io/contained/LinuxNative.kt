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
    private val STRERROR: MethodHandle
    private val SIGACTION: MethodHandle
    private val GETTID: MethodHandle
    private val IOCTL: MethodHandle
    private val PROCESS_VM_READV: MethodHandle
    private val POLL: MethodHandle

    val ERRNO_LAYOUT: StructLayout = Linker.Option.captureStateLayout()

    init {
        PRCTL = downcall("prctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG), Linker.Option.captureCallState("errno"))
        SYSCALL = downcall("syscall", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"), Linker.Option.firstVariadicArg(1))
        STRERROR = downcall("strerror", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
        SIGACTION = downcall("sigaction", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
        GETTID = downcall("gettid", FunctionDescriptor.of(ValueLayout.JAVA_INT))
        
        // int ioctl(int fd, unsigned long request, ...)
        IOCTL = downcall("ioctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS), Linker.Option.captureCallState("errno"), Linker.Option.firstVariadicArg(2))
        
        // ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
        PROCESS_VM_READV = downcall("process_vm_readv", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG))
        
        // int poll(struct pollfd *fds, nfds_t nfds, int timeout);
        POLL = downcall("poll", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT))
    }

    private fun downcall(name: String, desc: FunctionDescriptor, vararg options: Linker.Option): MethodHandle {
        val symbol = stdlib.find(name).orElse(null) ?: return MethodHandles.insertArguments(
            MethodHandles.throwException(desc.returnLayout().get().javaWithFallback(), UnsupportedOperationException::class.java),
            0, UnsupportedOperationException("Symbol $name not found in libc")
        )
        return linker.downcallHandle(symbol, desc, *options)
    }

    private fun MemoryLayout.javaWithFallback(): Class<*> = when (this) {
        is ValueLayout.OfInt -> Int::class.javaPrimitiveType!!
        is ValueLayout.OfLong -> Long::class.javaPrimitiveType!!
        else -> MemorySegment::class.java
    }

    fun strerror(errno: Int): String {
        return try {
            val ptr = STRERROR.invokeExact(errno) as MemorySegment
            ptr.reinterpret(1024).getString(0)
        } catch (e: Throwable) {
            "Unknown error $errno"
        }
    }

    fun gettid(): Int {
        return try {
            GETTID.invokeExact() as Int
        } catch (e: Throwable) {
            val SYS_gettid = if (Arch.current() == Arch.AMD64) 186L else 178L
            syscall(SYS_gettid, 0, 0, MemorySegment.NULL).returnValue.toInt()
        }
    }

    fun ioctl(fd: Int, request: Long, arg: MemorySegment): Int {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            return try {
                val ret = IOCTL.invokeExact(capturedState, fd, request, arg) as Int
                if (ret != 0) {
                    val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno")))
                    return -errno
                }
                ret
            } catch (e: Throwable) {
                -999
            }
        }
    }

    fun process_vm_readv(pid: Int, localIov: MemorySegment, liovcnt: Long, remoteIov: MemorySegment, riovcnt: Long, flags: Long): Long {
        return try {
            PROCESS_VM_READV.invokeExact(pid, localIov, liovcnt, remoteIov, riovcnt, flags) as Long
        } catch (e: Throwable) {
            -1L
        }
    }

    fun poll(fds: MemorySegment, nfds: Long, timeout: Int): Int {
        return try {
            POLL.invokeExact(fds, nfds, timeout) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun sigaction(signum: Int, act: MemorySegment, oldact: MemorySegment): Int {
        return try {
            SIGACTION.invokeExact(signum, act, oldact) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun prctl(option: Int, arg2: Long, arg3: Long, arg4: Long, arg5: Long): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = PRCTL.invokeExact(capturedState, option, arg2, arg3, arg4, arg5) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno")))
            return SyscallResult(ret.toLong(), errno)
        }
    }

    fun prctl(option: Int, arg2: Long, arg3ptr: MemorySegment, arg4: Long, arg5: Long): SyscallResult =
        prctl(option, arg2, arg3ptr.address(), arg4, arg5)

    fun syscall(number: Long, arg1: Long, arg2: Long, arg3: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SYSCALL.invokeExact(capturedState, number, arg1, arg2, arg3) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno")))
            return SyscallResult(ret, errno)
        }
    }

    val SOCK_FPROG_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("len"),
        MemoryLayout.paddingLayout(6), // Align pointer to 8 bytes
        ValueLayout.ADDRESS.withName("filter")
    )

    fun newSockFProg(arena: Arena, filters: Array<SockFilter>): MemorySegment {
        val filterArraySeg = arena.allocate(MemoryLayout.sequenceLayout(filters.size.toLong(), SOCK_FILTER_LAYOUT))
        val filterSize = SOCK_FILTER_LAYOUT.byteSize()
        for (i in filters.indices) {
            val f = filters[i]
            val offset = i * filterSize
            filterArraySeg.set(ValueLayout.JAVA_SHORT, offset, f.code)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 2, (f.jt.toInt() and 0xFF).toByte())
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 3, (f.jf.toInt() and 0xFF).toByte())
            filterArraySeg.set(ValueLayout.JAVA_INT, offset + 4, f.k)
        }
        
        val progSeg = arena.allocate(SOCK_FPROG_LAYOUT)
        progSeg.set(ValueLayout.JAVA_SHORT, SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("len")), filters.size.toShort())
        progSeg.set(ValueLayout.ADDRESS, SOCK_FPROG_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("filter")), filterArraySeg)
        return progSeg
    }

    data class SyscallResult(val returnValue: Long, val errno: Int)

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
    const val SECCOMP_FILTER_FLAG_NEW_LISTENER = 8

    const val SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100L
    const val SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101L
    const val SECCOMP_USER_NOTIF_FLAG_CONTINUE = 0x00000001
    const val EPERM = 1
    const val SIGSYS = 31
    const val SA_SIGINFO = 4
    const val POLLIN = 0x0001.toShort()
    const val POLLERR = 0x0008.toShort()
    const val POLLHUP = 0x0010.toShort()
    const val POLLNVAL = 0x0020.toShort()

    val SIGACTION_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.ADDRESS.withName("sa_handler"), MemoryLayout.sequenceLayout(16, ValueLayout.JAVA_LONG).withName("sa_mask"), ValueLayout.JAVA_INT.withName("sa_flags"), MemoryLayout.paddingLayout(4), ValueLayout.ADDRESS.withName("sa_restorer"))
    val SIGINFO_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.JAVA_INT.withName("si_signo"), ValueLayout.JAVA_INT.withName("si_errno"), ValueLayout.JAVA_INT.withName("si_code"), MemoryLayout.paddingLayout(4), ValueLayout.ADDRESS.withName("si_call_addr"), ValueLayout.JAVA_INT.withName("si_syscall"), ValueLayout.JAVA_INT.withName("si_arch"), MemoryLayout.paddingLayout(96))
    val SECCOMP_NOTIF_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.JAVA_LONG.withName("id"), ValueLayout.JAVA_INT.withName("pid"), ValueLayout.JAVA_INT.withName("flags"), ValueLayout.JAVA_INT.withName("nr"), ValueLayout.JAVA_INT.withName("arch"), ValueLayout.JAVA_LONG.withName("instruction_pointer"), MemoryLayout.sequenceLayout(6, ValueLayout.JAVA_LONG).withName("args"))
    val SECCOMP_NOTIF_RESP_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.JAVA_LONG.withName("id"), ValueLayout.JAVA_LONG.withName("val"), ValueLayout.JAVA_INT.withName("error"), ValueLayout.JAVA_INT.withName("flags"))
    val IOVEC_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.ADDRESS.withName("iov_base"), ValueLayout.JAVA_LONG.withName("iov_len"))
    val POLLFD_LAYOUT: StructLayout = MemoryLayout.structLayout(ValueLayout.JAVA_INT.withName("fd"), ValueLayout.JAVA_SHORT.withName("events"), ValueLayout.JAVA_SHORT.withName("revents"))

    val SOCK_FILTER_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("code"),
        ValueLayout.JAVA_BYTE.withName("jt"),
        ValueLayout.JAVA_BYTE.withName("jf"),
        ValueLayout.JAVA_INT.withName("k")
    )
    val SOCK_FPROG_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("len"),
        MemoryLayout.paddingLayout(ValueLayout.ADDRESS.byteSize() - 2),
        ValueLayout.ADDRESS.withName("filter")
    )
}
