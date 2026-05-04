package io.contained

import java.lang.foreign.*
import java.lang.invoke.MethodHandle

// Corresponds to struct sock_filter
data class SockFilter(val code: Short, val jt: Byte, val jf: Byte, val k: Int)

object LinuxNative {
    private val linker = Linker.nativeLinker()
    private val stdlib = linker.defaultLookup()

    private val PRCTL: MethodHandle
    private val SYSCALL: MethodHandle
    private val STRERROR: MethodHandle

    val ERRNO_LAYOUT: StructLayout = Linker.Option.captureStateLayout()

    init {
        // prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
        PRCTL = linker.downcallHandle(
            stdlib.find("prctl").get(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG),
            Linker.Option.captureCallState("errno")
        )

        // syscall(long number, ...)
        SYSCALL = linker.downcallHandle(
            stdlib.find("syscall").get(),
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS),
            Linker.Option.captureCallState("errno"),
            Linker.Option.firstVariadicArg(1)
        )

        // char *strerror(int errnum);
        STRERROR = linker.downcallHandle(
            stdlib.find("strerror").get(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
        )
    }

    fun strerror(errno: Int): String {
        return try {
            val ptr = STRERROR.invokeExact(errno) as MemorySegment
            ptr.reinterpret(1024).getString(0)
        } catch (e: Throwable) {
            "Unknown error $errno"
        }
    }

    // Allocate a sock_fprog struct pointing to an array of SockFilters
    fun newSockFProg(arena: Arena, filters: Array<SockFilter>): MemorySegment {
        val filterLayout = MemoryLayout.structLayout(
            ValueLayout.JAVA_SHORT.withName("code"),
            ValueLayout.JAVA_BYTE.withName("jt"),
            ValueLayout.JAVA_BYTE.withName("jf"),
            ValueLayout.JAVA_INT.withName("k")
        )

        val filterArrayLayout = MemoryLayout.sequenceLayout(filters.size.toLong(), filterLayout)
        val filterArraySeg = arena.allocate(filterArrayLayout)

        for (i in filters.indices) {
            val f = filters[i]
            val offset = i * 8L
            filterArraySeg.set(ValueLayout.JAVA_SHORT, offset, f.code)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 2, f.jt)
            filterArraySeg.set(ValueLayout.JAVA_BYTE, offset + 3, f.jf)
            filterArraySeg.set(ValueLayout.JAVA_INT, offset + 4, f.k)
        }

        // struct sock_fprog {
        //     unsigned short len;
        //     struct sock_filter *filter;
        // }; // 16 bytes (due to alignment padding)
        val progLayout = MemoryLayout.structLayout(
            ValueLayout.JAVA_SHORT.withName("len"),
            MemoryLayout.paddingLayout(6),
            ValueLayout.ADDRESS.withName("filter")
        )

        val progSeg = arena.allocate(progLayout)
        progSeg.set(ValueLayout.JAVA_SHORT, 0, filters.size.toShort())
        progSeg.set(ValueLayout.ADDRESS, 8, filterArraySeg)

        return progSeg
    }

    data class SyscallResult(val returnValue: Int, val errno: Int)

    fun prctl(option: Int, arg2: Long, arg3: Long, arg4: Long, arg5: Long): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = PRCTL.invokeExact(capturedState, option, arg2, arg3, arg4, arg5) as Int
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno")))
            return SyscallResult(ret, errno)
        }
    }

    /** Convenience overload for passing a pointer (MemorySegment) as arg3. */
    fun prctl(option: Int, arg2: Long, arg3ptr: MemorySegment, arg4: Long, arg5: Long): SyscallResult =
        prctl(option, arg2, arg3ptr.address(), arg4, arg5)

    fun syscall(number: Long, arg1: Long, arg2: Long, arg3: MemorySegment): SyscallResult {
        Arena.ofConfined().use { arena ->
            val capturedState = arena.allocate(ERRNO_LAYOUT)
            val ret = SYSCALL.invokeExact(capturedState, number, arg1, arg2, arg3) as Long
            val errno = capturedState.get(ValueLayout.JAVA_INT, ERRNO_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno")))
            return SyscallResult(ret.toInt(), errno)
        }
    }

    const val PR_SET_NO_NEW_PRIVS = 38
    const val PR_GET_NO_NEW_PRIVS = 39
    const val PR_SET_SECCOMP = 22
    const val PR_GET_SECCOMP = 21
    const val SECCOMP_MODE_FILTER = 2

    const val SECCOMP_RET_ERRNO = 0x00050000
    const val SECCOMP_RET_ALLOW = 0x7fff0000
    const val SECCOMP_RET_KILL_THREAD = 0x00000000

    const val SECCOMP_SET_MODE_FILTER = 1
    const val SECCOMP_FILTER_FLAG_TSYNC = 1

    const val EPERM = 1
}
