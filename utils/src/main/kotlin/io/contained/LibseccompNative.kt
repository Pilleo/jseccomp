package io.contained

import java.lang.foreign.*
import java.lang.invoke.MethodHandle

/**
 * FFM bindings for the system libseccomp library.
 */
object LibseccompNative {
    private val linker = Linker.nativeLinker()
    
    // We try to load libseccomp.so.2 (standard on most modern Linux)
    private val lib = try {
        SymbolLookup.libraryLookup("libseccomp.so.2", Arena.global())
    } catch (e: Exception) {
        null
    }

    val isAvailable: Boolean = lib != null && Platform.isSupported()

    private val SECOMP_INIT: MethodHandle? = bind("seccomp_init", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
    private val SECOMP_RELEASE: MethodHandle? = bind("seccomp_release", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
    private val SECOMP_RULE_ADD: MethodHandle? = bind("seccomp_rule_add", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), Linker.Option.firstVariadicArg(4))
    private val SECOMP_RULE_ADD_ARRAY: MethodHandle? = bind("seccomp_rule_add_array", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_LOAD: MethodHandle? = bind("seccomp_load", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_SYSCALL_RESOLVE_NAME: MethodHandle? = bind("seccomp_syscall_resolve_name", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_SYSCALL_RESOLVE_NUM_ARCH: MethodHandle? = bind("seccomp_syscall_resolve_num_arch", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT))
    private val SECOMP_NOTIFY_ALLOC: MethodHandle? = bind("seccomp_notify_alloc", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
    private val SECOMP_NOTIFY_FREE: MethodHandle? = bind("seccomp_notify_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS))
    private val SECOMP_NOTIFY_RECEIVE: MethodHandle? = bind("seccomp_notify_receive", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_NOTIFY_RESPOND: MethodHandle? = bind("seccomp_notify_respond", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_NOTIFY_FD: MethodHandle? = bind("seccomp_notify_fd", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
    private val SECOMP_ARCH_NATIVE: MethodHandle? = bind("seccomp_arch_native", FunctionDescriptor.of(ValueLayout.JAVA_INT))

    private fun bind(name: String, desc: FunctionDescriptor, vararg options: Linker.Option): MethodHandle? {
        return lib?.find(name)?.map { linker.downcallHandle(it, desc, *options) }?.orElse(null)
    }

    fun init(defaultAction: Int): MemorySegment? {
        return try {
            SECOMP_INIT?.invokeExact(defaultAction) as? MemorySegment
        } catch (e: Throwable) {
            null
        }
    }

    fun release(ctx: MemorySegment) {
        try {
            SECOMP_RELEASE?.invokeExact(ctx)
        } catch (e: Throwable) {
            // Log or ignore
        }
    }

    /** Simple rule add (no arguments) */
    fun ruleAdd(ctx: MemorySegment, action: Int, syscall: Int): Int {
        return try {
            SECOMP_RULE_ADD?.invoke(ctx, action, syscall, 0) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    /** Rule add with argument comparators */
    fun ruleAddArray(ctx: MemorySegment, action: Int, syscall: Int, argCnt: Int, argArray: MemorySegment): Int {
        return try {
            SECOMP_RULE_ADD_ARRAY?.invokeExact(ctx, action, syscall, argCnt, argArray) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun load(ctx: MemorySegment): Int {
        return try {
            SECOMP_LOAD?.invokeExact(ctx) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun resolveName(name: String, arena: Arena): Int {
        return try {
            val cName = arena.allocateFrom(name)
            SECOMP_SYSCALL_RESOLVE_NAME?.invokeExact(cName) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun resolveNumArch(archToken: Int, num: Int): String? {
        return try {
            val ptr = SECOMP_SYSCALL_RESOLVE_NUM_ARCH?.invokeExact(archToken, num) as? MemorySegment
            if (ptr == null || ptr == MemorySegment.NULL) return null
            ptr.reinterpret(1024).getString(0)
        } catch (e: Throwable) {
            null
        }
    }

    fun notifyAlloc(arena: Arena): Pair<MemorySegment, MemorySegment>? {
        return try {
            val reqPtrPtr = arena.allocate(ValueLayout.ADDRESS)
            val respPtrPtr = arena.allocate(ValueLayout.ADDRESS)
            val ret = SECOMP_NOTIFY_ALLOC?.invokeExact(reqPtrPtr, respPtrPtr) as Int
            if (ret != 0) return null
            val reqPtr = reqPtrPtr.get(ValueLayout.ADDRESS, 0).reinterpret(1024) // Simplified size
            val respPtr = respPtrPtr.get(ValueLayout.ADDRESS, 0).reinterpret(1024)
            Pair(reqPtr, respPtr)
        } catch (e: Throwable) {
            null
        }
    }

    fun notifyFree(req: MemorySegment, resp: MemorySegment) {
        try {
            SECOMP_NOTIFY_FREE?.invokeExact(req, resp)
        } catch (e: Throwable) {}
    }

    fun notifyReceive(fd: Int, req: MemorySegment): Int {
        return try {
            SECOMP_NOTIFY_RECEIVE?.invokeExact(fd, req) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun notifyRespond(fd: Int, resp: MemorySegment): Int {
        return try {
            SECOMP_NOTIFY_RESPOND?.invokeExact(fd, resp) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun notifyFd(ctx: MemorySegment): Int {
        return try {
            SECOMP_NOTIFY_FD?.invokeExact(ctx) as Int
        } catch (e: Throwable) {
            -1
        }
    }

    fun archNative(): Int {
        return try {
            SECOMP_ARCH_NATIVE?.invokeExact() as Int
        } catch (e: Throwable) {
            0
        }
    }

    // struct scmp_arg_cmp { unsigned int arg; enum scmp_compare op; uint64_t datum_a; uint64_t datum_b; }
    val SCMP_ARG_CMP_LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_INT.withName("arg"),
        ValueLayout.JAVA_INT.withName("op"),
        ValueLayout.JAVA_LONG.withName("datum_a"),
        ValueLayout.JAVA_LONG.withName("datum_b")
    )

    const val SCMP_ACT_KILL_THREAD = 0x00000000
    const val SCMP_ACT_TRAP = 0x00030000
    const val SCMP_ACT_NOTIFY = 0x7fc00000
    const val SCMP_ACT_ALLOW = 0x7fff0000

    fun SCMP_ACT_ERRNO(errno: Int): Int = 0x00050000 or (errno and 0x0000ffff)

    const val SCMP_CMP_NE = 1
    const val SCMP_CMP_LT = 2
    const val SCMP_CMP_LE = 3
    const val SCMP_CMP_EQ = 4
    const val SCMP_CMP_GE = 5
    const val SCMP_CMP_GT = 6
    const val SCMP_CMP_MASKED_EQ = 7
}
