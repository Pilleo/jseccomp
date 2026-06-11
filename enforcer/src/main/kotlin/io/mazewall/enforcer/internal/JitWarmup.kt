package io.mazewall.enforcer.internal

import io.mazewall.LinuxNative
import io.mazewall.core.Arch
import io.mazewall.enforcer.ContainmentViolationDetector
import java.lang.foreign.Arena

/**
 * Force JVM classloading and JIT compilation of core sandboxing components
 * before containment is applied to prevent the "lazy initialization trap".
 */
internal object JitWarmup {
    private var warmedUp = false

    @Synchronized
    fun perform() {
        if (warmedUp) return
        warmedUp = true

        // Force JVM classloading and JIT compilation
        ContainmentViolationDetector.isContainmentViolation(Throwable(""))
        try {
            Arch.current()
        } catch (ignored: Exception) {
            // Ignore unsupported architecture; will be handled by platform check
        }

        // Warm up Native Engine downcall stubs to prevent lazy Linking/JIT EPERM crashes inside sandboxed threads
        try {
            LinuxNative.gettid()
            LinuxNative.prctl(0, 0, 0, 0, 0)
            LinuxNative.syscall(-1L, 0, 0, 0, 0, 0, 0)
            Arena.ofConfined().use { arena ->
                LinuxNative.getMemory().newSockFProg(arena, emptyArray())
            }
        } catch (ignored: Exception) {
            // Ignore any failures during warmup
        }
    }
}
