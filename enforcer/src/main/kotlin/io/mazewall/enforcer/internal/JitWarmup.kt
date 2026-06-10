package io.mazewall.enforcer.internal

import io.mazewall.core.Arch
import io.mazewall.enforcer.ContainmentViolationDetector

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
    }
}
