package io.contained

import java.util.logging.Logger

/**
 * Platform checks and fallback configuration.
 */
object Platform {
    private val logger = Logger.getLogger(Platform::class.java.name)

    /**
     * Enum defining how the library behaves when run on an unsupported platform (e.g. macOS or Windows).
     */
    enum class FallbackBehavior {
        FAIL,            // throw UnsupportedOperationException
        WARN_AND_BYPASS, // log warning, run task uncontained
        SILENT_BYPASS    // run task uncontained, no warning
    }

    /**
     * Returns true if the current platform supports seccomp filters.
     */
    fun isSupported(): Boolean {
        if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return false

        // Check if the kernel actually supports seccomp
        // PR_GET_SECCOMP returns < 0 (and sets errno to EINVAL) if seccomp is not configured in the kernel
        if (LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0).returnValue < 0) {
            return false
        }

        // Bogus Sanity Check: Ensure the kernel actively enforces seccomp.
        // We call prctl(PR_SET_SECCOMP) with an invalid mode (-1).
        // A healthy kernel should return -1 and set errno to EINVAL (22).
        // Some container environments or broken kernels might silently return 0 or a different error.
        val bogusCheck = LinuxNative.prctl(LinuxNative.PR_SET_SECCOMP, -1L, 0L, 0, 0)
        if (bogusCheck.returnValue == 0L || bogusCheck.errno != 22) { // 22 is EINVAL (Invalid argument)
             logger.warning("Seccomp sanity check failed. The kernel returned unexpected results (ret=${bogusCheck.returnValue}, errno=${bogusCheck.errno}). Seccomp may be stubbed or broken in this environment.")
             return false
        }

        return try {
            Arch.current()
            true
        } catch (e: UnsupportedOperationException) {
            false
        }
    }

    /**
     * Resolves the configured fallback behavior based on system properties or environment variables.
     */
    fun configuredFallback(): FallbackBehavior {
        val prop = System.getProperty("io.contained.fallback") 
            ?: System.getenv("IO_CONTAINED_FALLBACK")
            
        if (prop != null) {
            try {
                return FallbackBehavior.valueOf(prop.uppercase())
            } catch (e: IllegalArgumentException) {
                logger.warning("Invalid fallback behavior '$prop', defaulting to FAIL")
            }
        }
        return FallbackBehavior.FAIL
    }
}
