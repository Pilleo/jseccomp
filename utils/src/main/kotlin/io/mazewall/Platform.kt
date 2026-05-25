package io.mazewall

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
        FAIL, // throw UnsupportedOperationException
        WARN_AND_BYPASS, // log warning, run task uncontained
        SILENT_BYPASS, // run task uncontained, no warning
    }

    private const val ERRNO_EINVAL = 22

    /**
     * Returns true if the current platform supports seccomp filters.
     */
    fun isSupported(): Boolean =
        System.getProperty("os.name").equals("Linux", ignoreCase = true) &&
            hasKernelSeccompSupport() &&
            isSeccompSanityCheckPassing() &&
            isArchitectureSupported()

    private fun hasKernelSeccompSupport(): Boolean = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0).returnValue >= 0

    private fun isSeccompSanityCheckPassing(): Boolean {
        // Bogus Sanity Check: Ensure the kernel actively enforces seccomp.
        // We call prctl(PR_SET_SECCOMP) with an invalid mode (-1).
        // A healthy kernel should return -1 and set errno to EINVAL (22).
        // Some container environments or broken kernels might silently return 0 or a different error.
        val bogusCheck = LinuxNative.prctl(LinuxNative.PR_SET_SECCOMP, -1L, 0L, 0, 0)
        val passed = bogusCheck.returnValue != 0L && bogusCheck.errno == ERRNO_EINVAL
        if (!passed) {
            logger.warning(
                "Seccomp sanity check failed. The kernel returned unexpected results (ret=${bogusCheck.returnValue}, errno=${bogusCheck.errno}). Seccomp may be stubbed or broken in this environment.",
            )
        }
        return passed
    }

    internal fun isArchitectureSupported(): Boolean =
        try {
            Arch.current()
            true
        } catch (e: UnsupportedOperationException) {
            logger.warning("Architecture not supported: ${e.message}")
            false
        }

    /**
     * Resolves the configured fallback behavior based on system properties or environment variables.
     */
    fun configuredFallback(): FallbackBehavior {
        val prop =
            System.getProperty("io.mazewall.fallback")
                ?: System.getenv("IO_MAZEWALL_FALLBACK")

        if (prop != null) {
            try {
                return FallbackBehavior.valueOf(prop.uppercase())
            } catch (e: IllegalArgumentException) {
                logger.warning("Invalid fallback behavior '$prop' (${e.message}), defaulting to FAIL")
            }
        }
        return FallbackBehavior.FAIL
    }
}
