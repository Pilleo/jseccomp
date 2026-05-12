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
