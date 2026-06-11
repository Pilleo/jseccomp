package io.mazewall

import io.mazewall.core.Arch
import io.mazewall.ffi.NativeConstants
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

    private fun hasKernelSeccompSupport(): Boolean = LinuxNative.prctl(NativeConstants.PR_GET_SECCOMP, 0, 0, 0, 0).returnValue >= 0

    private fun isSeccompSanityCheckPassing(): Boolean {
        // Bogus Sanity Check: Ensure the kernel actively enforces seccomp.
        // We call prctl(PR_SET_SECCOMP) with an invalid mode (-1).
        // A healthy kernel should return -1 and set errno to EINVAL (22).
        // Some container environments or broken kernels might silently return 0 or a different error.
        val bogusCheck = LinuxNative.prctl(NativeConstants.PR_SET_SECCOMP, -1L, 0L, 0, 0)
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

    /**
     * Data class containing in-app diagnostics.
     */
    data class Diagnostics(
        val osName: String,
        val osVersion: String,
        val osArch: String,
        val isLinux: Boolean,
        val isArchitectureSupported: Boolean,
        val isNoNewPrivsEnabled: Boolean,
        val seccompMode: SeccompMode,
        val yamaPtraceScope: YamaPtraceScope,
        val landlockAbiVersion: Int,
        val isContainer: Boolean,
    ) {
        override fun toString(): String {
            return """
                === Mazewall Platform Diagnostics ===
                OS Name: $osName ($osVersion)
                Architecture: $osArch (Supported: $isArchitectureSupported)
                Is Linux: $isLinux
                no_new_privs Enabled: $isNoNewPrivsEnabled
                Seccomp Mode: ${when (seccompMode) {
                    is SeccompMode.Disabled -> "Disabled (0)"
                    is SeccompMode.Strict -> "Strict Mode (1)"
                    is SeccompMode.Filter -> "Filter Mode (2)"
                    is SeccompMode.Error -> "Error (${seccompMode.errno})"
                }}
                Yama ptrace_scope: ${when (yamaPtraceScope) {
                    is YamaPtraceScope.Classic -> "Classic (0)"
                    is YamaPtraceScope.Restricted -> "Restricted (1)"
                    is YamaPtraceScope.AdminOnly -> "AdminOnly (2)"
                    is YamaPtraceScope.Disabled -> "Disabled (3)"
                    is YamaPtraceScope.Unknown -> "Unknown (${yamaPtraceScope.rawValue})"
                    is YamaPtraceScope.Unavailable -> "Unavailable"
                }}
                Landlock ABI Version: ${if (landlockAbiVersion > 0) "$landlockAbiVersion" else "Unsupported ($landlockAbiVersion)"}
                Container Detected: $isContainer
                =====================================
            """.trimIndent()
        }
    }

    @Suppress("MagicNumber")
    private fun readYamaPtraceScope(): YamaPtraceScope {
        val file = java.io.File("/proc/sys/kernel/yama/ptrace_scope")
        if (!file.exists()) return YamaPtraceScope.Unavailable
        return try {
            val content = file.readText().trim()
            val intVal = content.toIntOrNull() ?: return YamaPtraceScope.Unavailable
            when (intVal) {
                0 -> YamaPtraceScope.Classic
                1 -> YamaPtraceScope.Restricted
                2 -> YamaPtraceScope.AdminOnly
                3 -> YamaPtraceScope.Disabled
                else -> YamaPtraceScope.Unknown(intVal)
            }
        } catch (ignored: Exception) {
            YamaPtraceScope.Unavailable
        }
    }

    /**
     * Run diagnostics to check system capabilities and privilege/sandboxing status.
     */
    fun diagnose(): Diagnostics {
        val osName = System.getProperty("os.name") ?: "Unknown"
        val osVersion = System.getProperty("os.version") ?: "Unknown"
        val osArch = System.getProperty("os.arch") ?: "Unknown"
        val isLinux = osName.equals("Linux", ignoreCase = true)

        var isNoNewPrivsEnabled = false
        var seccompMode: SeccompMode = SeccompMode.Disabled
        var yamaPtraceScope: YamaPtraceScope = YamaPtraceScope.Unavailable
        var landlockAbiVersion = 0

        if (isLinux) {
            try {
                val nnpVal = LinuxNative.prctl(NativeConstants.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
                if (nnpVal.returnValue >= 0) {
                    isNoNewPrivsEnabled = nnpVal.returnValue == 1L
                }
            } catch (ignored: Exception) {
            }

            try {
                val seccompVal = LinuxNative.prctl(NativeConstants.PR_GET_SECCOMP, 0, 0, 0, 0)
                seccompMode = if (seccompVal.returnValue < 0) {
                    SeccompMode.Error(seccompVal.errno)
                } else {
                    when (seccompVal.returnValue) {
                        0L -> SeccompMode.Disabled
                        1L -> SeccompMode.Strict
                        2L -> SeccompMode.Filter
                        else -> SeccompMode.Error(-1)
                    }
                }
            } catch (ignored: Exception) {
            }

            yamaPtraceScope = readYamaPtraceScope()

            try {
                landlockAbiVersion = io.mazewall.landlock.Landlock
                    .getAbiVersion()
            } catch (ignored: Exception) {
            }
        }

        return Diagnostics(
            osName = osName,
            osVersion = osVersion,
            osArch = osArch,
            isLinux = isLinux,
            isArchitectureSupported = isArchitectureSupported(),
            isNoNewPrivsEnabled = isNoNewPrivsEnabled,
            seccompMode = seccompMode,
            yamaPtraceScope = yamaPtraceScope,
            landlockAbiVersion = landlockAbiVersion,
            isContainer = detectContainer(),
        )
    }

    private fun detectContainer(): Boolean {
        var isContainer = java.io.File("/.dockerenv").exists() ||
            java.io.File("/run/secrets/kubernetes.io").exists()

        if (!isContainer) {
            try {
                val cgroup = java.io.File("/proc/1/cgroup")
                if (cgroup.exists()) {
                    val content = cgroup.readText()
                    isContainer = content.contains("docker") ||
                        content.contains("podman") ||
                        content.contains("kubepods") ||
                        content.contains("containerd")
                }
            } catch (ignored: Exception) {
            }
        }
        return isContainer
    }
}
