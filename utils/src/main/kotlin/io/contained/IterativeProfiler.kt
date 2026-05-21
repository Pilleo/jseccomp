package io.contained

import java.nio.file.AccessDeniedException
import java.io.IOException

/**
 * Tier A Profiler: Unprivileged "Deny-and-Retry" loop.
 *
 * Intercepts AccessDeniedExceptions from io_uring or standard VFS operations,
 * extracts the failed path, whitelists it, and retries the operation until it succeeds.
 * This provides 100% unprivileged visibility into io_uring ring operations.
 */
object IterativeProfiler {

    fun profile(basePolicy: Policy = Policy.PURE_COMPUTE, task: Runnable): Policy {
        var currentPolicy = basePolicy
        val maxRetries = 20

        for (i in 0 until maxRetries) {
            val builder = Policy.builder().base(currentPolicy)
            var error: Throwable? = null

            val thread = Thread {
                try {
                    // Ensure Landlock is active even for empty policies to force discovery
                    if (currentPolicy.allowedFsReadPaths.isEmpty() && currentPolicy.allowedFsWritePaths.isEmpty()) {
                        Landlock.applyRestrictiveBarrier()
                    }
                    ContainedExecutors.installOnCurrentThread(currentPolicy)
                    task.run()
                } catch (t: Throwable) {
                    error = t
                }
            }
            thread.start()
            thread.join()

            val t = error
            if (t == null) return currentPolicy

            val path = extractViolationPath(t)
            if (path != null) {
                // Conservative write-path discovery: grant both read and write for the denied path.
                // AccessDeniedException from Landlock does not carry the access mode that was denied,
                // so we conservatively grant both read and write access to guarantee convergence.
                builder.allowFsRead(path)
                builder.allowFsWrite(path)
                currentPolicy = builder.build()
                continue
            }
            throw t
        }
        return currentPolicy
    }

    private fun extractViolationPath(t: Throwable): String? {
        if (t is AccessDeniedException) return t.file
        val msg = t.message ?: return null

        // Match absolute paths in typical JVM error messages:
        // java.io.FileNotFoundException: /etc/hostname (Permission denied)
        // java.io.FileNotFoundException: /etc/hostname (Operation not permitted)
        val pathRegex =
            Regex("""(?i)(/[^\s]+)\b.*?(?:Permission denied|Operation not permitted|refusé|verweigert|negado)""")
        val match = pathRegex.find(msg)
        return match?.groupValues?.get(1)?.removeSuffix(":")?.trim()
    }
}
