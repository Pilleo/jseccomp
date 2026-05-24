package io.mazewall.profiler

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.landlock.Landlock
import java.nio.file.AccessDeniedException

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
                // Heuristic-based access discovery.
                // AccessDeniedException from Landlock does not explicitly carry the access mode that was denied.
                // To avoid over-granting write access, we check if the path is already readable by the current
                // process (ignoring Landlock). If it is already readable but we still got a violation, it was
                // likely a Write attempt.
                val file = java.io.File(path)
                val isReadableOutsideSandbox = file.exists() && file.canRead()
                val isCurrentlyReadAllowed = currentPolicy.allowedFsReadPaths.any { path.startsWith(it) }

                if (isReadableOutsideSandbox && isCurrentlyReadAllowed) {
                    // It was already readable, so it's probably a write denial
                    builder.allowFsWrite(path)
                } else {
                    // Conservative fallback: grant both to guarantee convergence.
                    // This covers cases where the file doesn't exist (Write needed for creation)
                    // or where Read itself was the reason for denial.
                    builder.allowFsRead(path)
                    builder.allowFsWrite(path)
                }
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

        // Search for any of the localized denial phrases
        var phraseIdx = -1
        for (phrase in ContainedExecutors.DENIED_PHRASES) {
            phraseIdx = msg.indexOf(phrase, ignoreCase = true)
            if (phraseIdx != -1) break
        }

        if (phraseIdx == -1) return null

        // Find the end of the path by skipping backwards over whitespace and '('
        var pathEnd = phraseIdx - 1
        while (pathEnd >= 0 && (msg[pathEnd].isWhitespace() || msg[pathEnd] == '(')) {
            pathEnd--
        }

        if (pathEnd < 0) return null

        // Scan further backwards to find the start of the absolute path
        var pathStart = pathEnd
        while (pathStart > 0) {
            val c = msg[pathStart - 1]
            if (c.isWhitespace() || c == ':') break
            pathStart--
        }

        val path = msg.substring(pathStart, pathEnd + 1)
        return if (path.startsWith("/")) path else null
    }
}
