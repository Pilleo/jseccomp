package io.mazewall.profiler

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationDetector
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
    fun profile(
        basePolicy: Policy = Policy.PURE_COMPUTE,
        task: Runnable,
    ): Policy {
        var currentPolicy = basePolicy
        val maxRetries = 20

        for (i in 0 until maxRetries) {
            val t = executeTask(currentPolicy, task) ?: return currentPolicy
            val path = extractViolationPath(t)
            if (path != null) {
                currentPolicy = updatePolicyForViolation(currentPolicy, path)
                continue
            }
            throw t
        }
        return currentPolicy
    }

    private fun executeTask(
        currentPolicy: Policy,
        task: Runnable,
    ): Throwable? {
        var error: Throwable? = null
        val thread =
            Thread {
                // Ensure Landlock is active even for empty policies to force discovery
                if (currentPolicy.allowedFsReadPaths.isEmpty() && currentPolicy.allowedFsWritePaths.isEmpty()) {
                    Landlock.applyRestrictiveBarrier()
                }
                ContainedExecutors.installOnCurrentThread(currentPolicy)
                task.run()
            }
        thread.uncaughtExceptionHandler = Thread.UncaughtExceptionHandler { _, e ->
            error = e
        }
        thread.start()
        thread.join()
        return error
    }

    private fun updatePolicyForViolation(
        currentPolicy: Policy,
        path: String,
    ): Policy {
        val builder = Policy.builder().base(currentPolicy)
        val isCurrentlyReadAllowed = currentPolicy.allowedFsReadPaths.any { path.startsWith(it) }

        if (isCurrentlyReadAllowed) {
            // If read is already allowed but we still got denied, it's a write attempt.
            builder.allowFsWrite(path)
        } else {
            // First attempt: grant read access only.
            // If it was a write attempt, the next run will hit the `isCurrentlyReadAllowed` branch and add write.
            builder.allowFsRead(path)
        }
        return builder.build()
    }

    private fun extractViolationPath(t: Throwable): String? {
        val path = when {
            t is AccessDeniedException -> t.file
            else -> {
                val msg = t.message
                if (msg == null) {
                    null
                } else {
                    val phraseIdx = findDeniedPhraseIndex(msg)
                    val pathEnd = if (phraseIdx != -1) findPathEnd(msg, phraseIdx) else -1
                    if (pathEnd >= 0) resolveAbsolutePath(msg, pathEnd) else null
                }
            }
        }
        return path
    }

    private fun findDeniedPhraseIndex(msg: String): Int =
        ContainmentViolationDetector.DENIED_PHRASES.firstNotNullOfOrNull { phrase ->
            val idx = msg.indexOf(phrase, ignoreCase = true)
            if (idx != -1) idx else null
        } ?: -1

    private fun findPathEnd(
        msg: String,
        phraseIdx: Int,
    ): Int {
        var end = phraseIdx - 1
        while (end >= 0 && (msg[end].isWhitespace() || msg[end] == '(')) end--
        return end
    }

    private fun resolveAbsolutePath(
        msg: String,
        pathEnd: Int,
    ): String? {
        var start = pathEnd
        while (start > 0 && !msg[start - 1].isWhitespace() && msg[start - 1] != ':') start--
        val path = msg.substring(start, pathEnd + 1)
        return if (path.startsWith("/")) path else null
    }
}
