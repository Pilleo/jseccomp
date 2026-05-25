package io.mazewall.enforcer

import java.io.IOException
import java.nio.file.AccessDeniedException

/**
 * Internal helper for detecting containment violations in exceptions.
 */
internal object ContainmentViolationDetector {
    private val ERRNO_VIOLATION_REGEX = Regex("""\berror[=:]\s*(1|13)\b""")

    internal val DENIED_PHRASES = arrayOf(
        "Operation not permitted",
        "Permission denied",
        "refusé",
        "verweigert",
        "negado",
    )

    fun isContainmentViolation(t: Throwable): Boolean =
        isDirectContainmentViolation(t) ||
            isViolationInCauseChain(t.cause, t) ||
            isViolationInSuppressed(t.suppressedExceptions)

    fun findViolationCause(t: Throwable): Throwable? =
        if (isDirectContainmentViolation(t)) {
            t
        } else {
            findInCauseChain(t.cause, t) ?: findInSuppressed(t.suppressedExceptions)
        }

    private fun isViolationInCauseChain(
        cause: Throwable?,
        original: Throwable,
    ): Boolean {
        var current = cause
        while (current != null && current !== original) {
            if (isDirectContainmentViolation(current)) return true
            current = current.cause
        }
        return false
    }

    private fun isViolationInSuppressed(suppressed: List<Throwable>): Boolean = suppressed.any { isDirectContainmentViolation(it) }

    private fun findInCauseChain(
        cause: Throwable?,
        original: Throwable,
    ): Throwable? {
        var current = cause
        while (current != null && current !== original) {
            if (isDirectContainmentViolation(current)) return current
            current = current.cause
        }
        return null
    }

    private fun findInSuppressed(suppressed: List<Throwable>): Throwable? = suppressed.find { isDirectContainmentViolation(it) }

    private fun isDirectContainmentViolation(t: Throwable): Boolean {
        val msg = t.message ?: return false
        val isViolation = when {
            t is AccessDeniedException -> true
            ERRNO_VIOLATION_REGEX.containsMatchIn(msg) -> true
            t is IOException && (containsDeniedPhrase(msg) || msg.contains("Cannot run")) -> true
            else -> false
        }
        return isViolation
    }

    private fun containsDeniedPhrase(msg: String): Boolean = DENIED_PHRASES.any { msg.contains(it, ignoreCase = true) }
}
