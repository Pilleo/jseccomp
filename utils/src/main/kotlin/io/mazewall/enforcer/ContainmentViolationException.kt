package io.mazewall.enforcer

/**
 * Exception thrown when a contained task violates the configured policy
 * (e.g., attempts to execute a blocked syscall).
 */
class ContainmentViolationException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
