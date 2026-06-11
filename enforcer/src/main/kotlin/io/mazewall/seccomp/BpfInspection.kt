package io.mazewall.seccomp

import io.mazewall.core.SeccompAction

/**
 * Supported argument checks for BPF inspections.
 */
internal sealed interface ArgCheck {
    /** Checks if the bitwise AND of the argument and the mask matches the expected value. */
    data class MaskEquals(
        val mask: Long,
        val expected: Long,
    ) : ArgCheck

    /** Checks if the argument is exactly equal to one of the allowed values. */
    data class EqualsAny(
        val allowedValues: List<Long>,
    ) : ArgCheck
}

/**
 * Represents a declarative check for a specific syscall argument.
 */
internal data class SyscallInspection(
    val syscallNumber: Int,
    val argIndex: Int,
    val check: ArgCheck,
    val ifMatched: SeccompAction,
    val ifNotMatched: SeccompAction,
)
