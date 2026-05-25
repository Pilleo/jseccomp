package io.mazewall.enforcer

import io.mazewall.Policy
import io.mazewall.Syscall
import java.util.logging.Logger

/**
 * Internal helper for planning and verifying seccomp filter installations.
 */
internal object FilterInstallationPlanner {
    private val logger = Logger.getLogger(FilterInstallationPlanner::class.java.name)
    private const val MAX_SECCOMP_FILTERS = 32
    private const val WARN_FILTERS_THRESHOLD = 10

    data class ContainerState(
        val currentlyBlocked: Set<Syscall>,
        val currentlyAllowsMmapExec: Boolean,
        val currentlyAllowsNonThreadClone: Boolean,
        val currentlyAllowsUnsafePrctl: Boolean,
        val currentDepth: Int,
    )

    data class FilterPlan(
        val needsNewFilter: Boolean,
        val toInstall: Policy,
        val newBlocks: Set<Syscall>,
    )

    fun calculateNewFilter(
        policy: Policy,
        state: ContainerState,
    ): FilterPlan {
        val newBlocks = if (policy.mode == Policy.Mode.DENY_LIST) {
            policy.syscalls - state.currentlyBlocked
        } else {
            emptySet()
        }

        val needsMmapProtection = !policy.allowMmapExec && state.currentlyAllowsMmapExec
        val needsCloneProtection = !policy.allowNonThreadClone && state.currentlyAllowsNonThreadClone
        val needsPrctlProtection = !policy.allowUnsafePrctl && state.currentlyAllowsUnsafePrctl

        val needsNewFilter = policy.mode == Policy.Mode.ALLOW_LIST ||
            newBlocks.isNotEmpty() ||
            needsMmapProtection ||
            needsCloneProtection ||
            needsPrctlProtection

        val toInstall = if (policy.mode == Policy.Mode.ALLOW_LIST) {
            policy
        } else {
            val builder = Policy.builder().block(*newBlocks.toTypedArray())
            if (policy.allowMmapExec) builder.allowMmapExec()
            if (policy.allowNonThreadClone) builder.allowNonThreadClone()
            if (policy.allowUnsafePrctl) builder.allowUnsafePrctl()
            builder.build()
        }

        return FilterPlan(needsNewFilter, toInstall, newBlocks)
    }

    fun verifyFilterDepth(currentDepth: Int) {
        if (currentDepth >= MAX_SECCOMP_FILTERS) {
            throw IllegalStateException("Cannot install more than $MAX_SECCOMP_FILTERS seccomp filters.")
        }
        if (currentDepth > WARN_FILTERS_THRESHOLD) {
            logger.warning("Thread ${Thread.currentThread().name} has $currentDepth seccomp filters.")
        }
    }
}
