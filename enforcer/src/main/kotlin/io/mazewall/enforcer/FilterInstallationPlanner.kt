package io.mazewall.enforcer

import io.mazewall.Policy
import io.mazewall.SeccompAction
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
        // Any syscall with an action priority > ACT_ALLOW (1) is considered a block
        val blockedInPolicy = policy.syscallActions.filterValues { it.priority > SeccompAction.ACT_ALLOW.priority }.keys

        val newBlocks = if (policy.defaultAction == SeccompAction.ACT_ALLOW) {
            blockedInPolicy - state.currentlyBlocked
        } else {
            emptySet()
        }

        val needsMmapProtection = !policy.allowMmapExec && state.currentlyAllowsMmapExec
        val needsCloneProtection = !policy.allowNonThreadClone && state.currentlyAllowsNonThreadClone
        val needsPrctlProtection = !policy.allowUnsafePrctl && state.currentlyAllowsUnsafePrctl

        val needsNewFilter = policy.defaultAction != SeccompAction.ACT_ALLOW ||
            newBlocks.isNotEmpty() ||
            needsMmapProtection ||
            needsCloneProtection ||
            needsPrctlProtection

        val toInstall = if (policy.defaultAction != SeccompAction.ACT_ALLOW) {
            policy
        } else {
            val builder = Policy.builder()
            for (sys in newBlocks) {
                val action = policy.syscallActions[sys] ?: SeccompAction.ACT_ERRNO
                builder.addAction(action, sys)
            }
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
