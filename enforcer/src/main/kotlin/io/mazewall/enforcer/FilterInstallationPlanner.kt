package io.mazewall.enforcer

import io.mazewall.Policy
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import java.util.logging.Logger

/**
 * Internal helper for planning and verifying seccomp filter installations.
 */
internal object FilterInstallationPlanner {
    private val logger = Logger.getLogger(FilterInstallationPlanner::class.java.name)
    private const val MAX_SECCOMP_FILTERS = 32
    private const val WARN_FILTERS_THRESHOLD = 10

    data class ContainerState(
        val currentSyscallActions: Map<Syscall, SeccompAction>,
        val currentDefaultAction: SeccompAction,
        val currentlyAllowsMmapExec: Boolean,
        val currentlyAllowsNonThreadClone: Boolean,
        val currentlyAllowsUnsafePrctl: Boolean,
        val currentDepth: Int,
        val currentlyAllowedSyscalls: Set<Syscall>? = null,
    )

    data class FilterPlan(
        val needsNewFilter: Boolean,
        val toInstall: Policy,
        val newBlocks: Map<Syscall, SeccompAction>,
        val newDefaultAction: SeccompAction,
    )

    /**
     * Calculates the minimal new [Policy] (if any) needed to enforce the requested [policy]
     * given the current [state].
     *
     * It compares the incoming policy's default action and specific syscall actions against
     * the currently applied actions. BPF semantics dictate that the kernel will enforce the
     * most restrictive (highest priority) action across all stacked filters. Thus, a new filter
     * block is only strictly required if the new action has a higher priority than the current one.
     */
    @Suppress("CyclomaticComplexMethod")
    fun calculateNewFilter(
        policy: Policy,
        state: ContainerState,
    ): FilterPlan {
        val effectiveNewDefaultAction = if (policy.defaultAction.priority > state.currentDefaultAction.priority) {
            policy.defaultAction
        } else {
            state.currentDefaultAction
        }

        val newBlocksMap = mutableMapOf<Syscall, SeccompAction>()

        // Check explicitly mapped actions in the new policy
        for ((sys, action) in policy.syscallActions) {
            val currentAction = state.currentSyscallActions[sys] ?: state.currentDefaultAction
            if (action.priority > currentAction.priority) {
                newBlocksMap[sys] = action
            }
        }

        // If the new policy operates as a whitelist (or has any restrictive default),
        // we must check if there are syscalls currently allowed that the new policy restricts via its default action.
        if (policy.defaultAction.priority > SeccompAction.ACT_ALLOW.priority && state.currentlyAllowedSyscalls != null) {
            val toInstallAllowed = Syscall.entries.filter { policy.isSyscallAllowed(it) }.toSet()
            for (sys in state.currentlyAllowedSyscalls) {
                if (!toInstallAllowed.contains(sys)) {
                    val currentAction = state.currentSyscallActions[sys] ?: state.currentDefaultAction
                    if (policy.defaultAction.priority > currentAction.priority) {
                        newBlocksMap[sys] = policy.defaultAction
                    }
                }
            }
        }

        val needsMmapProtection = !policy.allowMmapExec && state.currentlyAllowsMmapExec
        val needsCloneProtection = !policy.allowNonThreadClone && state.currentlyAllowsNonThreadClone
        val needsPrctlProtection = !policy.allowUnsafePrctl && state.currentlyAllowsUnsafePrctl

        val needsDefaultActionEscalation = policy.defaultAction.priority > state.currentDefaultAction.priority

        val needsWhitelistEscalation = if (needsDefaultActionEscalation && policy.defaultAction != SeccompAction.ACT_ALLOW) {
            val toInstallAllowed = Syscall.entries.filter { policy.isSyscallAllowed(it) }.toSet()
            val currentlyAllowed = state.currentlyAllowedSyscalls

            if (currentlyAllowed != null) {
                !toInstallAllowed.containsAll(currentlyAllowed)
            } else {
                true
            }
        } else {
            needsDefaultActionEscalation
        }

        val needsNewFilter = needsWhitelistEscalation ||
            newBlocksMap.isNotEmpty() ||
            needsMmapProtection ||
            needsCloneProtection ||
            needsPrctlProtection

        val toInstall = if (needsWhitelistEscalation) {
            policy
        } else {
            val builder = Policy.builder()
            for ((sys, action) in newBlocksMap) {
                builder.addAction(action, sys)
            }
            if (policy.allowMmapExec || !state.currentlyAllowsMmapExec) builder.allowMmapExec()
            if (policy.allowNonThreadClone || !state.currentlyAllowsNonThreadClone) builder.allowNonThreadClone()
            if (policy.allowUnsafePrctl || !state.currentlyAllowsUnsafePrctl) builder.allowUnsafePrctl()
            builder.build()
        }

        return FilterPlan(needsNewFilter, toInstall, newBlocksMap, effectiveNewDefaultAction)
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
