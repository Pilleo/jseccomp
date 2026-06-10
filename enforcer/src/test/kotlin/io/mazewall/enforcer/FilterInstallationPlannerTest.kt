package io.mazewall.enforcer

import io.mazewall.Policy
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FilterInstallationPlannerTest {
    @Test
    fun `should Not Create New Filter For Identical Whitelist`() {
        val policy = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_KILL_PROCESS)
            .allow(Syscall.READ, Syscall.WRITE)
            .build()

        val state = FilterInstallationPlanner.ContainerState(
            currentSyscallActions = mapOf(
                Syscall.READ to SeccompAction.ACT_ALLOW,
                Syscall.WRITE to SeccompAction.ACT_ALLOW,
            ),
            currentDefaultAction = SeccompAction.ACT_KILL_PROCESS,
            currentlyAllowsMmapExec = false,
            currentlyAllowsNonThreadClone = false,
            currentlyAllowsUnsafePrctl = false,
            currentDepth = 1,
        )

        val plan = FilterInstallationPlanner.calculateNewFilter(policy, state)

        assertFalse(plan.needsNewFilter, "Should skip installing identical whitelist filter")
    }

    @Test
    fun `should Include Syscall In New Blocks When Action Is Escalated`() {
        val policy = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ALLOW)
            .addAction(SeccompAction.ACT_KILL_PROCESS, Syscall.EXECVE)
            .build()

        val state = FilterInstallationPlanner.ContainerState(
            currentSyscallActions = mapOf(
                Syscall.EXECVE to SeccompAction.ACT_LOG,
            ),
            currentDefaultAction = SeccompAction.ACT_ALLOW,
            currentlyAllowsMmapExec = true,
            currentlyAllowsNonThreadClone = true,
            currentlyAllowsUnsafePrctl = true,
            currentDepth = 1,
        )

        val plan = FilterInstallationPlanner.calculateNewFilter(policy, state)

        assertTrue(plan.needsNewFilter, "Should install filter to escalate action severity")
        assertTrue(plan.newBlocks.containsKey(Syscall.EXECVE))
        assertEquals(SeccompAction.ACT_KILL_PROCESS, plan.newBlocks[Syscall.EXECVE])
    }
}
