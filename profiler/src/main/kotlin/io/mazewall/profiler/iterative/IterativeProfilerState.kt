package io.mazewall.profiler.iterative

import io.mazewall.Policy

/**
 * States representing the lifecycle of the IterativeProfiler learning loop.
 */
internal sealed interface IterativeProfilerState {
    /** Currently running the target task with the specified policy. */
    data class Running(
        val policy: Policy<*>,
        val iteration: Int,
    ) : IterativeProfilerState

    /** Task finished with an error; analyzing whether it is a path violation. */
    data class Analyzing(
        val policy: Policy<*>,
        val error: Throwable,
        val iteration: Int,
    ) : IterativeProfilerState

    /** A path violation was identified; updating the policy to grant the needed access. */
    data class Updating(
        val policy: Policy<*>,
        val path: String,
        val iteration: Int,
    ) : IterativeProfilerState

    /** Iteration loop converged successfully with no violations. */
    data class Converged(
        val policy: Policy<*>,
    ) : IterativeProfilerState

    /** Maximum retries exceeded without convergence. */
    data class Exceeded(
        val policy: Policy<*>,
    ) : IterativeProfilerState

    /** Task execution failed with an error that is not a containment violation. */
    data class Failed(
        val policy: Policy<*>,
        val error: Throwable,
    ) : IterativeProfilerState
}
