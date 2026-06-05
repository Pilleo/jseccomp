package io.mazewall.profiler

/**
 * The result of a [Profiler.profile] invocation.
 *
 * @param value    The value returned by the profiled lambda.
 * @param behavior Everything the profiler observed during the run.
 *
 * To compile a policy: result.behavior.toPolicy(Policy.PURE_COMPUTE_UNSAFE)
 * To get DSL:          result.behavior.toDsl("Policy.PURE_COMPUTE_UNSAFE")
 * To merge runs:       (run1.behavior + run2.behavior).toPolicy(...)
 */
data class ProfilingResult<T>(
    val value: T,
    val behavior: BillOfBehavior,
)
