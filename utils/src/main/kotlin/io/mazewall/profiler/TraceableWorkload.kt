package io.mazewall.profiler

/**
 * A marker interface for workloads that can be profiled using the [StraceProfiler].
 * Workload classes must have a public no-arg constructor so they can be instantiated
 * dynamically inside the child JVM process.
 */
interface TraceableWorkload : Runnable
