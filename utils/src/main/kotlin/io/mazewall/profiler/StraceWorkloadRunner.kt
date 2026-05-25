package io.mazewall.profiler

/**
 * Subprocess entry point for the [StraceProfiler].
 * It receives the target workload class name as the first argument,
 * instantiates it via reflection using a no-arg constructor, and executes it.
 */
object StraceWorkloadRunner {
    @JvmStatic
    fun main(args: Array<String>) {
        val className = args.getOrNull(0) ?: throw IllegalArgumentException("Missing workload class name")
        val clazz = Class.forName(className)
        if (!TraceableWorkload::class.java.isAssignableFrom(clazz)) {
            throw IllegalArgumentException("Class $className does not implement TraceableWorkload")
        }
        val workload = clazz.getDeclaredConstructor().newInstance() as TraceableWorkload
        workload.run()
    }
}
