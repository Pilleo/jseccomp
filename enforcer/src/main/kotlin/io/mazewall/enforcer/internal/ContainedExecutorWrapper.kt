package io.mazewall.enforcer.internal

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationDetector
import io.mazewall.enforcer.ContainmentViolationException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/**
 * Internal wrapper that applies containment policies before task execution.
 */
internal class ContainedExecutorWrapper(
    private val delegate: ExecutorService,
    private val policy: Policy<*, *>,
) : ExecutorService by delegate {
    private fun <T> wrapCallable(task: Callable<T>): Callable<T> =
        Callable {
            applyContainment()
            val result = runCatching { task.call() }
            result.getOrElse { e ->
                if (e is Exception && ContainmentViolationDetector.isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

    private fun wrapRunnable(task: Runnable): Runnable =
        Runnable {
            applyContainment()
            val result = runCatching { task.run() }
            result.onFailure { e ->
                if (e is Exception && ContainmentViolationDetector.isContainmentViolation(e)) {
                    throw ContainmentViolationException("Task violated containment policy", e)
                }
                throw e
            }
        }

    private fun applyContainment() {
        ContainedExecutors.installOnCurrentThread(policy)
    }

    override fun execute(command: Runnable) {
        delegate.execute(wrapRunnable(command))
    }

    override fun <T> submit(task: Callable<T>): Future<T> = delegate.submit(wrapCallable(task))

    override fun <T> submit(
        task: Runnable,
        result: T,
    ): Future<T> = delegate.submit(wrapRunnable(task), result)

    override fun submit(task: Runnable): Future<*> = delegate.submit(wrapRunnable(task))

    override fun <T> invokeAll(tasks: Collection<Callable<T>>): List<Future<T>> = delegate.invokeAll(tasks.map { wrapCallable(it) })

    override fun <T> invokeAll(
        tasks: Collection<Callable<T>>,
        timeout: Long,
        unit: TimeUnit,
    ): List<Future<T>> = delegate.invokeAll(tasks.map { wrapCallable(it) }, timeout, unit)

    override fun <T> invokeAny(tasks: Collection<Callable<T>>): T = delegate.invokeAny(tasks.map { wrapCallable(it) })

    override fun <T> invokeAny(
        tasks: Collection<Callable<T>>,
        timeout: Long,
        unit: TimeUnit,
    ): T = delegate.invokeAny(tasks.map { wrapCallable(it) }, timeout, unit)

    override fun close() {
        delegate.close()
    }
}
