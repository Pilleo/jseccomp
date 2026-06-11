package io.mazewall.profiler

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class ProfilerStressTest {
    private val stressTimeout = Duration.ofSeconds(120)

    @Test
    fun `test thundering herd handshake stress`() {
        assertTimeoutPreemptively(stressTimeout) {
            val threadCount = 64
            val iterationsPerThread = 10
            val pool = Executors.newFixedThreadPool(threadCount)
            val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE_UNSAFE)

            val successCount = AtomicInteger(0)
            val totalExpected = threadCount * iterationsPerThread

            try {
                val futures =
                    (1..totalExpected).map {
                        wrapped.submit {
                            // Trigger a seccomp notification via OPENAT
                            if (File("/etc/hostname").readText().isNotEmpty()) {
                                successCount.incrementAndGet()
                            }
                        }
                    }

                futures.forEach { it.get(10, TimeUnit.SECONDS) }
            } finally {
                wrapped.shutdown()
                wrapped.awaitTermination(5, TimeUnit.SECONDS)
            }

            assertTrue(successCount.get() == totalExpected, "All tasks should complete successfully")
        }
    }

    @Test
    fun `test rapid wrapped executor lifecycle stress`() {
        assertTimeoutPreemptively(stressTimeout) {
            val lifecycleIterations = 30
            val tasksPerIteration = 5

            repeat(lifecycleIterations) {
                val pool = Executors.newFixedThreadPool(4)
                val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE_UNSAFE)

                try {
                    val futures =
                        (1..tasksPerIteration).map {
                            wrapped.submit {
                                File("/etc/hostname").readText()
                            }
                        }
                    futures.forEach { it.get(5, TimeUnit.SECONDS) }
                } finally {
                    wrapped.shutdown()
                    wrapped.awaitTermination(2, TimeUnit.SECONDS)
                }
            }
        }
    }

    @Test
    fun `test concurrent profiling context integrity`() {
        val concurrentRuns = 5
        val pool = Executors.newFixedThreadPool(concurrentRuns)

        val futures =
            (1..concurrentRuns).map { runId ->
                pool.submit(
                    java.util.concurrent.Callable<String> {
                        val result =
                            Profiler.profile {
                                // Mixed syscalls
                                File("/etc/hostname").readText()
                                File("/proc/self/comm").readText()
                                "ID-$runId"
                            }
                        // Each run should have its own isolated BillOfBehavior
                        assertTrue(result.behavior.syscalls.isNotEmpty(), "Syscalls should not be empty for ID-$runId")
                        assertTrue(result.behavior.opens.contains("/etc/hostname"), "Should capture /etc/hostname for ID-$runId")
                        result.value
                    },
                )
            }

        val results =
            futures.mapIndexed { index, future ->
                try {
                    val valRes = future.get(15, TimeUnit.SECONDS)
                    if (valRes == null) {
                        System.err.println("TASK-$index RETURNED NULL!")
                    }
                    valRes
                } catch (e: Exception) {
                    throw IllegalStateException("Task $index failed: ${e.message}", e)
                }
            }
        System.err.println("INTEGRITY_RESULTS: $results")
        assertTrue(results.toSet().size == concurrentRuns, "All concurrent profile blocks should return unique IDs. Got: $results")

        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)
    }
}
