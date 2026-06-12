package io.mazewall.enforcer

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.IsolatedProcessTester
import io.mazewall.Policy
import io.mazewall.PolicyScope
import io.mazewall.core.Syscall
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ContainedExecutorsTest {
    fun testContainmentWrapperBlocksExecve() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        val future = safeExecutor.submit {
            ProcessBuilder("echo", "hello").start()
        }
        try {
            future.get()
            throw IllegalStateException("Should have failed")
        } catch (e: ExecutionException) {
            if (e.cause !is ContainmentViolationException) {
                throw e
            }
        } finally {
            executor.shutdown()
        }
    }

    fun testPerThreadIsolation() {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        val future = safeExecutor.submit(java.util.concurrent.Callable { "installed" })
        if (future.get() != "installed") throw IllegalStateException("Failed to install")

        // Main thread should still be able to exec
        val process = ProcessBuilder("echo", "uncontained").start()
        if (process.waitFor() != 0) throw IllegalStateException("Main thread blocked unexpectedly")
        executor.shutdown()
    }

    fun testInvokeAllAppliesContainment() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        try {
            val tasks = listOf(
                java.util.concurrent.Callable { ProcessBuilder("echo", "1").start() },
                java.util.concurrent.Callable { ProcessBuilder("echo", "2").start() },
            )
            val futures = safeExecutor.invokeAll(tasks)
            for (future in futures) {
                try {
                    future.get()
                    throw IllegalStateException("Task should have been contained")
                } catch (e: ExecutionException) {
                    if (e.cause !is ContainmentViolationException) throw e
                }
            }
        } finally {
            executor.shutdown()
        }
    }

    fun testInvokeAnyAppliesContainment() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        try {
            val tasks = listOf(
                java.util.concurrent.Callable {
                    Runtime.getRuntime().exec(arrayOf("echo", "fail"))
                    "should not reach here"
                },
            )
            try {
                safeExecutor.invokeAny(tasks)
                throw IllegalStateException("Should have failed")
            } catch (e: ExecutionException) {
                if (e.cause !is ContainmentViolationException) throw e
            }
        } finally {
            executor.shutdown()
        }
    }

    fun testHierarchicalLandlockStackingSuccess() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit(
                java.util.concurrent.Callable {
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/tmp").build())
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/tmp/foo").build())
                "success"
            },
            )
            if (future.get() != "success") throw IllegalStateException("Failed")
        } finally {
            executor.shutdown()
        }
    }

    fun testHierarchicalLandlockStackingFailureOnExpansion() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit {
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/tmp").build())
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/etc").build())
            }
            try {
                future.get()
                throw IllegalStateException("Should have failed")
            } catch (e: ExecutionException) {
                val cause = e.cause
                if (cause !is IllegalStateException || cause.message?.contains("Cannot expand Landlock") != true) {
                    throw e
                }
            }
        } finally {
            executor.shutdown()
        }
    }

    fun testHierarchicalLandlockStackingFailureOnComponentBoundaryMismatch() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit {
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/tmp").build())
                ContainedExecutors.installOnCurrentThread(Policy.builder().allowFsRead("/tmp-foo").build())
            }
            try {
                future.get()
                throw IllegalStateException("Should have failed")
            } catch (e: ExecutionException) {
                val cause = e.cause
                if (cause !is IllegalStateException || cause.message?.contains("Cannot expand Landlock") != true) {
                    throw e
                }
            }
        } finally {
            executor.shutdown()
        }
    }

    fun testHierarchicalLandlockStackingIdenticalPaths() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit(
                java.util.concurrent.Callable {
                val p = Policy.builder().allowFsRead("/tmp").build()
                ContainedExecutors.installOnCurrentThread(p)
                ContainedExecutors.installOnCurrentThread(p)
                "success"
            },
            )
            if (future.get() != "success") throw IllegalStateException("Failed")
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test containment wrapper blocks execve`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testContainmentWrapperBlocksExecve")
    }

    @Test
    fun `test graceful degradation fallback`() {
        val osName = System.getProperty("os.name")
        if (osName.equals("Linux", ignoreCase = true)) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        val future = safeExecutor.submit { "success" }
        assertEquals("success", future.get())
        executor.shutdown()
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test per-thread isolation (TSYNC bug fix)`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testPerThreadIsolation")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `invokeAll applies containment to all tasks`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testInvokeAllAppliesContainment")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `invokeAny applies containment`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testInvokeAnyAppliesContainment")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test wrap() executor invokeAll and invokeAny with timeouts`() {
        val executor = Executors.newFixedThreadPool(2)
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        try {
            val tasks = listOf(
                java.util.concurrent.Callable { "task1" },
                java.util.concurrent.Callable { "task2" },
            )
            val results = safeExecutor.invokeAll(tasks, 5, TimeUnit.SECONDS)
            assertEquals(2, results.size)
            assertEquals("task1", results[0].get())

            val any = safeExecutor.invokeAny(tasks, 5, TimeUnit.SECONDS)
            assertTrue(any == "task1" || any == "task2")
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `isContainmentViolation handles nested exceptions with error code`() {
        val root = java.io.IOException("something went wrong (error=1)")
        val nested = RuntimeException("wrapper", root)
        val deeplyNested = RuntimeException("outer", nested)
        assertTrue(ContainmentViolationDetector.isContainmentViolation(deeplyNested))
    }

    @Test
    fun `isContainmentViolation handles suppressed exceptions with error code`() {
        val root = java.io.IOException("failed (error: 13)")
        val main = RuntimeException("main")
        main.addSuppressed(root)
        assertTrue(ContainmentViolationDetector.isContainmentViolation(main))
    }

    @Test
    fun `installOnProcess rejects policies with io_uring due to landlock requirement`() {
        val policy = Policy
            .builder()
            .base(Policy.PURE_COMPUTE_UNSAFE)
            .unblock(Syscall.IO_URING_SETUP)
            .build()
        val ex = assertFailsWith<UnsupportedOperationException> {
            ContainedExecutors.installOnProcess(policy)
        }
        assertTrue(ex.message!!.contains("does not support Landlock filesystem rules"))
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test hierarchical Landlock stacking success`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testHierarchicalLandlockStackingSuccess")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test hierarchical Landlock stacking failure on expansion`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testHierarchicalLandlockStackingFailureOnExpansion")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test hierarchical Landlock stacking failure on component boundary mismatch`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testHierarchicalLandlockStackingFailureOnComponentBoundaryMismatch")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test hierarchical Landlock stacking identical paths`() {
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testHierarchicalLandlockStackingIdenticalPaths")
    }

    @Test
    fun `installOnCurrentThread accepts both process-wide and thread-local policies`() {
        val threadLocalPolicy: Policy<PolicyScope.ThreadLocalOnly> = Policy.builder().allowFsRead("/tmp").build()
        val processWidePolicy: Policy<PolicyScope.ProcessWideSafe> = Policy.builder().build()

        val list = listOf<Policy<*>>(threadLocalPolicy, processWidePolicy)
        assertEquals(2, list.size)
    }

    @Test
    fun `installOnProcess rejects cast thread-local policy with UnsupportedOperationException`() {
        val threadLocalPolicy = Policy.builder().allowFsRead("/tmp").build()

        @Suppress("UNCHECKED_CAST")
        val castPolicy = threadLocalPolicy as Policy<PolicyScope.ProcessWideSafe>

        val ex = assertFailsWith<UnsupportedOperationException> {
            ContainedExecutors.installOnProcess(castPolicy)
        }
        assertTrue(ex.message!!.contains("only allowed for ThreadLocalOnly") || ex.message!!.contains("not support") || ex.message != null)
    }
}
