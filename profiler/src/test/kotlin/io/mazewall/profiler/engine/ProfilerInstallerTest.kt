package io.mazewall.profiler.engine

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import org.junit.jupiter.api.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class ProfilerInstallerTest {
    @Test
    fun `test coordinator thread handles connection retry failure`() {
        val accumulatedLogs = CopyOnWriteArrayList<TraceEvent>()
        val pathCache = ConcurrentHashMap<String, Long>()
        val errorRef = AtomicReference<Throwable?>(null)

        // Run on a dedicated thread to avoid contaminating the main JUnit thread
        val thread = Thread {
            try {
                val currentThread = Thread.currentThread()
                ProfilerInstaller.installProfilingFilterForThread(
                    socketPath = "/tmp/nonexistent-path.sock",
                    policy = Policy.PURE_COMPUTE_UNSAFE,
                    accumulatedLogs = accumulatedLogs,
                    stackTracesMap = null,
                    pathCache = pathCache,
                    workerThreadProvider = { currentThread },
                    connectWithRetry = { _ ->
                        throw IllegalStateException("Simulated connection retry failure")
                    },
                    startTraceListener = { _, _, _, _, _ -> },
                )
                // Trigger an intercepted syscall to force blocking in seccomp
                java.io.FileInputStream("/etc/hostname").use {}
            } catch (t: Throwable) {
                errorRef.set(t)
            }
        }
        thread.start()
        thread.join()

        val ex = errorRef.get()
        System.err.println("[TEST DEBUG] connection retry failure ex: $ex")
        ex?.printStackTrace()
        assertTrue(ex is IllegalStateException)
        assertTrue(ex.message?.contains("Simulated connection retry failure") == true)
    }

    @Test
    fun `test main thread waits for coordinator thread to finish`() {
        val accumulatedLogs = CopyOnWriteArrayList<TraceEvent>()
        val pathCache = ConcurrentHashMap<String, Long>()
        val errorRef = AtomicReference<Throwable?>(null)
        val startTime = System.currentTimeMillis()

        // Run on a dedicated thread to avoid contaminating the main JUnit thread
        val thread = Thread {
            try {
                val currentThread = Thread.currentThread()
                ProfilerInstaller.installProfilingFilterForThread(
                    socketPath = "/tmp/nonexistent-path.sock",
                    policy = Policy.PURE_COMPUTE_UNSAFE,
                    accumulatedLogs = accumulatedLogs,
                    stackTracesMap = null,
                    pathCache = pathCache,
                    workerThreadProvider = { currentThread },
                    connectWithRetry = { _ ->
                        Thread.sleep(500)
                        throw IllegalStateException("Delayed error")
                    },
                    startTraceListener = { _, _, _, _, _ -> },
                )
            } catch (t: Throwable) {
                errorRef.set(t)
            }
        }
        thread.start()
        thread.join()

        val duration = System.currentTimeMillis() - startTime
        val ex = errorRef.get()

        System.err.println("[TEST DEBUG] delayed error duration: $duration ms, ex: $ex")

        // This assertion will fail if the race condition is present (duration will be < 500ms)
        assertTrue(duration >= 500, "Main thread should have waited at least 500ms, but took $duration ms")
        assertTrue(ex is IllegalStateException)
        assertTrue(ex.message?.contains("Delayed error") == true)
    }

    @Test
    fun `test coordinator thread handles send descriptor failure`() {
        val accumulatedLogs = CopyOnWriteArrayList<TraceEvent>()
        val pathCache = ConcurrentHashMap<String, Long>()
        val errorRef = AtomicReference<Throwable?>(null)

        // Run on a dedicated thread to avoid contaminating the main JUnit thread
        val thread = Thread {
            try {
                val currentThread = Thread.currentThread()
                ProfilerInstaller.installProfilingFilterForThread(
                    socketPath = "/tmp/nonexistent-path.sock",
                    policy = Policy.PURE_COMPUTE_UNSAFE,
                    accumulatedLogs = accumulatedLogs,
                    stackTracesMap = null,
                    pathCache = pathCache,
                    workerThreadProvider = { currentThread },
                    connectWithRetry = { _ ->
                        // Return a dummy FD that will fail sendDescriptor
                        999
                    },
                    startTraceListener = { _, _, _, _, _ -> },
                )
                // Trigger an intercepted syscall to force blocking in seccomp
                java.io.FileInputStream("/etc/hostname").use {}
            } catch (t: Throwable) {
                errorRef.set(t)
            }
        }
        thread.start()
        thread.join()

        val ex = errorRef.get()
        System.err.println("[TEST DEBUG] send descriptor failure ex: $ex")
        ex?.printStackTrace()
        assertTrue(ex is IllegalStateException)
        assertTrue(ex.message?.contains("Failed to send seccomp listener FD to daemon") == true)
    }
}
