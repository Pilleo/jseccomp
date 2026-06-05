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
        assertTrue(ex is java.io.IOException)
        assertTrue(ex.message?.contains("Function not implemented") == true)
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
        assertTrue(ex is java.io.IOException)
        assertTrue(ex.message?.contains("Function not implemented") == true)
    }
}
