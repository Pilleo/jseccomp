package io.contained

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertTrue
import kotlin.test.assertEquals

@EnabledOnOs(OS.LINUX)
class ProfilerIntegrationTest {

    @Test
    fun `test profiler intercepts and logs file opens with path resolving via process_vm_readv`() {
        if (!Platform.isSupported()) return

        val baseExecutor = Executors.newSingleThreadExecutor()
        // Create a policy blocking file opens
        val openPolicy = Policy.builder()
            .block(Syscall.OPEN, Syscall.OPENAT)
            .build()

        val profilerExecutor = Profiler.wrap(baseExecutor, openPolicy)

        try {
            val targetFile = File("/etc/hostname")
            assertTrue(targetFile.exists(), "/etc/hostname should exist on Linux")

            // Submit a task that opens and reads /etc/hostname inside the sandboxed thread
            val future = profilerExecutor.submit(java.util.concurrent.Callable {
                targetFile.readText()
            })

            // Wait for completion. Under standard seccomp block, this would throw EPERM/IOException.
            // Under Profiler, the daemon intercepts it, reads the path, logs it, and continues it.
            val content = future.get(10, TimeUnit.SECONDS)
            assertTrue(content.isNotEmpty())

            // Give a short delay for background daemon logs to be piped
            Thread.sleep(1000)

            val logs = Profiler.recentLogs
            println("Captured logs in open test: $logs")

            // Check if any log line successfully captured the OPEN/OPENAT syscall and the path /etc/hostname
            val foundOpen = logs.any { line ->
                (line.contains("syscall=OPEN") || line.contains("syscall=OPENAT")) && 
                line.contains("paths=/etc/hostname")
            }
            assertTrue(foundOpen, "Expected to find intercepted file open for /etc/hostname. Got: $logs")

        } finally {
            profilerExecutor.shutdownNow()
            baseExecutor.shutdownNow()
        }
    }

    @Test
    fun `test profiler robustly handles grandchild process execution without crashing`() {
        if (!Platform.isSupported()) return

        val baseExecutor = Executors.newSingleThreadExecutor()
        val profilerExecutor = Profiler.wrap(baseExecutor, Policy.NO_EXEC)

        try {
            // Submit a task that runs a ProcessBuilder (triggers execve/execveat in grandchild)
            val future = profilerExecutor.submit {
                val pb = ProcessBuilder("echo", "hello-profiler")
                val process = pb.start()
                val exitCode = process.waitFor()
                assertEquals(0, exitCode)
            }

            // Wait for completion.
            future.get(10, TimeUnit.SECONDS)

            // Let the logs stream
            Thread.sleep(1000)

            val logs = Profiler.recentLogs
            println("Captured logs in process test: $logs")

            // Even if ptrace_scope restricts process_vm_readv on grandchild, the syscall must be intercepted and successfully continued.
            val foundExec = logs.any { line ->
                line.contains("syscall=EXECVE") || line.contains("syscall=EXECVEAT")
            }
            assertTrue(foundExec, "Expected to find intercepted EXECVE/EXECVEAT in logs. Got: $logs")

        } finally {
            profilerExecutor.shutdownNow()
            baseExecutor.shutdownNow()
        }
    }

    @Test
    fun `test profiler end-to-end compilation creates a valid policy and dsl`() {
        if (!Platform.isSupported()) return

        val baseExecutor = Executors.newSingleThreadExecutor()
        
        // PURE_COMPUTE blocks file open and network
        val profilerExecutor = Profiler.wrap(baseExecutor, Policy.PURE_COMPUTE)

        Profiler.clear()

        try {
            val targetFile = File("/etc/hostname")
            assertTrue(targetFile.exists())

            // Read the file inside the sandboxed thread (triggers OPEN/OPENAT/OPENAT2)
            val future = profilerExecutor.submit(java.util.concurrent.Callable {
                targetFile.readText()
            })

            val content = future.get(10, TimeUnit.SECONDS)
            assertTrue(content.isNotEmpty())

            // Wait for trace message piping
            Thread.sleep(1000)

            // Let's compile!
            val compiledPolicy = Profiler.compilePolicy()
            val dsl = Profiler.compileToDsl()
            println("Profiler compiled DSL:\n$dsl")

            // The compiled policy should have the open variant unblocked!
            val arch = Arch.current()
            val blocked = compiledPolicy.blockedSyscalls(arch).toSet()

            val openNr = Syscall.OPEN.numberFor(arch)
            val openatNr = Syscall.OPENAT.numberFor(arch)

            val openUnblocked = (openNr >= 0 && openNr !in blocked) || (openatNr >= 0 && openatNr !in blocked)
            assertTrue(openUnblocked, "At least one of OPEN or OPENAT should be unblocked in compiled policy")

            // The compiled policy should allow reading from /etc/hostname
            assertTrue(compiledPolicy.allowedFsReadPaths.contains("/etc/hostname"), "Should contain read-path for /etc/hostname")

            // Verify DSL has the correct builder and allowFsRead
            assertTrue(dsl.contains("Policy.builder()"))
            assertTrue(dsl.contains("allowFsRead(\"/etc/hostname\")"))

        } finally {
            profilerExecutor.shutdownNow()
            baseExecutor.shutdownNow()
        }
    }
}
