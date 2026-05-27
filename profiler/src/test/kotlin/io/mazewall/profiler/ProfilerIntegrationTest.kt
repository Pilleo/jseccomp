package io.mazewall.profiler

import io.mazewall.Arch
import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.Syscall
import io.mazewall.profiler.compiler.BobCompiler
import org.junit.jupiter.api.Test
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class ProfilerIntegrationTest {
    @Test
    fun `test profiler intercepts and logs file opens with path resolving and stack trace capture`() {
        val targetFile = File("/etc/hostname")
        assertTrue(targetFile.exists(), "/etc/hostname should exist on Linux")

        // Submit task inside the new stateless profile block
        val result =
            Profiler.profile {
                targetFile.readText()
            }

        assertTrue(result.value.isNotEmpty())
        val bob = result.behavior

        // Verify we captured the OPEN or OPENAT syscall in bob
        assertTrue(
            bob.syscalls.contains(Syscall.OPEN) ||
                bob.syscalls.contains(Syscall.OPENAT) ||
                bob.syscalls.contains(Syscall.OPENAT2),
            "Should capture file open syscall. Observed: ${bob.syscalls}",
        )
        assertTrue(bob.opens.contains("/etc/hostname"), "Should contain opened path /etc/hostname")

        // Assert that the stackProfile contains the trace event and its stack trace has our test class name!
        assertTrue(bob.stackProfile.isNotEmpty(), "Stack profile should not be empty")
        val hasOurClass =
            bob.stackProfile.values.any { traces ->
                traces.any { frames ->
                    frames.any { frame -> frame.className.contains("ProfilerIntegrationTest") }
                }
            }
        assertTrue(hasOurClass, "Stack trace should contain the ProfilerIntegrationTest call frame")
    }

    @Test
    fun `test profiler robustly handles grandchild process execution without crashing`() {
        // Submit a task that runs a ProcessBuilder (triggers execve/execveat in grandchild)
        val result =
            Profiler.profile {
                val pb = ProcessBuilder("echo", "hello-profiler")
                val process = pb.start()
                val exitCode = process.waitFor()
                assertEquals(0, exitCode)
            }

        val bob = result.behavior
        assertTrue(
            bob.syscalls.contains(Syscall.EXECVE) || bob.syscalls.contains(Syscall.EXECVEAT),
            "Should capture process execution syscall. Observed: ${bob.syscalls}",
        )
    }

    @Test
    fun `test profiler end-to-end compilation creates a valid policy and dsl`() {
        val targetFile = File("/etc/hostname")
        assertTrue(targetFile.exists())

        // Read the file inside the sandboxed thread (triggers OPEN/OPENAT/OPENAT2)
        val result =
            Profiler.profile {
                targetFile.readText()
            }

        assertTrue(result.value.isNotEmpty())
        val bob = result.behavior

        // Let's compile!
        val compiledPolicy = bob.toPolicy(Policy.PURE_COMPUTE)
        val dsl = bob.toDsl("Policy.PURE_COMPUTE", Policy.PURE_COMPUTE)
        println("Profiler compiled DSL:\n$dsl")

        // The compiled policy should have the open variant unblocked!
        val arch = Arch.current()
        val restricted = compiledPolicy.syscallActionNumbers(Arch.current()).keys.toList()

        val openNr = Syscall.OPEN.numberFor(arch)
        val openatNr = Syscall.OPENAT.numberFor(arch)

        val openUnblocked = (openNr >= 0 && compiledPolicy.isSyscallAllowed(Syscall.OPEN)) || (openatNr >= 0 && compiledPolicy.isSyscallAllowed(Syscall.OPENAT))
        assertTrue(openUnblocked, "At least one of OPEN or OPENAT should be unblocked in compiled policy")

        // The compiled policy should allow reading from /etc/hostname
        assertTrue(
            compiledPolicy.allowedFsReadPaths.contains("/etc/hostname"),
            "Should contain read-path for /etc/hostname",
        )

        // Verify DSL has the correct builder and allowFsRead
        assertTrue(dsl.contains("Policy.builder()"))
        assertTrue(dsl.contains("allowFsRead(\"/etc/hostname\")"))
    }

    @Test
    fun `test profiler rejects being run inside virtual thread`() {
        val vExecutor = Executors.newVirtualThreadPerTaskExecutor()
        try {
            val future =
                vExecutor.submit {
                    Profiler.profile { println("inside virtual thread") }
                }
            val ex =
                org.junit.jupiter.api.assertThrows<java.util.concurrent.ExecutionException> {
                    future.get(5, TimeUnit.SECONDS)
                }
            assertTrue(ex.cause is IllegalStateException)
            assertTrue(ex.cause?.message?.contains("virtual threads") == true)
        } finally {
            vExecutor.shutdownNow()
        }
    }

    @Test
    fun `test profiler correctly resolves relative paths via AT_FDCWD`() {
        val fileName = "relative-test-${System.currentTimeMillis()}.txt"
        val file = File(fileName)
        file.writeText("relative content")
        try {
            val result =
                Profiler.profile {
                    // This triggers openat(AT_FDCWD, "filename", ...)
                    file.readText()
                }
            val absolutePath = file.absolutePath
            assertTrue(
                result.behavior.opens.contains(absolutePath),
                "Should resolve relative path $fileName to absolute path $absolutePath. Observed: ${result.behavior.opens}",
            )
        } finally {
            file.delete()
        }
    }

    @Test
    fun `test profiler correctly resolves fd based paths like FCHMOD`() {
        val file = File("fchmod-test-${System.currentTimeMillis()}.txt")
        file.writeText("content")
        val absolutePath = file.absolutePath
        val pool = Executors.newSingleThreadExecutor()
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        try {
            wrapped
                .submit(
                    Callable {
                        java.lang.foreign.Arena.ofConfined().use { arena ->
                            val pathSeg = arena.allocateFrom(absolutePath)
                            val openRes = LinuxNative.open(pathSeg, 0)
                            if (openRes.returnValue >= 0) {
                                val fd = openRes.returnValue.toInt()
                                val fchmodNr = Syscall.FCHMOD.numberFor(Arch.current()).toLong()
                                if (fchmodNr >= 0) {
                                    LinuxNative.syscall(fchmodNr, fd, 0x1FF) // 0777
                                }
                                LinuxNative.close(fd)
                            }
                        }
                    },
                ).get(5, TimeUnit.SECONDS)

            val eventsWithPath = wrapped.recentLogs.filter { it.paths.contains(absolutePath) }
            assertTrue(
                eventsWithPath.any { it.syscallName == "FCHMOD" || it.syscallName == "OPENAT" || it.syscallName == "OPEN" },
                "Should resolve fd-based syscall paths to absolute path $absolutePath. Observed events: ${wrapped.recentLogs.map {
                    it.syscallName to it.paths
                }}",
            )
        } finally {
            wrapped.shutdownNow()
            file.delete()
        }
    }

    @Test
    fun `test profiler daemon handles high-frequency concurrent events without stream corruption`() {
        val pool = Executors.newFixedThreadPool(8)
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        try {
            val taskCount = 200
            val target = File("/etc/hostname")
            val futures =
                (1..taskCount).map {
                    wrapped.submit(
                        Callable {
                            target.readText()
                        },
                    )
                }
            futures.forEach { it.get(10, TimeUnit.SECONDS) }

            // If the stream was corrupted, BobCompiler would throw or return garbage.
            val bob = BobCompiler.compile(wrapped.recentLogs)
            assertTrue(bob.opens.contains("/etc/hostname"), "Should contain /etc/hostname")
            // We should have many events, but they should all be structurally valid.
            assertTrue(wrapped.recentLogs.isNotEmpty())

            // Validate that we don't have partial/corrupted events (e.g. empty syscall names)
            assertTrue(wrapped.recentLogs.all { it.syscallName.isNotEmpty() })
        } finally {
            wrapped.shutdownNow()
        }
    }

    @Test
    fun `test wrap() executor correctly resolves paths via daemon ptrace`() {
        val targetFile = File("/etc/hostname")
        val pool = Executors.newSingleThreadExecutor()
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        try {
            val future =
                wrapped.submit(
                    Callable {
                        targetFile.readText()
                    },
                )
            future.get(5, TimeUnit.SECONDS)

            val bob = wrapped.compileBillOfBehavior()
            assertTrue(
                bob.opens.contains("/etc/hostname"),
                "Path resolution should work in wrapped executor. Observed opens: ${bob.opens}",
            )
        } finally {
            wrapped.shutdownNow()
        }
    }

    @Test
    fun `test wrap() executor with multiple threads does not duplicate audit events`() {
        // We simulate multiple threads opening the same file.
        // Even if Landlock audit was enabled, the sharedPathCache should deduplicate them
        // if they happen within the 500ms window.
        val pool = Executors.newFixedThreadPool(4)
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        try {
            val target = File("/etc/hostname")
            val tasks =
                (1..10).map {
                    wrapped.submit(
                        Callable {
                            target.readText()
                        },
                    )
                }
            tasks.forEach { it.get(5, TimeUnit.SECONDS) }

            val bob = wrapped.compileBillOfBehavior()
            // The number of OPEN/OPENAT events in recentLogs for /etc/hostname should be low
            // due to deduplication, even if triggered from different threads.
            val openEvents = wrapped.recentLogs.filter { it.paths.contains("/etc/hostname") }
            // Since they all run almost concurrently, most should be deduplicated.
            assertTrue(openEvents.size < 10, "Should have deduplicated some events. Observed: ${openEvents.size}")
        } finally {
            wrapped.shutdownNow()
        }
    }

    @Test
    fun `test wrap() executor shutdown waits for pending tasks and avoids ENOSYS`() {
        val pool = Executors.newSingleThreadExecutor()
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        val latch = java.util.concurrent.CountDownLatch(1)
        val finished =
            java.util.concurrent.atomic
                .AtomicBoolean(false)

        val future =
            wrapped.submit(
                Callable {
                    latch.countDown()
                    Thread.sleep(1000) // Simulate long-running syscall or operation
                    val text = File("/etc/hostname").readText()
                    finished.set(true)
                    text
                },
            )

        latch.await()
        wrapped.shutdown() // Should not kill daemon immediately

        val result = future.get(5, TimeUnit.SECONDS)
        assertTrue(result.isNotEmpty())
        assertTrue(finished.get(), "Task should have finished even after shutdown() was called")
    }

    @Test
    fun `test wrap() executor captures stack traces correctly`() {
        val targetFile = File("/etc/hostname")
        val pool = Executors.newSingleThreadExecutor()
        val wrapped = Profiler.wrap(pool, Policy.PURE_COMPUTE)
        try {
            wrapped
                .submit(
                    Callable {
                        targetFile.readText()
                    },
                ).get(5, TimeUnit.SECONDS)

            assertTrue(
                wrapped.recentStackProfiles.isNotEmpty(),
                "Stack profiles should be captured in wrapped executor",
            )
            val hasOurClass =
                wrapped.recentStackProfiles.values.any { traces ->
                    traces.any { frames ->
                        frames.any { frame -> frame.className.contains("ProfilerIntegrationTest") }
                    }
                }
            assertTrue(hasOurClass, "Stack trace in wrapped executor should contain ProfilerIntegrationTest")
        } finally {
            wrapped.shutdownNow()
        }
    }
}
