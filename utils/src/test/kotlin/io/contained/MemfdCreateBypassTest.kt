package io.contained

import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.ValueLayout
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MemfdCreateBypassTest {

    private val linker = Linker.nativeLinker()
    private val stdlib = linker.defaultLookup()

    private fun callMemfdCreate(): Int {
        val mh = linker.downcallHandle(
            stdlib.find("memfd_create").get(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
        )
        Arena.ofConfined().use { arena ->
            val name = arena.allocateFrom("bypass_test")
            return mh.invokeExact(name, 1) as Int
        }
    }

    private fun closeFd(fd: Int) {
        try {
            val mh = linker.downcallHandle(
                stdlib.find("close").get(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT)
            )
            mh.invokeExact(fd)
        } catch (_: Throwable) {}
    }

    @Test
    fun `memfd_create is callable on an uncontained thread`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val fdRef = AtomicInteger(-999)
        val errorRef = AtomicReference<Throwable>(null)

        val thread = Thread {
            try {
                val fd = callMemfdCreate()
                fdRef.set(fd)
                if (fd >= 0) closeFd(fd)
            } catch (e: Throwable) {
                errorRef.set(e)
            }
        }
        thread.start()
        thread.join()

        val err = errorRef.get()
        if (err != null) throw err

        if (fdRef.get() < 0) {
            println("WARNING: memfd_create returned ${fdRef.get()} on this system. " +
                "This may indicate seccomp filters are already active on the test runner. " +
            "Skipping assertion.")
            return
        }

        assertTrue(fdRef.get() >= 0, "memfd_create should succeed on uncontained thread, got fd=${fdRef.get()}")
    }

    @Test
    fun `NO_EXEC does not block memfd_create - demonstrating the bypass`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val fdRef = AtomicInteger(-999)
        val errorRef = AtomicReference<Throwable>(null)

        val thread = Thread {
            try {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
                val fd = callMemfdCreate()
                fdRef.set(fd)
                if (fd >= 0) closeFd(fd)
            } catch (e: Throwable) {
                errorRef.set(e)
            }
        }
        thread.start()
        thread.join()

        val err = errorRef.get()
        if (err != null) throw err

        assertTrue(fdRef.get() >= 0,
            "memfd_create succeeded under NO_EXEC (fd=${fdRef.get()}). " +
            "This demonstrates the bypass: NO_EXEC only blocks execve/execveat, " +
            "not memfd_create. An attacker can use memfd_create + mmap(PROT_EXEC) " +
            "to execute shellcode without calling execve. " +
            "Mitigation: block Syscall.MEMFD_CREATE in your policy.")
    }

    @Test
    fun `blocking MEMFD_CREATE makes memfd_create return error`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val policy = Policy.builder()
            .block(Syscall.EXECVE, Syscall.EXECVEAT, Syscall.FORK, Syscall.VFORK)
            .block(Syscall.MEMFD_CREATE)
            .build()

        val fdRef = AtomicInteger(-999)
        val errorRef = AtomicReference<Throwable>(null)

        val thread = Thread {
            try {
                ContainedExecutors.clearViolation()
                ContainedExecutors.installOnCurrentThread(policy)
                val fd = callMemfdCreate()
                val violated = ContainedExecutors.getLastViolationSyscall() != -1
                fdRef.set(if (violated) -1 else fd)
                if (fd >= 0 && !violated) closeFd(fd)
            } catch (e: Throwable) {
                errorRef.set(e)
            }
        }
        thread.start()
        thread.join()

        val err = errorRef.get()
        if (err != null) throw err

        assertTrue(fdRef.get() < 0,
            "memfd_create should fail when blocked, but got fd=${fdRef.get()}")
    }

    @Test
    fun `combine NO_EXEC with MEMFD_CREATE for robust code execution prevention`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val combined = Policy.combine(Policy.NO_EXEC, Policy.builder().block(Syscall.MEMFD_CREATE).build())

        val fdRef = AtomicInteger(-999)
        val errorRef = AtomicReference<Throwable>(null)

        val thread = Thread {
            try {
                ContainedExecutors.clearViolation()
                ContainedExecutors.installOnCurrentThread(combined)
                val fd = callMemfdCreate()
                val violated = ContainedExecutors.getLastViolationSyscall() != -1
                fdRef.set(if (violated) -1 else fd)
                if (fd >= 0 && !violated) closeFd(fd)
            } catch (e: Throwable) {
                errorRef.set(e)
            }
        }
        thread.start()
        thread.join()

        val err = errorRef.get()
        if (err != null) throw err

        assertTrue(fdRef.get() < 0,
            "memfd_create should fail with combined NO_EXEC + MEMFD_CREATE, but got fd=${fdRef.get()}")
    }

    @Test
    fun `execve is blocked by NO_EXEC policy via ContainedExecutors wrap`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        val future = safeExecutor.submit {
            Runtime.getRuntime().exec(arrayOf("echo", "hello"))
        }

        val ex = org.junit.jupiter.api.assertThrows<ExecutionException> {
            future.get()
        }

        assertTrue(ex.cause is ContainmentViolationException,
            "Expected ContainmentViolationException, got ${ex.cause}")

        executor.shutdown()
    }
}
