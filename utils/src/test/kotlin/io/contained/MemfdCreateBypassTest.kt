package io.contained

import java.lang.foreign.*
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class MemfdCreateBypassTest {

    private val arch = Arch.current()

    private fun callMemfdCreate(): Int {
        val linker = Linker.nativeLinker()
        val syscall = linker.downcallHandle(
            linker.defaultLookup().find("syscall").get(),
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
            Linker.Option.firstVariadicArg(1)
        )
        
        Arena.ofConfined().use { arena ->
            val name = arena.allocateFrom("test")
            val ret = syscall.invoke(arch.memfdCreate.toLong(), name, 0) as Long
            return ret.toInt()
        }
    }

    private fun closeFd(fd: Int) {
        val linker = Linker.nativeLinker()
        val close = linker.downcallHandle(
            linker.defaultLookup().find("close").get(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT)
        )
        close.invoke(fd)
    }

    @Test
    fun `NO_EXEC does not block memfd_create - demonstrating the bypass`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val fdRef = AtomicInteger(-999)
        val thread = Thread {
            try {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
                val fd = callMemfdCreate()
                fdRef.set(fd)
                if (fd >= 0) closeFd(fd)
            } catch (e: Throwable) {
                e.printStackTrace()
            }
        }
        thread.start()
        thread.join()

        assertTrue(fdRef.get() >= 0, 
            "memfd_create should succeed under NO_EXEC alone (the bypass), but got fd=${fdRef.get()}")
    }

    @Test
    fun `combine NO_EXEC with MEMFD_CREATE for robust code execution prevention`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val fdRef = AtomicInteger(-999)
        val combined = Policy.combine(Policy.NO_EXEC, Policy.builder().block(Syscall.MEMFD_CREATE).build())
        
        val thread = Thread {
            try {
                ContainedExecutors.installOnCurrentThread(combined)
                val fd = callMemfdCreate()
                fdRef.set(fd)
                if (fd >= 0) closeFd(fd)
            } catch (e: Throwable) {
                // Expected failure
                fdRef.set(-1)
            }
        }
        thread.start()
        thread.join()

        assertTrue(fdRef.get() < 0, 
            "memfd_create should fail with combined NO_EXEC + MEMFD_CREATE, but got fd=${fdRef.get()}")
    }

    @Test
    fun `blocking MEMFD_CREATE makes memfd_create return error`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!Platform.isSupported()) return

        val fdRef = AtomicInteger(-999)
        val policy = Policy.builder().block(Syscall.MEMFD_CREATE).build()
        
        val thread = Thread {
            try {
                ContainedExecutors.installOnCurrentThread(policy)
                val fd = callMemfdCreate()
                fdRef.set(fd)
                if (fd >= 0) closeFd(fd)
            } catch (e: Throwable) {
                fdRef.set(-1)
            }
        }
        thread.start()
        thread.join()

        assertTrue(fdRef.get() < 0, 
            "memfd_create should fail with MEMFD_CREATE block, but got fd=${fdRef.get()}")
    }
}
