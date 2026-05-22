package io.contained

import io.contained.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.util.concurrent.Executors
import kotlin.test.assertTrue

class MemfdCreateBypassTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `NO_EXEC blocks memfd_create as of recent security update`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        try {
            executor.submit {
                ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)

                val arch = Arch.current()
                // memfd_create IS blocked by NO_EXEC
                val res = java.lang.foreign.Arena.ofConfined().use { arena ->
                    val name = arena.allocateFrom("test_memfd")
                    LinuxNative.syscall(arch.memfdCreate.toLong(), name.address(), 0, java.lang.foreign.MemorySegment.NULL)
                }
                assertTrue(res.returnValue < 0, "memfd_create should be blocked by NO_EXEC")
                assertTrue(res.errno == LinuxNative.EPERM, "Expected EPERM, got ${res.errno}")
            }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `memfd_create is blocked when explicitly added to policy`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        try {
            executor.submit {
                val combined = Policy.builder()
                    .block(Syscall.MEMFD_CREATE)
                    .build()
                
                ContainedExecutors.installOnCurrentThread(combined)

                val arch = Arch.current()
                val res = java.lang.foreign.Arena.ofConfined().use { arena ->
                    val name = arena.allocateFrom("test_memfd_blocked")
                    LinuxNative.syscall(arch.memfdCreate.toLong(), name.address(), 0, java.lang.foreign.MemorySegment.NULL)
                }
                assertTrue(res.returnValue < 0, "memfd_create should be blocked")
                assertTrue(res.errno == LinuxNative.EPERM, "Expected EPERM, got ${res.errno}")
            }.get()
        } finally {
            executor.shutdown()
        }
    }
}
