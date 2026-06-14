package io.mazewall.seccomp

import io.mazewall.BaseIntegrationTest
import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.ffi.NativeConstants
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import kotlin.test.assertTrue

class MemfdCreateBypassTest : BaseIntegrationTest() {
    @Test
    @EnabledIfLinuxAndSupported
    fun `NO_EXEC blocks memfd_create as of recent security update`() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            executor
                .submit {
                    ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)

                    val arch = Arch.current()
                    // memfd_create IS blocked by NO_EXEC
                    val res =
                        java.lang.foreign.Arena.ofConfined().use { arena ->
                            val name = arena.allocateFrom("test_memfd")
                            LinuxNative.syscall(
                                arch.memfdCreate.toLong(),
                                name.address(),
                                0,
                                java.lang.foreign.MemorySegment.NULL,
                            )
                        }
                    assertTrue(res is LinuxNative.SyscallResult.Error && res.errno == NativeConstants.EPERM, "Expected EPERM, got $res")
                }.get()
        } finally {
            executor.shutdown()
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `memfd_create is blocked when explicitly added to policy`() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            executor
                .submit {
                    val combined =
                        Policy
                            .builder()
                            .block(Syscall.MEMFD_CREATE)
                            .build()

                    ContainedExecutors.installOnCurrentThread(combined)

                    val arch = Arch.current()
                    val res =
                        java.lang.foreign.Arena.ofConfined().use { arena ->
                            val name = arena.allocateFrom("test_memfd_blocked")
                            LinuxNative.syscall(
                                arch.memfdCreate.toLong(),
                                name.address(),
                                0,
                                java.lang.foreign.MemorySegment.NULL,
                            )
                        }
                    assertTrue(res is LinuxNative.SyscallResult.Error && res.errno == NativeConstants.EPERM, "Expected EPERM, got $res")
                }.get()
        } finally {
            executor.shutdown()
        }
    }
}
