package io.mazewall.seccomp

import io.mazewall.BaseIntegrationTest
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BpfHardeningTest : BaseIntegrationTest() {
    @Test
    fun `test that prctl can be blocked when inspection is explicitly disabled`() {
        val policy =
            Policy
                .builder()
                .allowUnsafePrctl() // Disable argument inspection (previously would cause PRCTL to be skipped in block list)
                .block(Syscall.PRCTL) // Explicitly block it
                .build()

        val result = AtomicReference<LinuxNative.SyscallResult>()
        val error = AtomicReference<Throwable>()

        val thread =
            Thread {
                try {
                    ContainedExecutors.installOnCurrentThread(policy)
                    // PR_SET_NAME = 15
                    val res = LinuxNative.prctl(15, 0, 0, 0, 0)
                    result.set(res)
                } catch (t: Throwable) {
                    error.set(t)
                }
            }
        thread.start()
        thread.join()

        if (error.get() != null) throw error.get()

        val res = result.get()
        assertTrue(res is LinuxNative.SyscallResult.Error && res.errno == 1, "PRCTL should have been blocked with EPERM, got $res")
    }

    @Test
    fun `test that mmap can be blocked when mmap exec inspection is disabled`() {
        val policy =
            Policy
                .builder()
                .allowMmapExec() // Disable mmap inspection (previously would cause MMAP to be skipped in block list)
                .block(Syscall.MMAP) // Explicitly block it
                .build()

        val result = AtomicReference<LinuxNative.SyscallResult>()
        val error = AtomicReference<Throwable>()

        val thread =
            Thread {
                try {
                    ContainedExecutors.installOnCurrentThread(policy)
                    // We don't call mmap directly via FFM here because it's hard to set up the arguments safely,
                    // so we use the generic syscall(2) downcall.
                    val arch = io.mazewall.core.Arch
                        .current()
                    val res = LinuxNative.syscall(arch.mmap.toLong(), 0, 4096, 1, 2, -1, 0)
                    result.set(res)
                } catch (t: Throwable) {
                    error.set(t)
                }
            }
        thread.start()
        thread.join()

        if (error.get() != null) throw error.get()

        val res = result.get()
        assertTrue(res is LinuxNative.SyscallResult.Error && res.errno == 1, "MMAP should have been blocked with EPERM, got $res")
    }
}
