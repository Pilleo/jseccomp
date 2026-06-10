package io.mazewall.seccomp

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

@EnabledIfLinuxAndSupported
class AllowListTest {
    private fun jvmFloor(): Array<Syscall> =
        arrayOf(
            Syscall.WRITE,
            Syscall.EXIT,
            Syscall.EXIT_GROUP,
            Syscall.FUTEX,
            Syscall.RT_SIGRETURN,
            Syscall.SCHED_YIELD,
            Syscall.MADVISE,
            Syscall.MMAP,
            Syscall.MPROTECT,
            Syscall.MUNMAP,
            Syscall.GETTID,
            Syscall.GETPID,
            Syscall.CLOCK_GETTIME,
            Syscall.PRCTL,
            Syscall.READ,
            Syscall.FSTAT,
            Syscall.LSEEK,
            Syscall.CLOSE,
            Syscall.BRK,
            Syscall.FSTATAT,
            Syscall.STATX,
            Syscall.RT_SIGACTION,
            Syscall.RT_SIGPROCMASK,
            Syscall.GETRANDOM,
            Syscall.FCNTL,
        )

    private fun preWarm() {
        // Force loading of classes and native symbols
        LinuxNative.socket(2, 1, 0)
        val mmap = Arch.current().mmap.toLong()
        if (mmap >= 0) {
            LinuxNative.syscall(mmap, 0, 4096, 0, 0x22, -1, 0)
        }
    }

    @Test
    fun `ALLOW_LIST mode blocks unlisted syscalls`() {
        val pool = Executors.newSingleThreadExecutor()
        try {
            pool
                .submit {
                    preWarm()

                    val policy =
                        Policy
                            .builder()
                            .defaultAction(io.mazewall.core.SeccompAction.ACT_ERRNO)
                            .allow(*jvmFloor())
                            .build()

                    ContainedExecutors.installOnCurrentThread(policy)

                    // socket() is NOT allowed, should fail with EPERM
                    val result = LinuxNative.socket(2, 1, 0)
                    if (result.returnValue != -1L || result.errno != 1) {
                        throw IllegalStateException("Expected EPERM (1), got returnValue=${result.returnValue}, errno=${result.errno}")
                    }
                }.get()
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `ALLOW_LIST mode still blocks unsafe arguments even if syscall is allowed`() {
        val pool = Executors.newSingleThreadExecutor()
        try {
            pool
                .submit {
                    preWarm()

                    val policy =
                        Policy
                            .builder()
                            .defaultAction(io.mazewall.core.SeccompAction.ACT_ERRNO)
                            .allow(*jvmFloor())
                            .build()

                    ContainedExecutors.installOnCurrentThread(policy)

                    // mmap with PROT_EXEC should fail even though MMAP is allowed
                    val mmap = Arch.current().mmap.toLong()
                    if (mmap >= 0) {
                        val result = LinuxNative.syscall(mmap, 0, 4096, 0x04 /* PROT_EXEC */, 0x22, -1, 0)
                        if (result.returnValue != -1L || result.errno != 1) {
                            throw IllegalStateException(
                                "Expected EPERM (1) for mmap(PROT_EXEC), got returnValue=${result.returnValue}, errno=${result.errno}",
                            )
                        }
                    }
                }.get()
        } finally {
            pool.shutdownNow()
        }
    }
}
