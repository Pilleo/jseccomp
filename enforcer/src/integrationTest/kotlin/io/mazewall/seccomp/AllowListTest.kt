package io.mazewall.seccomp

import io.mazewall.BaseIntegrationTest
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

class AllowListTest : BaseIntegrationTest() {
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
        // Force loading of classes and native symbols that PureJavaBpfEngine and
        // ContainedExecutors will reference AFTER the ALLOW_LIST filter is installed.
        // The ALLOW_LIST blocks openat (not in jvmFloor), so any class not yet loaded
        // before installation will cause ClassNotFoundException.
        // This is the legitimate use of pre-loading — targeted to THIS test's policy.
        io.mazewall.seccomp.SeccompInstallationState.Uninitialized
            .toString()
        io.mazewall.seccomp.SeccompInstallationState.PrivilegesLocked
            .toString()
        io.mazewall.seccomp.SeccompInstallationState.Verified
            .toString()
        io.mazewall.seccomp.SeccompInstallationState.SystemCallApplied
            .toString()
        io.mazewall.seccomp.SeccompInstallationState.FallbackPrctlApplied
            .toString()
        io.mazewall.seccomp.SeccompInstallationState.FilterBuilt::class.java
        io.mazewall.seccomp.SeccompInstallationState.Failed::class.java
        Arch.current()
        // Force native symbol linking for LinuxNative downcall stubs
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
                    if (result !is LinuxNative.SyscallResult.Error || result.errno != 1) {
                        throw IllegalStateException("Expected EPERM (1), got $result")
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
                        if (result !is LinuxNative.SyscallResult.Error || result.errno != 1) {
                            throw IllegalStateException("Expected EPERM (1) for mmap(PROT_EXEC), got $result")
                        }
                    }
                }.get()
        } finally {
            pool.shutdownNow()
        }
    }
}
