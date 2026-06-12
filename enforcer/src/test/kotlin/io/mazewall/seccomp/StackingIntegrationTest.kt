package io.mazewall.seccomp

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.IsolatedProcessTester
import io.mazewall.Policy
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class StackingIntegrationTest {
    fun testDepthLimit() {
        val safeSyscalls =
            listOf(
                Syscall.EXECVE,
                Syscall.EXECVEAT,
                Syscall.FORK,
                Syscall.VFORK,
                Syscall.CONNECT,
                Syscall.SOCKET,
                Syscall.BIND,
                Syscall.LISTEN,
                Syscall.ACCEPT,
                Syscall.ACCEPT4,
                Syscall.SENDTO,
                Syscall.SENDMSG,
                Syscall.MEMFD_CREATE,
                Syscall.IO_URING_SETUP,
                Syscall.BPF,
                Syscall.PTRACE,
                Syscall.PROCESS_VM_WRITEV,
                Syscall.PROCESS_VM_READV,
                Syscall.USERFAULTFD,
                Syscall.UNSHARE,
                Syscall.SETNS,
                Syscall.MOUNT,
                Syscall.UMOUNT2,
                Syscall.PIVOT_ROOT,
                Syscall.CHROOT,
                Syscall.INIT_MODULE,
                Syscall.FINIT_MODULE,
                Syscall.GETPID,
                Syscall.GETPPID,
                Syscall.GETUID,
                Syscall.GETEUID,
                Syscall.GETGID,
                Syscall.GETEGID,
                Syscall.GETTID,
                Syscall.GETCWD,
                Syscall.UMASK,
            )

        for (syscall in safeSyscalls.take(34)) {
            val policy =
                Policy
                    .builder()
                    .block(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
                    .block(syscall)
                    .build()
            ContainedExecutors.installOnCurrentThread(policy)
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test filter stacking depth limit`() {
        // We expect the isolated runner to FAIL because it exceeds the 32-filter limit.
        // IsolatedProcessTester.runIsolatedTest/runIsolatedMethod throws IllegalStateException
        // if the child process exit code is non-zero.
        val ex = org.junit.jupiter.api.assertThrows<IllegalStateException> {
            IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testDepthLimit")
        }
        assertTrue(ex.message!!.contains("Isolated test process failed with exit code 2"), "Expected exit code 2 due to IllegalStateException in child process, but got: ${ex.message}")
    }
}
