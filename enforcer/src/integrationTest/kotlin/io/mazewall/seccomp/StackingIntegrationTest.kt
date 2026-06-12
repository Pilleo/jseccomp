package io.mazewall.seccomp

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.IsolatedProcessTester
import io.mazewall.Policy
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test

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

        try {
            // We try to install 34 filters. Kernel limit is 32.
            for (syscall in safeSyscalls.take(34)) {
                val policy =
                    Policy
                        .builder()
                        .block(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
                        .block(syscall)
                        .build()
                ContainedExecutors.installOnCurrentThread(policy)
            }
            // If we reach here, the kernel didn't enforce the limit (or we miscounted)
            System.err.println("[TEST ERROR] Successfully installed 34 filters, but limit is 32.")
            System.exit(1)
        } catch (e: Throwable) {
            val msg = e.message ?: ""
            if (msg.contains("32 seccomp filters")) {
                // Success - we hit the limit as expected.
                System.out.println("[TEST OK] Hit filter limit as expected: $msg")
                return
            }
            System.err.println("[TEST ERROR] Caught unexpected exception during depth limit test: ${e.javaClass.name}: $msg")
            e.printStackTrace(System.err)
            System.exit(2)
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test filter stacking depth limit`() {
        // Now the isolated method handles the exception itself and exits with 0 on success.
        IsolatedProcessTester.runIsolatedMethod(this::class.java.name, "testDepthLimit")
    }
}
