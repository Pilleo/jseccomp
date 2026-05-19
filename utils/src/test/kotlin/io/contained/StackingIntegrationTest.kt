package io.contained

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS

import kotlin.test.assertTrue

class StackingIntegrationTest {
    @Test
    fun `test filter stacking depth limit`() {
        if (!Platform.isSupported()) return

        // Explicit list of syscalls that are safe to block for depth-testing:
        // - No PRCTL (required for NO_NEW_PRIVS before each seccomp install)
        // - No MMAP / MPROTECT (required by JVM JIT and GC)
        // - No CLONE (required for JVM thread creation)
        // - No CLONE3 (must remain blockable via ENOSYS for the clone fallback to work)
        // Ordering is stable and independent of Syscall enum declaration order.
        val safeSyscalls = listOf(
            Syscall.EXECVE,   Syscall.EXECVEAT,  Syscall.FORK,           Syscall.VFORK,
            Syscall.CONNECT,  Syscall.SOCKET,    Syscall.BIND,           Syscall.LISTEN,
            Syscall.ACCEPT,   Syscall.ACCEPT4,   Syscall.SENDTO,         Syscall.SENDMSG,
            Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.BPF,  Syscall.PTRACE,
            Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV,
            Syscall.USERFAULTFD, Syscall.UNSHARE, Syscall.SETNS,
            Syscall.MOUNT,    Syscall.UMOUNT2,   Syscall.PIVOT_ROOT,     Syscall.CHROOT,
            Syscall.INIT_MODULE, Syscall.FINIT_MODULE,
            Syscall.GETPID,   Syscall.GETPPID,   Syscall.GETUID,
            Syscall.GETEUID,  Syscall.GETGID,    Syscall.GETEGID,
            Syscall.GETTID,   Syscall.GETCWD,    Syscall.UMASK
        )
        // Must have enough distinct entries to exceed the 32-filter limit
        check(safeSyscalls.size > 32) { "Need >32 distinct syscalls to test the depth limit" }

        var depthException: IllegalStateException? = null
        val t = Thread {
            try {
                // Install one new syscall block per iteration. Each is distinct, so the
                // incremental filter logic always adds a new BPF program to the kernel chain.
                for (syscall in safeSyscalls.take(34)) {
                    val policy = Policy.builder().block(syscall).build()
                    ContainedExecutors.installOnCurrentThread(policy)
                }
            } catch (e: IllegalStateException) {
                depthException = e
            }
        }
        t.start()
        t.join()

        val exception = depthException
        assertTrue(exception != null, "Expected IllegalStateException after 32 filters")
        val message = exception.message
        assertTrue(
            message != null && message.contains("Cannot install more than 32 seccomp filters"),
            "Unexpected exception message: $message"
        )
    }
}


