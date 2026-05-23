package io.mazewall.seccomp

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.IsolatedProcessTester
import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.Syscall
import io.mazewall.enforcer.ContainedExecutors
import org.junit.jupiter.api.Test
import java.nio.channels.Selector

/**
 * Helper object used to run seccomp installation tests in an isolated JVM process.
 * This prevents the Gradle Test Worker from being permanently "poisoned" by
 * irreversible seccomp filters.
 */
object SeccompIsolatedTestApp {
    @JvmStatic
    fun main(args: Array<String>) {
        if (!Platform.isSupported()) System.exit(0)

        val mode = args.firstOrNull() ?: "process-wide"
        try {
            when (mode) {
                "process-wide" -> testProcessWide()
                "thread-depth" -> testThreadDepth()
                "inheritance" -> testInheritance()
                "nio-stability" -> testNioStability()
                else -> System.exit(1)
            }
            System.exit(0)
        } catch (e: Throwable) {
            e.printStackTrace()
            System.exit(2)
        }
    }

    private fun testProcessWide() {
        val safeGlobalPolicy = Policy.builder()
            .block(Syscall.EXECVE, Syscall.EXECVEAT, Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
            .allowMmapExec()
            .allowNonThreadClone()
            .build()

        ContainedExecutors.installOnProcess(safeGlobalPolicy)
        try {
            ProcessBuilder("echo", "should-fail").start()
            throw IllegalStateException("Should have failed")
        } catch (e: Exception) {
            if (!ContainedExecutors.isContainmentViolation(e)) {
                throw e
            }
        }
    }

    private fun testInheritance() {
        ContainedExecutors.installOnProcess(Policy.NO_EXEC)

        val thread = Thread {
            try {
                ProcessBuilder("echo", "should-fail").start()
                throw IllegalStateException("Child thread should have been contained")
            } catch (e: Exception) {
                if (!ContainedExecutors.isContainmentViolation(e)) {
                    throw e
                }
            }
        }
        thread.start()
        thread.join()
    }

    private fun testNioStability() {
        // Warm up NIO and Networking before installing the filter.
        // This ensures libextnet.so, libnio.so and other dependencies are loaded,
        // avoiding UnsatisfiedLinkError when mmap(PROT_EXEC) is blocked later.
        Selector.open().close()
        try {
            java.net.Socket().connect(java.net.InetSocketAddress("127.0.0.1", 1), 1)
        } catch (e: Exception) {
            // Expected to fail or timeout, just need to trigger library loading
        }

        // Process-wide NO_NETWORK (blocks bind, listen, accept, connect, etc.)
        ContainedExecutors.installOnProcess(Policy.NO_NETWORK)

        // NIO Selector uses epoll_create/epoll_ctl under the hood on Linux.
        // These should NOT be blocked by NO_NETWORK.
        val selector = Selector.open()
        selector.close()

        // Verify that network calls are actually blocked
        try {
            java.net.Socket().connect(java.net.InetSocketAddress("127.0.0.1", 80))
            throw IllegalStateException("Connect should have failed")
        } catch (e: Exception) {
            if (!ContainedExecutors.isContainmentViolation(e)) {
                throw e
            }
        }
    }

    private fun testThreadDepth() {
        val safeSyscalls = listOf(
            Syscall.EXECVE, Syscall.EXECVEAT, Syscall.FORK, Syscall.VFORK,
            Syscall.CONNECT, Syscall.SOCKET, Syscall.BIND, Syscall.LISTEN,
            Syscall.ACCEPT, Syscall.ACCEPT4, Syscall.SENDTO, Syscall.SENDMSG,
            Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.BPF, Syscall.PTRACE,
            Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV,
            Syscall.USERFAULTFD, Syscall.UNSHARE, Syscall.SETNS,
            Syscall.MOUNT, Syscall.UMOUNT2, Syscall.PIVOT_ROOT, Syscall.CHROOT,
            Syscall.INIT_MODULE, Syscall.FINIT_MODULE,
            Syscall.GETPID, Syscall.GETPPID, Syscall.GETUID,
            Syscall.GETEUID, Syscall.GETGID, Syscall.GETEGID,
            Syscall.GETTID, Syscall.GETCWD, Syscall.UMASK
        )

        for (i in 0 until 32) {
            ContainedExecutors.installOnCurrentThread(
                Policy.builder().block(safeSyscalls[i]).allowMmapExec().allowNonThreadClone().build()
            )
        }

        try {
            ContainedExecutors.installOnCurrentThread(
                Policy.builder().block(safeSyscalls[32]).allowMmapExec().allowNonThreadClone().build()
            )
            throw IllegalStateException("Should have failed")
        } catch (e: IllegalStateException) {
            if (!e.message!!.contains("32 seccomp filters")) {
                throw e
            }
        }
    }
}

class ProcessContainmentTest {

    @Test
    @EnabledIfLinuxAndSupported
    fun `installOnProcess applies containment globally`() {
        IsolatedProcessTester.runIsolatedTest("io.mazewall.seccomp.SeccompIsolatedTestApp", "process-wide")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `subsequent threads inherit process-wide filter`() {
        IsolatedProcessTester.runIsolatedTest("io.mazewall.seccomp.SeccompIsolatedTestApp", "inheritance")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `process-wide NO_NETWORK does not break NIO selector`() {
        IsolatedProcessTester.runIsolatedTest("io.mazewall.seccomp.SeccompIsolatedTestApp", "nio-stability")
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `thread-local installation respects filter depth`() {
        IsolatedProcessTester.runIsolatedTest("io.mazewall.seccomp.SeccompIsolatedTestApp", "thread-depth")
    }
}
