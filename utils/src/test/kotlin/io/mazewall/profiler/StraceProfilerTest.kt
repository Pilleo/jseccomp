package io.mazewall.profiler

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.assertTrue

@EnabledIfLinuxAndSupported
class StraceProfilerTest {
    class FileReadWorkload : TraceableWorkload {
        override fun run() {
            File("/etc/hostname").readText()
        }
    }

    class FileWriteWorkload : TraceableWorkload {
        override fun run() {
            val file = File("/tmp/strace_test_write.txt").absoluteFile
            file.writeText("strace write test content")
            file.delete()
        }
    }

    class NetworkWorkload : TraceableWorkload {
        override fun run() {
            val server = ServerSocket(0)
            val port = server.localPort
            val thread = Thread {
                try {
                    val client = server.accept()
                    client.close()
                } catch (ignored: Exception) {
                }
            }
            thread.start()
            val socket = Socket("127.0.0.1", port)
            socket.close()
            server.close()
            thread.join()
        }
    }

    class MissingFileReadWorkload : TraceableWorkload {
        override fun run() {
            try {
                File("/tmp/iterative_missing_strace/does_not_exist.txt").readText()
            } catch (ignored: Exception) {
            }
        }
    }

    @Test
    fun `test strace profiling of filesystem reads`() {
        val bob = StraceProfiler.profile(FileReadWorkload::class.java)
        assertTrue(
            bob.syscalls.contains(Syscall.OPEN) ||
            bob.syscalls.contains(Syscall.OPENAT) ||
            bob.syscalls.contains(Syscall.OPENAT2),
            "Should capture open syscall. Observed: ${bob.syscalls}",
        )
        assertTrue(bob.opens.contains("/etc/hostname"), "Should contain read path /etc/hostname. Observed: ${bob.opens}")
    }

    @Test
    fun `test strace profiling of filesystem writes`() {
        val bob = StraceProfiler.profile(FileWriteWorkload::class.java)
        assertTrue(
            bob.syscalls.contains(Syscall.OPEN) ||
            bob.syscalls.contains(Syscall.OPENAT) ||
            bob.syscalls.contains(Syscall.OPENAT2) ||
            bob.syscalls.contains(Syscall.WRITE),
            "Should capture write/open syscalls. Observed: ${bob.syscalls}",
        )
        assertTrue(
            bob.fsWritePaths.contains("/tmp/strace_test_write.txt"),
            "Should contain write path. Observed: ${bob.fsWritePaths}",
        )
    }

    @Test
    fun `test strace profiling of network connections`() {
        val bob = StraceProfiler.profile(NetworkWorkload::class.java)
        assertTrue(bob.syscalls.contains(Syscall.SOCKET), "Should capture socket syscall. Observed: ${bob.syscalls}")
        assertTrue(bob.syscalls.contains(Syscall.CONNECT), "Should capture connect syscall. Observed: ${bob.syscalls}")
    }

    @Test
    fun `test strace profiling of missing file reads`() {
        val bob = StraceProfiler.profile(MissingFileReadWorkload::class.java)
        assertTrue(
            bob.opens.contains("/tmp/iterative_missing_strace/does_not_exist.txt"),
            "Should capture read path of missing file even on failure. Observed: ${bob.opens}",
        )
        assertTrue(
            !bob.fsWritePaths.contains("/tmp/iterative_missing_strace/does_not_exist.txt"),
            "Should NOT grant write permission for missing file read. Observed: ${bob.fsWritePaths}",
        )
    }
}
