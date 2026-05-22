package io.contained

import org.junit.jupiter.api.Test
import io.contained.EnabledIfLinuxAndSupported
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.lang.foreign.MemorySegment
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@EnabledIfLinuxAndSupported
class LinuxNativeTest {

    @Test
    fun testPrctlGetSeccomp() {
        val result = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
        // Usually returns 0 or 2, unless error
        assertTrue(result.returnValue >= 0)
    }

    @Test
    fun testToLongError() {
        assertFailsWith<IllegalArgumentException> {
            // String is not a supported type for toLong()
            LinuxNative.prctl(LinuxNative.PR_SET_NAME, "string-not-allowed")
        }
    }

    @Test
    fun testSockFilterBoundsValidation() {
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, 256.toShort(), 0.toShort(), 0)
        }
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, (-1).toShort(), 0.toShort(), 0)
        }
        assertFailsWith<IllegalArgumentException> {
            SockFilter(0, 0.toShort(), 256.toShort(), 0)
        }
        // Valid bounds should not throw
        SockFilter(0, 0.toShort(), 255.toShort(), 0)
    }

    @Test
    fun testBasicSyscalls() {
        Arena.ofConfined().use { arena ->
            // test open/close/read/write on a temp file
            val tempFile = java.nio.file.Files.createTempFile("native-test", ".txt")
            val path = arena.allocateFrom(tempFile.toString())

            val openResult = LinuxNative.open(path, 0) // O_RDONLY
            assertTrue(openResult.returnValue >= 0, "open failed with errno ${openResult.errno}")
            val fd = openResult.returnValue.toInt()

            val buffer = arena.allocate(1024)
            val readResult = LinuxNative.read(fd, buffer, 1024)
            assertTrue(readResult.returnValue >= 0)

            val closeResult = LinuxNative.close(fd)
            assertEquals(0, closeResult.returnValue)

            tempFile.toFile().delete()
        }
    }

    @Test
    fun testLayoutAccessors() {
        LinuxNative.ERRNO_LAYOUT
        LinuxNative.SOCK_FILTER_LAYOUT
        LinuxNative.SOCK_FPROG_LAYOUT
        LinuxNative.IOVEC_LAYOUT
        LinuxNative.MSGHDR_LAYOUT
        LinuxNative.CMSGHDR_LAYOUT
        LinuxNative.SOCKADDR_UN_LAYOUT
        LinuxNative.NLMSGHDR_LAYOUT
        LinuxNative.SECCOMP_DATA_LAYOUT
        LinuxNative.SECCOMP_NOTIF_LAYOUT
        LinuxNative.SECCOMP_NOTIF_RESP_LAYOUT
        LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT
        LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_LAYOUT
    }

    @Test
    fun testSocketSyscalls() {
        // test socket()
        val socketResult = LinuxNative.socket(2, 1, 0) // AF_INET, SOCK_STREAM
        if (socketResult.returnValue >= 0) {
            val fd = socketResult.returnValue.toInt()

            // test bind (to a random port)
            Arena.ofConfined().use { arena ->
                val addr = arena.allocate(16) // struct sockaddr_in
                LinuxNative.bind(fd, addr, 16)
            }

            LinuxNative.listen(fd, 5)
            LinuxNative.close(fd)
        }
    }

    @Test
    fun testSocketpair() {
        Arena.ofConfined().use { arena ->
            val fds = arena.allocate(ValueLayout.JAVA_INT, 2)
            val result = LinuxNative.socketpair(1, 1, 0, fds) // AF_UNIX, SOCK_STREAM
            if (result.returnValue == 0L) {
                LinuxNative.close(fds.get(ValueLayout.JAVA_INT, 0))
                LinuxNative.close(fds.get(ValueLayout.JAVA_INT, 4))
            }
        }
    }

    @Test
    fun testProcessVmReadv() {
        Arena.ofConfined().use { arena ->
            // Try reading from our own memory
            val localBuf = arena.allocate(10)
            localBuf.set(ValueLayout.JAVA_BYTE, 0, 123)

            val remoteIovec = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            remoteIovec.set(ValueLayout.ADDRESS, 0, localBuf)
            remoteIovec.set(ValueLayout.JAVA_LONG, 8, 10)

            val localIovec = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            val destBuf = arena.allocate(10)
            localIovec.set(ValueLayout.ADDRESS, 0, destBuf)
            localIovec.set(ValueLayout.JAVA_LONG, 8, 10)

            val result = LinuxNative.processVmReadv(
                ProcessHandle.current().pid().toInt(),
                localIovec, 1,
                remoteIovec, 1,
                0 // flags
            )
        }
    }

    @Test
    fun testFcntl() {
        Arena.ofConfined().use { arena ->
            val tempFile = java.nio.file.Files.createTempFile("fcntl-test", ".txt")
            val path = arena.allocateFrom(tempFile.toString())
            val openResult = LinuxNative.open(path, 0)
            val fd = openResult.returnValue.toInt()

            val flags = LinuxNative.fcntl(fd, 3, 0) // F_GETFL
            assertTrue(flags.returnValue >= 0)

            LinuxNative.close(fd)
            tempFile.toFile().delete()
        }
    }

    @Test
    fun testReadlink() {
        Arena.ofConfined().use { arena ->
            val path = arena.allocateFrom("/proc/self/exe")
            val buffer = arena.allocate(1024)
            val result = LinuxNative.readlink(path, buffer, 1024)
            assertTrue(result.returnValue >= 0)
        }
    }
}
