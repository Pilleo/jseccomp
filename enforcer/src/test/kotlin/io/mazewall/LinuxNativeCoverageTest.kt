package io.mazewall

import io.mazewall.ffi.Layouts
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import kotlin.test.*

class LinuxNativeCoverageTest {
    @AfterEach
    fun tearDown() {
        LinuxNative.resetToDefault()
    }

    @Test
    fun `test data class methods for SyscallResult`() {
        val res1 = LinuxNative.SyscallResult(100, 0)
        val res2 = LinuxNative.SyscallResult(100, 0)
        val res3 = LinuxNative.SyscallResult(200, 1)

        assertEquals(res1, res2)
        assertNotEquals(res1, res3)
        assertEquals(res1.hashCode(), res2.hashCode())
        assertNotNull(res1.toString())
        assertEquals(100L, res1.returnValue)
        assertEquals(0, res1.errno)
    }

    @Test
    fun `test data class methods for SockFilter`() {
        val f1 = SockFilter(1, 2, 3, 4)
        val f2 = SockFilter(1, 2, 3, 4)
        val f3 = SockFilter(1, 0, 0, 0)

        assertEquals(f1, f2)
        assertNotEquals(f1, f3)
        assertEquals(f1.hashCode(), f2.hashCode())
        assertNotNull(f1.toString())
        assertEquals(1, f1.code.toInt())
        assertEquals(2, f1.jt.toInt())
        assertEquals(3, f1.jf.toInt())
        assertEquals(4, f1.k)
    }

    @Test
    fun `test LinuxNative engine delegation getters`() {
        assertNotNull(LinuxNative.getFileSystem())
        assertNotNull(LinuxNative.getNetworking())
        assertNotNull(LinuxNative.getProcess())
        assertNotNull(LinuxNative.getMemory())
    }

    @Test
    fun `test LinuxNative syscall4 delegate`() {
        val mock = MockNativeEngine()
        mock.syscallResult = LinuxNative.SyscallResult(444, 0)
        LinuxNative.setEngine(mock)

        val res = LinuxNative.syscall4(1, 2, 3, 4, 5)
        assertEquals(444L, res.returnValue)
    }

    @Test
    fun `test toLong branches`() {
        // We use LinuxNative methods to test the actual implementation of toLong() in RealNativeEngine
        // null branch
        LinuxNative.syscall(-1, null, null, null, null, null, null)

        // MemorySegment branch
        Arena.ofConfined().use { arena ->
            val seg = arena.allocate(8)
            LinuxNative.syscall(-1, seg, 1, 2, 3, 4, 5)
        }
    }

    @Test
    fun `test toLong failure path`() {
        assertFailsWith<IllegalArgumentException> {
            // Use a type that is not Number or MemorySegment
            LinuxNative.syscall(-1, Any())
        }
    }

    @Test
    @EnabledIfLinuxAndSupported
    fun `test newSockFProg manual packing`() {
        Arena.ofConfined().use { arena ->
            val filters = arrayOf(
                SockFilter(0x01, 2, 3, 0x12345678),
                SockFilter(0x05, 0, 0, 0x00000001),
            )
            val prog = LinuxNative.newSockFProg(arena, filters)
            assertNotNull(prog)

            assertEquals(2, prog.get(ValueLayout.JAVA_SHORT, Layouts.SOCK_FPROG_LEN_OFFSET).toInt())
            val filterArrayRaw = prog.get(ValueLayout.ADDRESS, Layouts.SOCK_FPROG_FILTER_OFFSET)
            val filterArray = filterArrayRaw.reinterpret(Layouts.SOCK_FILTER_SIZE * 2)

            // Verify first filter
            assertEquals(0x01.toShort(), filterArray.get(ValueLayout.JAVA_SHORT, 0))
            assertEquals(2.toByte(), filterArray.get(ValueLayout.JAVA_BYTE, 2))
            assertEquals(3.toByte(), filterArray.get(ValueLayout.JAVA_BYTE, 3))
            assertEquals(0x12345678, filterArray.get(ValueLayout.JAVA_INT, 4))
        }
    }

    @Test
    fun `test missing syscall wrappers in LinuxNative`() {
        val mock = MockNativeEngine()
        LinuxNative.setEngine(mock)

        Arena.ofConfined().use { arena ->
            val seg = arena.allocate(8)

            mock.acceptResult = LinuxNative.SyscallResult(10, 0)
            assertEquals(10L, LinuxNative.accept(1, seg, seg).returnValue)

            mock.sendmsgResult = LinuxNative.SyscallResult(20, 0)
            assertEquals(20L, LinuxNative.sendmsg(1, seg, 0).returnValue)

            mock.recvmsgResult = LinuxNative.SyscallResult(30, 0)
            assertEquals(30L, LinuxNative.recvmsg(1, seg, 0).returnValue)

            mock.ioctlResult = LinuxNative.SyscallResult(40, 0)
            assertEquals(40L, LinuxNative.ioctl(1, 2L, seg).returnValue)
            assertEquals(40L, LinuxNative.ioctl(1, 2L, 3L).returnValue)

            mock.recvResult = LinuxNative.SyscallResult(50, 0)
            assertEquals(50L, LinuxNative.recv(1, seg, 8L, 0).returnValue)

            assertEquals(1234, LinuxNative.gettid())
        }
    }
}
