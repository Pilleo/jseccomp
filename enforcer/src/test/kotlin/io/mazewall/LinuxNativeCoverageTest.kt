package io.mazewall

import io.mazewall.ffi.Layouts
import io.mazewall.seccomp.BpfInstruction
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
        val res1 = LinuxNative.SyscallResult.Success(100)
        val res2 = LinuxNative.SyscallResult.Success(100)
        val res3 = LinuxNative.SyscallResult.Error(1, 200)

        assertEquals(res1, res2)
        assertNotEquals<LinuxNative.SyscallResult>(res1, res3)
        assertEquals(res1.hashCode(), res2.hashCode())
        assertNotNull(res1.toString())
        assertEquals(100L, res1.value)
        assertEquals(1, (res3 as LinuxNative.SyscallResult.Error).errno)
        assertEquals(200L, res3.rawValue)
    }

    @Test
    fun `test FileDescriptor methods`() {
        val fd1 = LinuxNative.FileDescriptor(10)
        val fd2 = LinuxNative.FileDescriptor(10)
        val fd3 = LinuxNative.FileDescriptor(-1)

        assertEquals(fd1, fd2)
        assertNotEquals(fd1, fd3)
        assertTrue(fd1.isValid)
        assertTrue(fd3.isInvalid)
        assertEquals("fd(10)", fd1.toString())
        assertEquals("fd(INVALID)", fd3.toString())
    }

    @Test
    fun `test data class methods for BpfInstruction`() {
        val f1 = BpfInstruction.Jmp(1, 2, 3, 4)
        val f2 = BpfInstruction.Jmp(1, 2, 3, 4)
        val f3 = BpfInstruction.Jmp(1, 0, 0, 0)

        assertEquals(f1, f2)
        assertNotEquals(f1, f3)
        assertEquals(f1.hashCode(), f2.hashCode())
        assertNotNull(f1.toString())
        assertEquals(1, f1.code.toInt())
        assertEquals(2, f1.jt.toInt())
        assertEquals(3, f1.jf.toInt())
        assertEquals(4, f1.k)

        val l1 = BpfInstruction.Ld(0x20, 0x1234)
        assertEquals(0x20.toShort(), l1.code)
        assertEquals(0, l1.jt.toInt())
        assertEquals(0, l1.jf.toInt())
        assertEquals(0x1234, l1.k)
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
        mock.syscallResult = LinuxNative.SyscallResult.Success(444)
        LinuxNative.setEngine(mock)

        val res = LinuxNative.syscall4(1, 2, 3, 4, 5)
        assertEquals(444L, res.getOrThrow("test"))
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
            val filters = listOf(
                BpfInstruction.Jmp(0x01, 2, 3, 0x12345678),
                BpfInstruction.Ld(0x05, 0x00000001),
            )
            val prog = with(arena) { LinuxNative.newSockFProg(filters) }
            assertNotNull(prog)

            assertEquals(2, prog.get(ValueLayout.JAVA_SHORT, Layouts.SOCK_FPROG_LEN_OFFSET).toInt())
            val filterArrayRaw = prog.get(ValueLayout.ADDRESS, Layouts.SOCK_FPROG_FILTER_OFFSET)
            val filterArray = filterArrayRaw.reinterpret(Layouts.SOCK_FILTER_SIZE * 2)

            // Verify first filter
            assertEquals(0x01.toShort(), filterArray.get(ValueLayout.JAVA_SHORT, 0))
            assertEquals(2, filterArray.get(ValueLayout.JAVA_BYTE, 2).toInt())
            assertEquals(3, filterArray.get(ValueLayout.JAVA_BYTE, 3).toInt())
            assertEquals(0x12345678, filterArray.get(ValueLayout.JAVA_INT, 4))
        }
    }


    @Test
    fun `test missing syscall wrappers in LinuxNative`() {
        val mock = MockNativeEngine()
        LinuxNative.setEngine(mock)

        Arena.ofConfined().use { arena ->
            val seg = arena.allocate(8)
            val fd = LinuxNative.FileDescriptor(1)

            mock.acceptResult = LinuxNative.SyscallResult.Success(10)
            assertEquals(10L, LinuxNative.accept(fd, seg, seg).getOrThrow("test"))

            mock.sendmsgResult = LinuxNative.SyscallResult.Success(20)
            assertEquals(20L, LinuxNative.sendmsg(fd, seg, 0).getOrThrow("test"))

            mock.recvmsgResult = LinuxNative.SyscallResult.Success(30)
            assertEquals(30L, LinuxNative.recvmsg(fd, seg, 0).getOrThrow("test"))

            mock.ioctlResult = LinuxNative.SyscallResult.Success(40)
            assertEquals(40L, LinuxNative.ioctl(fd, 2L, seg).getOrThrow("test"))
            assertEquals(40L, LinuxNative.ioctl(fd, 2L, 3L).getOrThrow("test"))

            mock.recvResult = LinuxNative.SyscallResult.Success(50)
            assertEquals(50L, LinuxNative.recv(fd, seg, 8L, 0).getOrThrow("test"))

            assertEquals(1234, LinuxNative.gettid())
        }
    }
}
