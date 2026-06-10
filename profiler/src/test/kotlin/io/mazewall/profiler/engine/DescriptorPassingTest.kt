package io.mazewall.profiler.engine

import io.mazewall.ffi.Layouts
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

class DescriptorPassingTest {
    @Test
    fun `test setupScmRightsMsgHdr correctly initializes msghdr and iovec`() {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(1)
            dummyByte.set(ValueLayout.JAVA_BYTE, 0, 42.toByte())
            val controlBuf = arena.allocate(128)

            val msgHdr = DescriptorPassing.setupScmRightsMsgHdr(arena, dummyByte, controlBuf)

            // msg_name and msg_namelen should be zero
            assertEquals(0L, msgHdr.get(ValueLayout.ADDRESS, 0L).address(), "msg_name should be null")
            assertEquals(0, msgHdr.get(ValueLayout.JAVA_INT, 8L), "msg_namelen should be 0")

            // msg_iov and msg_iovlen should be correctly set
            val iovPointer = msgHdr.get(ValueLayout.ADDRESS, 16L)
            val msgIovLen = msgHdr.get(ValueLayout.JAVA_LONG, 24L)
            assertEquals(1L, msgIovLen, "msg_iovlen should be 1")

            // Reinterpret iovPointer to check iovec contents
            val iovSegment = iovPointer.reinterpret(Layouts.IOVEC.byteSize())
            val iovBase = iovSegment.get(ValueLayout.ADDRESS, 0L)
            val iovLen = iovSegment.get(ValueLayout.JAVA_LONG, 8L)
            assertEquals(dummyByte.address(), iovBase.address(), "iov_base should point to dummyByte")
            assertEquals(1L, iovLen, "iov_len should be 1")

            // msg_control and msg_controllen should be correctly set
            val msgControl = msgHdr.get(ValueLayout.ADDRESS, 32L)
            val msgControlLen = msgHdr.get(ValueLayout.JAVA_LONG, 40L)
            assertEquals(controlBuf.address(), msgControl.address(), "msg_control should point to controlBuf")
            assertEquals(128L, msgControlLen, "msg_controllen should be 128")

            // msg_flags should be zero
            assertEquals(0, msgHdr.get(ValueLayout.JAVA_INT, 48L), "msg_flags should be 0")
        }
    }
}
