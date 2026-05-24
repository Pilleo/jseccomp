package io.mazewall.profiler

import io.mazewall.LinuxNative
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Shared utility for SCM_RIGHTS file descriptor passing via Unix Domain Sockets.
 */
internal object DescriptorPassing {
    /**
     * Sets up a [msghdr] structure for sending or receiving file descriptors.
     *
     * @param arena The arena to allocate memory from.
     * @param dummyByte A 1-byte buffer used as the mandatory data payload for [sendmsg]/[recvmsg].
     * @param controlBuf The buffer for [cmsghdr] that contains (or will contain) the file descriptors.
     * @return The initialized [msghdr] MemorySegment.
     */
    fun setupScmRightsMsgHdr(
        arena: Arena,
        dummyByte: MemorySegment,
        controlBuf: MemorySegment,
    ): MemorySegment {
        val iov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
        iov.set(ValueLayout.ADDRESS, 0L, dummyByte)
        iov.set(ValueLayout.JAVA_LONG, 8L, 1L)

        val msg = arena.allocate(LinuxNative.MSGHDR_LAYOUT)
        msg.fill(0)
        // Offset 16: msg_iov (pointer)
        msg.set(ValueLayout.ADDRESS, 16L, iov)
        // Offset 24: msg_iovlen (size_t)
        msg.set(ValueLayout.JAVA_LONG, 24L, 1L)
        // Offset 32: msg_control (pointer)
        msg.set(ValueLayout.ADDRESS, 32L, controlBuf)
        // Offset 40: msg_controllen (size_t)
        msg.set(ValueLayout.JAVA_LONG, 40L, controlBuf.byteSize())
        return msg
    }
}
