package io.mazewall.profiler.engine

import io.mazewall.ffi.Layouts
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Shared utility for SCM_RIGHTS file descriptor passing via Unix Domain Sockets.
 */
internal object DescriptorPassing {
    private const val IOV_LEN_OFF = 8L
    private const val MSG_IOV_OFF = 16L
    private const val MSG_IOVLEN_OFF = 24L
    private const val MSG_CONTROL_OFF = 32L
    private const val MSG_CONTROLLEN_OFF = 40L

    /**
     * Sets up a [msghdr] structure for sending or receiving file descriptors.
     *
     * @param arena The arena to allocate memory from.
     * @param dummyByte A 1-byte buffer used as the mandatory data payload for [io.mazewall.LinuxNative.sendmsg]/[io.mazewall.LinuxNative.recvmsg].
     * @param controlBuf The buffer for [cmsghdr] that contains (or will contain) the file descriptors.
     * @return The initialized [msghdr] MemorySegment.
     */
    fun setupScmRightsMsgHdr(
        arena: Arena,
        dummyByte: MemorySegment,
        controlBuf: MemorySegment,
    ): MemorySegment {
        val iov = arena.allocate(Layouts.IOVEC)
        iov.set(ValueLayout.ADDRESS, 0L, dummyByte)
        iov.set(ValueLayout.JAVA_LONG, IOV_LEN_OFF, 1L)

        val msg = arena.allocate(Layouts.MSGHDR)
        msg.fill(0)
        // Offset 16: msg_iov (pointer)
        msg.set(ValueLayout.ADDRESS, MSG_IOV_OFF, iov)
        // Offset 24: msg_iovlen (size_t)
        msg.set(ValueLayout.JAVA_LONG, MSG_IOVLEN_OFF, 1L)
        // Offset 32: msg_control (pointer)
        msg.set(ValueLayout.ADDRESS, MSG_CONTROL_OFF, controlBuf)
        // Offset 40: msg_controllen (size_t)
        msg.set(ValueLayout.JAVA_LONG, MSG_CONTROLLEN_OFF, controlBuf.byteSize())
        return msg
    }
}
