package io.mazewall.profiler.internal

import io.mazewall.LinuxNative
import java.io.InputStream
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

internal class NativeSocketInputStream(
    private val socketFd: Int,
    private val arena: Arena,
    private val nativeRead: (Int, MemorySegment, Long) -> LinuxNative.SyscallResult = LinuxNative::read,
    private val nativeClose: (Int) -> Unit = LinuxNative::close,
) : InputStream() {
    private val readBuf = arena.allocate(1)
    private val multiBuf = arena.allocate(BUFFER_SIZE.toLong())

    companion object {
        private const val BUFFER_SIZE = 8192
        private const val BYTE_MASK = 0xFF
        private const val EINTR = 4
    }

    override fun read(): Int {
        while (true) {
            val res = nativeRead(socketFd, readBuf, 1)
            if (res.returnValue <= 0) {
                if (res.returnValue < 0 && res.errno == EINTR) continue
                return -1
            }
            return readBuf.get(ValueLayout.JAVA_BYTE, 0L).toInt() and BYTE_MASK
        }
    }

    override fun read(
        b: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        if (len == 0) return 0
        return readWithRetry(b, off, len)
    }

    private fun readWithRetry(
        b: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        val count = Math.min(len.toLong(), BUFFER_SIZE.toLong())
        while (true) {
            val res = nativeRead(socketFd, multiBuf, count)
            if (res.returnValue <= 0) {
                if (res.returnValue < 0 && res.errno == EINTR) continue
                return -1
            }
            val actualLen = res.returnValue.toInt()
            MemorySegment.copy(multiBuf, ValueLayout.JAVA_BYTE, 0L, b, off, actualLen)
            return actualLen
        }
    }

    override fun close() {
        nativeClose(socketFd)
    }
}
