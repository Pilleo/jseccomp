package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * Interface for reading memory and resolving paths from a tracee process.
 */
interface ProfilerMemoryReader {
    fun readStringFromProcess(
        pid: Int,
        remoteAddr: Long,
        maxLen: Int = 4096,
    ): String?

    fun resolveLink(
        pid: Int,
        link: String,
    ): String?
}

/**
 * Real implementation of [ProfilerMemoryReader] using process_vm_readv and readlink.
 */
object RealMemoryReader : ProfilerMemoryReader {
    private const val PATH_MAX_VAL = 4096L
    private const val IOV_LEN_OFF = 8L

    override fun readStringFromProcess(
        pid: Int,
        remoteAddress: Long,
        maxLen: Int,
    ): String? {
        Arena.ofConfined().use { arena ->
            val localBuf = arena.allocate(maxLen.toLong())
            localBuf.fill(0)
            val localIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            localIov.set(ValueLayout.ADDRESS, 0L, localBuf)
            localIov.set(ValueLayout.JAVA_LONG, IOV_LEN_OFF, maxLen.toLong())
            val remoteIov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            remoteIov.set(ValueLayout.ADDRESS, 0L, MemorySegment.ofAddress(remoteAddress))
            remoteIov.set(ValueLayout.JAVA_LONG, IOV_LEN_OFF, maxLen.toLong())
            val res = LinuxNative.processVmReadv(pid, localIov, 1, remoteIov, 1, 0)
            var result: String? = null
            if (res.returnValue >= 0) {
                val bytesRead = res.returnValue.toInt()
                var len = 0
                while (len < bytesRead && localBuf.get(ValueLayout.JAVA_BYTE, len.toLong()) != 0.toByte()) len++

                if (len < bytesRead) {
                    result = localBuf.copyToString(len)
                }
            } else if (res.errno == 1) { // EPERM
                System.err.println("[DAEMON] WARN: Permission denied reading memory from PID $pid. (Yama ptrace_scope?)")
            }
            return result
        }
    }

    override fun resolveLink(
        pid: Int,
        link: String,
    ): String? {
        val procPath = "/proc/$pid/$link"
        Arena.ofConfined().use { arena ->
            val pathSeg = arena.allocateFrom(procPath)
            val buf = arena.allocate(PATH_MAX_VAL)
            val res = LinuxNative.readlink(pathSeg, buf, PATH_MAX_VAL)
            if (res.returnValue < 0) return null
            return buf.copyToString(res.returnValue.toInt())
        }
    }

    private fun MemorySegment.copyToString(len: Int): String {
        val bytes = this.asSlice(0L, len.toLong()).toArray(ValueLayout.JAVA_BYTE)
        return String(bytes, StandardCharsets.UTF_8)
    }
}
