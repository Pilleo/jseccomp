package io.mazewall.profiler.internal

import io.mazewall.LinuxNative
import io.mazewall.profiler.Profiler
import io.mazewall.profiler.engine.TraceEvent
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.CopyOnWriteArrayList
import java.util.logging.Logger

internal class ProfilerTraceListener(
    private val socketFd: Int,
    private val accumulatedLogs: MutableList<TraceEvent>,
    private val stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
    private val pathCache: MutableMap<String, Long>,
    private val workerThreadProvider: () -> Thread?,
) {
    private val logger = Logger.getLogger(ProfilerTraceListener::class.java.name)

    companion object {
        private const val DEDUPLICATION_WINDOW_MS = 500L
        private const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
        private const val IO_BUFFER_SIZE = 8192
        private const val BYTE_MASK = 0xFF
        private const val EINTR = 4
        private const val EAGAIN = 11
        private const val RETRY_DELAY_MS = 1L
    }

    fun start(): Thread {
        val arena = Arena.ofShared()

        val inputStream = NativeSocketInputStream(socketFd, arena)

        return Thread {
            try {
                runListenerLoop(inputStream, arena)
            } finally {
                arena.close()
                inputStream.close()
            }
        }.apply {
            isDaemon = true
            name = "trace-listener-$socketFd"
        }.also {
            it.start()
        }
    }

    @Suppress("NestedBlockDepth")
    private fun runListenerLoop(
        inputStream: InputStream,
        arena: Arena,
    ) {
        val ackBuf = arena.allocate(1)
        ackBuf.set(ValueLayout.JAVA_BYTE, 0L, PROTOCOL_ACK_BYTE)

        val dis = DataInputStream(BufferedInputStream(inputStream))
        try {
            while (true) {
                val pid = dis.readInt()
                val syscallNameLen = dis.readInt()
                val syscallNameBytes = ByteArray(syscallNameLen)
                dis.readFully(syscallNameBytes)
                val syscallName = String(syscallNameBytes, Charsets.UTF_8)

                val argsCount = dis.readInt()
                val args = LongArray(argsCount)
                for (i in 0 until argsCount) {
                    args[i] = dis.readLong()
                }

                val pathsCount = dis.readInt()
                val paths = mutableListOf<String>()
                for (i in 0 until pathsCount) {
                    val pathLen = dis.readInt()
                    val pathBytes = ByteArray(pathLen)
                    dis.readFully(pathBytes)
                    paths.add(String(pathBytes, Charsets.UTF_8))
                }

                val threadToProfile = Profiler.threadRegistry[pid] ?: workerThreadProvider()
                val frames = if (stackTracesMap != null && threadToProfile != null) {
                    threadToProfile.stackTrace
                } else {
                    null
                }
                val stackTrace = frames?.map { it.toString() }
                val event = TraceEvent(pid, syscallName, args, paths, stackTrace)

                var isDuplicate = false
                if (paths.isNotEmpty()) {
                    val cacheKey = "$syscallName:${paths.sorted().joinToString(",")}"
                    val now = System.currentTimeMillis()
                    val lastSeen = pathCache[cacheKey] ?: 0L
                    if (now - lastSeen < DEDUPLICATION_WINDOW_MS) {
                        logger.fine("[PROFILER] Deduplicated duplicate event for $cacheKey")
                        isDuplicate = true
                    } else {
                        pathCache[cacheKey] = now
                    }
                }

                if (!isDuplicate) {
                    if (stackTracesMap != null && frames != null) {
                        stackTracesMap.getOrPut(event) { CopyOnWriteArrayList() }.add(frames)
                    }
                    accumulatedLogs.add(event)
                }

                sendAck(socketFd, ackBuf)
            }
        } catch (e: java.io.EOFException) {
            logger.log(java.util.logging.Level.FINE, "Trace listener socket closed (EOF)", e)
        } catch (e: java.io.IOException) {
            logger.log(java.util.logging.Level.WARNING, "Trace listener error", e)
        }
    }

    private fun sendAck(
        socketFd: Int,
        ackBuf: MemorySegment,
    ) {
        var status = 0
        while (status == 0) {
            val res = LinuxNative.write(socketFd, ackBuf, 1)
            status = checkWriteResult(res)
        }
    }

    private fun checkWriteResult(res: LinuxNative.SyscallResult): Int {
        var result = -1
        if (res.returnValue == 1L) {
            result = 1
        } else if (res.returnValue < 0) {
            val errno = res.errno
            if (errno == EINTR || errno == EAGAIN) {
                Thread.sleep(RETRY_DELAY_MS)
                result = 0
            } else {
                logger.warning("[PROFILER] Failed to write ACK: errno=$errno")
            }
        }
        return result
    }
}
