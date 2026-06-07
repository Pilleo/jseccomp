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
    }

    fun start(): Thread {
        val arena = Arena.ofShared()
        val readBuf = arena.allocate(1)
        val multiBuf = arena.allocate(IO_BUFFER_SIZE.toLong())

        val inputStream = object : InputStream() {
            override fun read(): Int {
                val res = LinuxNative.read(socketFd, readBuf, 1)
                return if (res.returnValue <= 0) {
                    -1
                } else {
                    readBuf.get(ValueLayout.JAVA_BYTE, 0L).toInt() and BYTE_MASK
                }
            }

            override fun read(
                b: ByteArray,
                off: Int,
                len: Int,
            ): Int {
                if (len == 0) return 0
                val count = Math.min(len.toLong(), IO_BUFFER_SIZE.toLong())
                val res = LinuxNative.read(socketFd, multiBuf, count)
                return if (res.returnValue <= 0) {
                    -1
                } else {
                    val actualLen = res.returnValue.toInt()
                    MemorySegment.copy(multiBuf, ValueLayout.JAVA_BYTE, 0L, b, off, actualLen)
                    actualLen
                }
            }

            override fun close() {
                LinuxNative.close(socketFd)
            }
        }

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
                val stackTrace = threadToProfile?.stackTrace?.map { it.toString() }
                val event = TraceEvent(pid, syscallName, args, paths, stackTrace)

                if (paths.isNotEmpty()) {
                    val cacheKey = "$syscallName:${paths.sorted().joinToString(",")}"
                    val now = System.currentTimeMillis()
                    val lastSeen = pathCache[cacheKey] ?: 0L
                    if (now - lastSeen < DEDUPLICATION_WINDOW_MS) {
                        logger.fine("[PROFILER] Deduplicated duplicate event for $cacheKey")
                        if (pid != 0) {
                            LinuxNative.write(socketFd, ackBuf, 1)
                        }
                        continue
                    }
                    pathCache[cacheKey] = now
                }

                if (stackTracesMap != null) {
                    if (threadToProfile != null) {
                        val frames = threadToProfile.stackTrace
                        stackTracesMap
                            .computeIfAbsent(event) {
                                CopyOnWriteArrayList<Array<StackTraceElement>>()
                            }.add(frames)
                    }
                }

                accumulatedLogs.add(event)

                if (pid != 0) {
                    LinuxNative.write(socketFd, ackBuf, 1)
                }
            }
        } catch (e: java.io.EOFException) {
            logger.log(java.util.logging.Level.FINE, "Trace listener socket closed (EOF)", e)
        } catch (e: java.io.IOException) {
            logger.log(java.util.logging.Level.WARNING, "Trace listener error", e)
        }
    }
}
