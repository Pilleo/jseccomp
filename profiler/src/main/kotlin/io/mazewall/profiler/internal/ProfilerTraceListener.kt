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
    private val socketFd: LinuxNative.FileDescriptor,
    private val accumulatedLogs: MutableList<TraceEvent>,
    private val stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
    private val pathCache: MutableMap<String, Long>,
    private val workerThreadProvider: () -> Thread?,
) {
    private val logger = Logger.getLogger(ProfilerTraceListener::class.java.name)

    var state: TraceListenerState = TraceListenerState.Disconnected
        private set

    companion object {
        private const val DEDUPLICATION_WINDOW_MS = 500L
        private const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
        private const val IO_BUFFER_SIZE = 8192
        private const val BYTE_MASK = 0xFF
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
            name = "trace-listener-${socketFd.value}"
        }.also {
            it.start()
        }
    }

    private fun runListenerLoop(
        inputStream: InputStream,
        arena: Arena,
    ) {
        val ackBuf = arena.allocate(1)
        ackBuf.set(ValueLayout.JAVA_BYTE, 0L, PROTOCOL_ACK_BYTE)

        val dis = DataInputStream(BufferedInputStream(inputStream))
        try {
            while (true) {
                state = TraceListenerState.AwaitingEvent
                val event = readNextEvent(dis)
                state = TraceListenerState.ProcessingEvent(event)
                processEvent(event, ackBuf)
            }
        } catch (e: java.io.EOFException) {
            logger.log(java.util.logging.Level.FINE, "Trace listener socket closed (EOF)", e)
        } catch (e: java.io.IOException) {
            logger.log(java.util.logging.Level.WARNING, "Trace listener error", e)
        } finally {
            state = TraceListenerState.Disconnected
        }
    }

    private fun readNextEvent(dis: DataInputStream): TraceEvent {
        val pid = dis.readInt()
        state = TraceListenerState.ReadingHeader(pid)

        val syscallNameLen = dis.readInt()
        state = TraceListenerState.ReadingSyscall(pid, syscallNameLen)

        val syscallNameBytes = ByteArray(syscallNameLen)
        dis.readFully(syscallNameBytes)
        val syscallName = String(syscallNameBytes, Charsets.UTF_8)

        val argsCount = dis.readInt()
        state = TraceListenerState.ReadingArguments(pid, syscallName, argsCount)

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
        return TraceEvent(pid, syscallName, args, paths, stackTrace)
    }

    private fun processEvent(
        event: TraceEvent,
        ackBuf: MemorySegment,
    ) {
        if (event.paths.isNotEmpty() && isDuplicate(event)) {
            sendAckIfNecessary(event.pid, ackBuf)
            return
        }

        accumulateStackTrace(event)
        accumulatedLogs.add(event)
        sendAckIfNecessary(event.pid, ackBuf)
    }

    private fun isDuplicate(event: TraceEvent): Boolean {
        val cacheKey = "${event.syscallName}:${event.paths.sorted().joinToString(",")}"
        val now = System.currentTimeMillis()
        val lastSeen = pathCache[cacheKey] ?: 0L
        return if (now - lastSeen < DEDUPLICATION_WINDOW_MS) {
            logger.fine("[PROFILER] Deduplicated duplicate event for $cacheKey")
            true
        } else {
            pathCache[cacheKey] = now
            false
        }
    }

    private fun accumulateStackTrace(event: TraceEvent) {
        if (stackTracesMap == null) return
        val threadToProfile = Profiler.threadRegistry[event.pid] ?: workerThreadProvider()
        if (threadToProfile != null) {
            val frames = threadToProfile.stackTrace
            stackTracesMap
                .computeIfAbsent(event) {
                    CopyOnWriteArrayList<Array<StackTraceElement>>()
                }.add(frames)
        }
    }

    private fun sendAckIfNecessary(
        pid: Int,
        ackBuf: MemorySegment,
    ) {
        if (pid != 0) {
            LinuxNative.write(socketFd, ackBuf, 1)
        }
    }
}
