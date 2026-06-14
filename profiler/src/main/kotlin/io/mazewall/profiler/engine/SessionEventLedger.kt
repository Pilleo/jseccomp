package io.mazewall.profiler.engine

import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReferenceArray

sealed interface SessionEvent {
    val timestampNanos: Long
    val threadId: Long

    class Notified(
        override val timestampNanos: Long,
        override val threadId: Long,
        val syscall: Long,
    ) : SessionEvent {
        override fun toString() = "[$timestampNanos] Thread $threadId: NOTIFIED syscall $syscall"
    }

    class VmReadvResolved(
        override val timestampNanos: Long,
        override val threadId: Long,
        val success: Boolean,
    ) : SessionEvent {
        override fun toString() = "[$timestampNanos] Thread $threadId: VM_READV_RESOLVED success=$success"
    }

    class EventSent(
        override val timestampNanos: Long,
        override val threadId: Long,
    ) : SessionEvent {
        override fun toString() = "[$timestampNanos] Thread $threadId: EVENT_SENT"
    }

    class AckReceived(
        override val timestampNanos: Long,
        override val threadId: Long,
    ) : SessionEvent {
        override fun toString() = "[$timestampNanos] Thread $threadId: ACK_RECEIVED"
    }

    class ContinueReplied(
        override val timestampNanos: Long,
        override val threadId: Long,
        val valToReply: Long,
    ) : SessionEvent {
        override fun toString() = "[$timestampNanos] Thread $threadId: CONTINUE_REPLIED valToReply=$valToReply"
    }
}

@Suppress("MagicNumber")
class SessionEventLedger {
    private val buffer = AtomicReferenceArray<SessionEvent>(CAPACITY)
    private val writeIndex = AtomicLong(0)

    fun record(event: SessionEvent) {
        val idx = writeIndex.getAndIncrement()
        buffer.set((idx % CAPACITY).toInt(), event)
    }

    fun dump(): List<SessionEvent> {
        val currentWrite = writeIndex.get()
        val start = maxOf(0L, currentWrite - CAPACITY)
        val list = mutableListOf<SessionEvent>()
        for (i in start until currentWrite) {
            val event = buffer.get((i % CAPACITY).toInt())
            if (event != null) {
                list.add(event)
            }
        }
        return list
    }

    companion object {
        private const val CAPACITY = 64
    }
}
