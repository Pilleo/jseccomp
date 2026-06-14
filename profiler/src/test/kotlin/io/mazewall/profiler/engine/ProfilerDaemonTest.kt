package io.mazewall.profiler.engine

import io.mazewall.LinuxNative
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.atomic.AtomicInteger

class ProfilerDaemonTest {
    private class MockTransport : ProfilerTransport {
        val sentEvents = mutableListOf<TraceEvent>()
        val pollCount = AtomicInteger(0)
        var nextPollResult = LinuxNative.SyscallResult(1, 0)
        var nextReadResult = LinuxNative.SyscallResult(1, 0)
        var ackByte: Byte = 0xAC.toByte()
        val ioctlCalls = mutableListOf<Long>()

        override fun sendTraceEvent(
            socketFd: Int,
            event: TraceEvent,
        ) {
            sentEvents.add(event)
        }

        override fun recvDescriptor(socketFd: Int): Int? = 5

        override fun poll(
            fds: MemorySegment,
            nfds: Long,
            timeout: Int,
        ): LinuxNative.SyscallResult {
            pollCount.incrementAndGet()
            // In the wait-for-ack loop, we need to set the revents
            if (nfds == 1L) {
                 fds.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, NativeConstants.POLLIN)
            }
            return nextPollResult
        }

        override fun read(
            fd: Int,
            buf: MemorySegment,
            count: Long,
        ): LinuxNative.SyscallResult {
            if (count == 1L) {
                buf.set(ValueLayout.JAVA_BYTE, 0L, ackByte)
            }
            return nextReadResult
        }

        override fun write(
            fd: Int,
            buf: MemorySegment,
            count: Long,
        ): LinuxNative.SyscallResult = LinuxNative.SyscallResult(count, 0)

        override fun recv(
            sockfd: Int,
            buf: MemorySegment,
            len: Long,
            flags: Int,
        ): LinuxNative.SyscallResult = LinuxNative.SyscallResult(len, 0)

        override fun ioctl(
            fd: Int,
            request: Long,
            arg: MemorySegment,
        ): LinuxNative.SyscallResult {
            ioctlCalls.add(request)
            if (request == 0xc0502100L) { // RECV
                arg.set(ValueLayout.JAVA_LONG, 0L, 123L) // id
                arg.set(ValueLayout.JAVA_INT, 8L, 456) // pid
                arg.set(ValueLayout.JAVA_INT, 16L, 2) // nr (open)
                arg.set(ValueLayout.JAVA_LONG, 32L, 0x1000L) // args[0] = non-zero pointer
            }
            return LinuxNative.SyscallResult(0, 0)
        }

        override fun createServer(socketPath: String): Int = 99

        override fun accept(serverFd: Int): Int = 100

        override fun close(fd: Int) {}
    }

    private class MockReader : ProfilerMemoryReader {
        override fun readStringFromProcess(
            pid: Int,
            remoteAddr: Long,
            maxLen: Int,
        ): String? = "/tmp/test.txt"

        override fun resolveLink(
            pid: Int,
            link: String,
        ): String? = "/proc/1/cwd"
    }

    @Test
    fun `session handler processes notification and waits for ACK`() {
        val transport = MockTransport()
        val reader = MockReader()
        val syscallMap = mapOf(2 to "OPEN")
        var shutdownCalled = false
        val handler = ProfilerSessionHandler(10, 20, transport, reader, syscallMap) {
            shutdownCalled = true
        }

        Arena.ofConfined().use { arena ->
            val notif = arena.allocate(Layouts.SECCOMP_NOTIF)
            notif.set(ValueLayout.JAVA_LONG, NOTIF_ID_OFF, 123L) // ID
            notif.set(ValueLayout.JAVA_INT, NOTIF_PID_OFF, 456) // PID
            notif.set(ValueLayout.JAVA_INT, NOTIF_NR_OFF, 2) // NR (open)

            val resp = arena.allocate(Layouts.SECCOMP_NOTIF_RESP)
            val ackBuf = arena.allocate(1L)
            val socketPollFd = arena.allocate(Layouts.POLLFD)

            val pollFds = setupMockPoll(arena)
            val action = handler.handleActiveListener(pollFds, ackBuf, notif, resp, socketPollFd)

            assertTrue(action is LoopAction.Continue)
            assertEquals(1, transport.sentEvents.size)
            assertEquals("OPEN", transport.sentEvents[0].syscallName)
            assertEquals(456, transport.sentEvents[0].pid)
            // Verify that continue response was sent via ioctl
            assertTrue(transport.ioctlCalls.contains(SECCOMP_IOCTL_NOTIF_SEND), "Should have sent SECCOMP_IOCTL_NOTIF_SEND")
        }
    }

    @Test
    fun `test SessionEventLedger records and dumps events on ACK timeout`() {
        val transport = MockTransport()
        // Simulate a timeout by poll returning 0L
        transport.nextPollResult = LinuxNative.SyscallResult(0L, 0)
        
        val reader = MockReader()
        val syscallMap = mapOf(2 to "OPEN")
        var shutdownCalled = false
        val handler = ProfilerSessionHandler(10, 20, transport, reader, syscallMap) {
            shutdownCalled = true
        }

        Arena.ofConfined().use { arena ->
            val notif = arena.allocate(Layouts.SECCOMP_NOTIF)
            notif.set(ValueLayout.JAVA_LONG, NOTIF_ID_OFF, 123L) // ID
            notif.set(ValueLayout.JAVA_INT, NOTIF_PID_OFF, 456) // PID
            notif.set(ValueLayout.JAVA_INT, NOTIF_NR_OFF, 2) // NR (open)
            notif.set(ValueLayout.JAVA_LONG, NOTIF_ARGS_OFF, 0x1000L) // args[0] = non-zero pointer

            val resp = arena.allocate(Layouts.SECCOMP_NOTIF_RESP)
            val ackBuf = arena.allocate(1L)
            val socketPollFd = arena.allocate(Layouts.POLLFD)

            val pollFds = setupMockPoll(arena)
            val action = handler.handleActiveListener(pollFds, ackBuf, notif, resp, socketPollFd)

            // Since ACK timed out, the handler action is still continue (or break/shutdown depending on implementation), 
            // but the state becomes Terminated because waitForParentAck returned false.
            assertTrue(handler.state is ProfilerState.Terminated, "Handler state should be Terminated on ACK timeout")
            
            // Check that ledger recorded events
            val events = handler.ledger.dump()
            assertTrue(events.isNotEmpty(), "Ledger should have recorded events")
            assertTrue(events.any { it is SessionEvent.Notified }, "Ledger should contain Notified event")
            assertTrue(events.any { it is SessionEvent.VmReadvResolved }, "Ledger should contain VmReadvResolved event")
            assertTrue(events.any { it is SessionEvent.EventSent }, "Ledger should contain EventSent event")
            assertTrue(events.any { it is SessionEvent.ContinueReplied }, "Ledger should contain ContinueReplied event")
        }
    }

    private fun setupMockPoll(arena: Arena): MemorySegment {
        val pollFds = arena.allocate(MemoryLayout.sequenceLayout(2, Layouts.POLLFD))
        // [0]: Seccomp listener FD - set POLLIN
        pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, NativeConstants.POLLIN)
        return pollFds
    }
}
