package io.mazewall.profiler

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.mazewall.LinuxNative
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import io.mazewall.profiler.engine.ACK_BUF_SIZE
import io.mazewall.profiler.engine.ADDR_UN_SIZE
import io.mazewall.profiler.engine.LoopAction
import io.mazewall.profiler.engine.POLLFD_REVENTS_OFF
import io.mazewall.profiler.engine.PROTOCOL_ACK_BYTE
import io.mazewall.profiler.engine.ProfilerMemoryReader
import io.mazewall.profiler.engine.ProfilerSessionHandler
import io.mazewall.profiler.engine.ProfilerTransport
import io.mazewall.profiler.engine.SHUTDOWN_COMMAND_BYTE
import io.mazewall.profiler.engine.SOCKADDR_UN_PATH_SIZE
import io.mazewall.profiler.engine.TraceEvent
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

class ProfilerDesignSpec :
    FreeSpec({

        "ACK Protocol Constants (profiler_design.md §2 / architectural_map.md §2)" - {
            "PROTOCOL_ACK_BYTE is exactly 0xAC" {
                PROTOCOL_ACK_BYTE shouldBe 0xAC.toByte()
            }

            "SHUTDOWN_COMMAND_BYTE is exactly 0x53 ('S')" {
                SHUTDOWN_COMMAND_BYTE shouldBe 0x53.toByte()
            }

            "ACK byte is a single byte (ACK_BUF_SIZE == 1)" {
                ACK_BUF_SIZE shouldBe 1L
            }
        }

        "Profiler Transport Invariants (profiler_design.md §5 Operational Hazards)" - {
            "SOCKADDR_UN path field is 108 bytes (sun_path POSIX limit)" {
                SOCKADDR_UN_PATH_SIZE shouldBe 108
                val pathElement = Layouts.SOCKADDR_UN.select(MemoryLayout.PathElement.groupElement("sun_path"))
                pathElement.byteSize() shouldBe 108L
            }

            "SOCKADDR_UN total struct is 110 bytes (2-byte family + 108 path)" {
                ADDR_UN_SIZE shouldBe 110
                Layouts.SOCKADDR_UN.byteSize() shouldBe 110L
                Layouts.SOCKADDR_UN.byteOffset(MemoryLayout.PathElement.groupElement("sun_family")) shouldBe 0L
                val familyLayout = Layouts.SOCKADDR_UN.select(MemoryLayout.PathElement.groupElement("sun_family")) as ValueLayout
                familyLayout.carrier() shouldBe Short::class.java
                Layouts.SOCKADDR_UN.byteOffset(MemoryLayout.PathElement.groupElement("sun_path")) shouldBe 2L
            }
        }

        class MockMemoryReader : ProfilerMemoryReader {
            var readStringResult: String? = "/tmp/test.txt"
            var resolveLinkResult: String? = "/proc/1/cwd"

            override fun readStringFromProcess(
                pid: Int,
                remoteAddr: Long,
                maxLen: Int,
            ): String? = readStringResult

            override fun resolveLink(
                pid: Int,
                link: String,
            ): String? = resolveLinkResult
        }

        class MockTransport : ProfilerTransport {
            val sentEvents = mutableListOf<TraceEvent>()
            var nextPollResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(1)
            var nextReadResult: LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(1)
            var ackByte: Byte = 0xAC.toByte()
            val ioctlCalls = mutableListOf<Long>()
            var createdServerPath: String? = null
            var acceptedServerFd: LinuxNative.FileDescriptor? = null
            var closedFds = mutableListOf<LinuxNative.FileDescriptor>()

            var nextNotifId = 123L
            var nextNotifPid = 456
            var nextNotifNr = 2
            val nextNotifArgs = LongArray(6)

            override fun sendTraceEvent(
                socketFd: LinuxNative.FileDescriptor,
                event: TraceEvent,
            ) {
                sentEvents.add(event)
            }

            override fun recvDescriptor(socketFd: LinuxNative.FileDescriptor): LinuxNative.FileDescriptor? = LinuxNative.FileDescriptor(5)

            override fun poll(
                fds: MemorySegment,
                nfds: Long,
                timeout: Int,
            ): LinuxNative.SyscallResult {
                if (nfds == 1L) {
                    fds.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, NativeConstants.POLLIN)
                }
                return nextPollResult
            }

            override fun read(
                fd: LinuxNative.FileDescriptor,
                buf: MemorySegment,
                count: Long,
            ): LinuxNative.SyscallResult {
                if (count == 1L) {
                    buf.set(ValueLayout.JAVA_BYTE, 0L, ackByte)
                }
                return nextReadResult
            }

            override fun write(
                fd: LinuxNative.FileDescriptor,
                buf: MemorySegment,
                count: Long,
            ): LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(count)

            override fun recv(
                sockfd: LinuxNative.FileDescriptor,
                buf: MemorySegment,
                len: Long,
                flags: Int,
            ): LinuxNative.SyscallResult = LinuxNative.SyscallResult.Success(len)

            override fun ioctl(
                fd: LinuxNative.FileDescriptor,
                request: Long,
                arg: MemorySegment,
            ): LinuxNative.SyscallResult {
                ioctlCalls.add(request)
                if (request == 0xc0502100L) { // RECV
                    arg.set(ValueLayout.JAVA_LONG, 0L, nextNotifId) // id
                    arg.set(ValueLayout.JAVA_INT, 8L, nextNotifPid) // pid
                    arg.set(ValueLayout.JAVA_INT, 16L, nextNotifNr) // nr
                    for (i in 0 until 6) {
                        arg.set(ValueLayout.JAVA_LONG, 32L + i * 8, nextNotifArgs[i])
                    }
                }
                return LinuxNative.SyscallResult.Success(0)
            }

            override fun createServer(socketPath: String): LinuxNative.FileDescriptor {
                createdServerPath = socketPath
                return LinuxNative.FileDescriptor(99)
            }

            override fun accept(serverFd: LinuxNative.FileDescriptor): LinuxNative.FileDescriptor {
                acceptedServerFd = serverFd
                return LinuxNative.FileDescriptor(100)
            }

            override fun close(fd: LinuxNative.FileDescriptor) {
                closedFds.add(fd)
            }
        }

        "ProfilerSessionHandler Isolated Mock Testing (profiler/AGENTS.md §2)" - {
            "Session handler processes notification, resolves path, and notifies parent" {
                val transport = MockTransport()
                transport.nextNotifNr = 2
                transport.nextNotifArgs[0] = 0x1000L

                val reader = MockMemoryReader()
                reader.readStringResult = "/tmp/test.txt"

                val syscallMap = mapOf(2 to "OPEN")
                val handler = ProfilerSessionHandler(LinuxNative.FileDescriptor(10), LinuxNative.FileDescriptor(20), transport, reader, syscallMap) {}

                Arena.ofConfined().use { arena ->
                    val notif = arena.allocate(Layouts.SECCOMP_NOTIF)
                    val resp = arena.allocate(Layouts.SECCOMP_NOTIF_RESP)
                    val ackBuf = arena.allocate(1L)
                    val socketPollFd = arena.allocate(Layouts.POLLFD)

                    val pollFds = arena.allocate(MemoryLayout.sequenceLayout(2, Layouts.POLLFD))
                    pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, NativeConstants.POLLIN)

                    val action = handler.handleActiveListener(pollFds, ackBuf, notif, resp, socketPollFd)

                    action shouldBe LoopAction.Continue
                    transport.sentEvents.size shouldBe 1
                    transport.sentEvents[0].syscallName shouldBe "OPEN"
                    transport.sentEvents[0].pid shouldBe 456
                    transport.sentEvents[0].paths shouldBe listOf("/tmp/test.txt")
                    transport.ioctlCalls.contains(0xc0182101L) shouldBe true // SECCOMP_IOCTL_NOTIF_SEND
                }
            }

            "Path resolution correctly resolves relative paths using cwd and dirfd" {
                val transport = MockTransport()
                transport.nextNotifNr = 257 // OPENAT
                transport.nextNotifArgs[0] = -100L // dirfd = AT_FDCWD
                transport.nextNotifArgs[1] = 0x1000L // path address

                val reader = MockMemoryReader()
                reader.readStringResult = "relative.txt"
                reader.resolveLinkResult = "/home/user"

                val syscallMap = mapOf(257 to "OPENAT")
                val handler = ProfilerSessionHandler(LinuxNative.FileDescriptor(10), LinuxNative.FileDescriptor(20), transport, reader, syscallMap) {}

                Arena.ofConfined().use { arena ->
                    val notif = arena.allocate(Layouts.SECCOMP_NOTIF)
                    val resp = arena.allocate(Layouts.SECCOMP_NOTIF_RESP)
                    val ackBuf = arena.allocate(1L)
                    val socketPollFd = arena.allocate(Layouts.POLLFD)
                    val pollFds = arena.allocate(MemoryLayout.sequenceLayout(2, Layouts.POLLFD))
                    pollFds.set(ValueLayout.JAVA_SHORT, POLLFD_REVENTS_OFF, NativeConstants.POLLIN)

                    handler.handleActiveListener(pollFds, ackBuf, notif, resp, socketPollFd)
                    transport.sentEvents.size shouldBe 1
                    transport.sentEvents[0].paths shouldBe listOf("/home/user/relative.txt")
                }
            }
        }
    })
