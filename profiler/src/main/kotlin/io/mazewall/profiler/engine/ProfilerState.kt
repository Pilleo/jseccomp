package io.mazewall.profiler.engine

import io.mazewall.LinuxNative

/**
 * States representing the lifecycle of a profiler connection/session.
 */
internal sealed interface ProfilerState {
    /** Connection accepted, waiting to receive the seccomp listener file descriptor. */
    data class Connected(
        val socketFd: LinuxNative.FileDescriptor,
    ) : ProfilerState

    /** FD received, sending PROTOCOL_ACK_BYTE to parent. */
    data class HandshakeAck(
        val socketFd: LinuxNative.FileDescriptor,
        val listenerFd: LinuxNative.FileDescriptor,
    ) : ProfilerState

    /** Actively polling for seccomp notifications or shutdown command. */
    data class ActiveSession(
        val socketFd: LinuxNative.FileDescriptor,
        val listenerFd: LinuxNative.FileDescriptor,
    ) : ProfilerState

    /** Seccomp notification received, sending trace event. */
    data class Notified(
        val socketFd: LinuxNative.FileDescriptor,
        val listenerFd: LinuxNative.FileDescriptor,
        val notifId: Long,
        val event: TraceEvent,
    ) : ProfilerState

    /** Event sent, waiting for PROTOCOL_ACK_BYTE or SHUTDOWN from parent. */
    data class WaitingForAck(
        val socketFd: LinuxNative.FileDescriptor,
        val listenerFd: LinuxNative.FileDescriptor,
        val notifId: Long,
    ) : ProfilerState

    /** Closed state. */
    data object Terminated : ProfilerState
}
