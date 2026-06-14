package io.mazewall.profiler.engine

import io.mazewall.LinuxNative

/**
 * States representing the installation and socket handshake process.
 */
internal sealed interface ProfilerInstallerState {
    /** Setup hasn't started. */
    data object Uninitialized : ProfilerInstallerState

    /** Main thread is building and installing the Seccomp BPF filter. */
    data object InstallingBpf : ProfilerInstallerState

    /** BPF installed; coordinator is connecting to socket path. */
    data class Connecting(
        val listenerFd: LinuxNative.FileDescriptor,
    ) : ProfilerInstallerState

    /** Connected; coordinator is sending the listener FD to the daemon. */
    data class SendingDescriptor(
        val listenerFd: LinuxNative.FileDescriptor,
        val socketFd: LinuxNative.FileDescriptor,
    ) : ProfilerInstallerState

    /** Descriptor sent; coordinator is waiting for verification ACK. */
    data class VerifyingAck(
        val listenerFd: LinuxNative.FileDescriptor,
        val socketFd: LinuxNative.FileDescriptor,
    ) : ProfilerInstallerState

    /** Handshake verified; trace listener started. */
    data class Active(
        val listenerFd: LinuxNative.FileDescriptor,
        val socketFd: LinuxNative.FileDescriptor,
    ) : ProfilerInstallerState

    /** Installation or handshake failed; cleaning up descriptors and propagating error. */
    data class Failed(
        val error: Throwable,
    ) : ProfilerInstallerState
}
