package io.mazewall.profiler.engine

/**
 * States representing the lifecycle of the Profiler Daemon server.
 */
internal sealed interface ProfilerDaemonState {
    /** The daemon server has not been started. */
    data object Uninitialized : ProfilerDaemonState

    /** The daemon server is creating and binding the socket. */
    data class Listening(
        val serverFd: Int,
        val socketPath: String,
    ) : ProfilerDaemonState

    /** The daemon server is actively listening and processing client connections. */
    data class Active(
        val serverFd: Int,
    ) : ProfilerDaemonState

    /** Global shutdown has been triggered. */
    data object ShuttingDown : ProfilerDaemonState

    /** Teardown finished, all descriptors closed. */
    data object Terminated : ProfilerDaemonState
}
