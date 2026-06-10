package io.mazewall

/**
 * Standard Linux Seccomp-BPF return actions.
 *
 * The priority is used when combining multiple policies. Higher priority
 * actions (more restrictive) will override lower priority ones for the same syscall.
 */
enum class SeccompAction(
    val priority: Int,
) {
    /** Immediately terminates the entire process. */
    ACT_KILL_PROCESS(7),

    /** Immediately terminates the calling thread. */
    ACT_KILL_THREAD(6),

    /** Sends a SIGSYS signal to the calling thread (native interception). */
    ACT_TRAP(5),

    /** Returns EPERM (or ENOSYS for clone3) to the calling thread. */
    ACT_ERRNO(4),

    /** Sends a notification to a userspace supervisor (used by the Profiler). */
    ACT_NOTIFY(3),

    /** Allows the syscall but logs it via the kernel audit subsystem. */
    ACT_LOG(2),

    /** Unconditionally allows the system call. */
    ACT_ALLOW(1),
}
