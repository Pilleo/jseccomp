package io.mazewall.ffi

import java.lang.foreign.MemoryLayout
import java.lang.foreign.StructLayout
import java.lang.foreign.ValueLayout

/**
 * Centralized registry for all Foreign Function & Memory (FFM) API memory layouts.
 *
 * This registry eliminates hardcoded byte offsets in the codebase, significantly
 * improving safety for coding agents and developers. Always use the `byteOffset()`
 * method on these layouts to resolve member positions.
 */
object Layouts {
    /**
     * Corresponds to `struct sock_filter` in `<linux/filter.h>`.
     * Used for BPF filter instructions.
     */
    val SOCK_FILTER: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("code"),
        ValueLayout.JAVA_BYTE.withName("jt"),
        ValueLayout.JAVA_BYTE.withName("jf"),
        ValueLayout.JAVA_INT.withName("k"),
    )

    /**
     * Corresponds to `struct sock_fprog` in `<linux/filter.h>`.
     * Used to pass the BPF program to the kernel.
     */
    val SOCK_FPROG: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("len"),
        MemoryLayout.paddingLayout(6), // Align pointer to 8 bytes
        ValueLayout.ADDRESS.withName("filter"),
    )

    /**
     * Corresponds to `struct seccomp_data` in `<linux/seccomp.h>`.
     * Contains the syscall number and arguments for BPF inspection.
     */
    val SECCOMP_DATA: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_INT.withName("nr"),
        ValueLayout.JAVA_INT.withName("arch"),
        ValueLayout.JAVA_LONG.withName("instruction_pointer"),
        MemoryLayout.sequenceLayout(6, ValueLayout.JAVA_LONG).withName("args"),
    )

    /**
     * Corresponds to `struct seccomp_notif` in `<linux/seccomp.h>`.
     * Used by the Profiler to receive syscall notification events.
     */
    val SECCOMP_NOTIF: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("id"),
        ValueLayout.JAVA_INT.withName("pid"),
        ValueLayout.JAVA_INT.withName("flags"),
        SECCOMP_DATA.withName("data"),
    )

    /**
     * Corresponds to `struct seccomp_notif_resp` in `<linux/seccomp.h>`.
     * Used by the Profiler to ACK syscall notifications.
     */
    val SECCOMP_NOTIF_RESP: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("id"),
        ValueLayout.JAVA_LONG.withName("val"),
        ValueLayout.JAVA_INT.withName("error"),
        ValueLayout.JAVA_INT.withName("flags"),
    )

    /**
     * Corresponds to `struct iovec` in `<sys/uio.h>`.
     */
    val IOVEC: StructLayout = MemoryLayout.structLayout(
        ValueLayout.ADDRESS.withName("iov_base"),
        ValueLayout.JAVA_LONG.withName("iov_len"),
    )

    /**
     * Corresponds to `struct msghdr` in `<sys/socket.h>`.
     */
    val MSGHDR: StructLayout = MemoryLayout.structLayout(
        ValueLayout.ADDRESS.withName("msg_name"),
        ValueLayout.JAVA_INT.withName("msg_namelen"),
        MemoryLayout.paddingLayout(4),
        ValueLayout.ADDRESS.withName("msg_iov"),
        ValueLayout.JAVA_LONG.withName("msg_iovlen"),
        ValueLayout.ADDRESS.withName("msg_control"),
        ValueLayout.JAVA_LONG.withName("msg_controllen"),
        ValueLayout.JAVA_INT.withName("msg_flags"),
        MemoryLayout.paddingLayout(4),
    )

    /**
     * Corresponds to `struct cmsghdr` in `<sys/socket.h>`.
     */
    val CMSGHDR: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("cmsg_len"),
        ValueLayout.JAVA_INT.withName("cmsg_level"),
        ValueLayout.JAVA_INT.withName("cmsg_type"),
    )

    /**
     * Corresponds to `struct sockaddr_un` in `<sys/un.h>`.
     */
    val SOCKADDR_UN: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("sun_family"),
        MemoryLayout.sequenceLayout(108, ValueLayout.JAVA_BYTE).withName("sun_path"),
    )

    /**
     * Corresponds to `struct pollfd` in `<poll.h>`.
     */
    val POLLFD: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_INT.withName("fd"),
        ValueLayout.JAVA_SHORT.withName("events"),
        ValueLayout.JAVA_SHORT.withName("revents"),
    )

    /**
     * Corresponds to `struct landlock_ruleset_attr` in `<linux/landlock.h>`.
     */
    val LANDLOCK_RULESET_ATTR: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("handled_access_fs"),
        ValueLayout.JAVA_LONG.withName("handled_access_net"),
    )

    /**
     * Corresponds to `struct landlock_path_beneath_attr` in `<linux/landlock.h>`.
     */
    val LANDLOCK_PATH_BENEATH_ATTR: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withByteAlignment(1).withName("allowed_access"),
        ValueLayout.JAVA_INT.withByteAlignment(1).withName("parent_fd"),
    )
}
