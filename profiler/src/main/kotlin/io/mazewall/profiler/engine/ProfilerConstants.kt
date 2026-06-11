package io.mazewall.profiler.engine

import java.lang.foreign.ValueLayout

internal const val ADDR_UN_SIZE = 110
internal const val SOCKADDR_UN_PATH_SIZE = 108
internal const val BACKLOG_SIZE = 128
internal const val AF_UNIX = 1
internal const val SOCK_STREAM = 1
internal const val MSG_PEEK = 2
internal const val EINTR = 4
internal const val POLL_ACK_TIMEOUT_MS = 60000
internal const val POLL_TIMEOUT_MS = 500
internal const val PROTOCOL_ACK_BYTE = 0xAC.toByte()
internal const val SHUTDOWN_COMMAND_BYTE = 0x53.toByte() // 'S'
internal const val ACK_BUF_SIZE = 1L
internal const val NOTIF_ID_OFF = 0L
internal const val NOTIF_PID_OFF = 8L
internal const val NOTIF_NR_OFF = 16L
internal const val NOTIF_ARGS_OFF = 32L
internal const val RESP_ID_OFF = 0L
internal const val RESP_VAL_OFF = 8L
internal const val RESP_ERR_OFF = 16L
internal const val RESP_FLAGS_OFF = 20L
internal const val POLLFD_FD_OFF = 0L
internal const val POLLFD_EVENTS_OFF = 4L
internal const val POLLFD_REVENTS_OFF = 6L
internal val POLLFD_REVENT_DATA_OFF = ValueLayout.JAVA_LONG.byteSize() + POLLFD_REVENTS_OFF

internal const val MAX_SYSCALL_ARGS = 6
internal const val ARG_DIR_FD = 0
internal const val ARG_PATH = 1
internal const val ARG_OLD_DIR_FD = 0
internal const val ARG_OLD_PATH = 1
internal const val ARG_NEW_DIR_FD = 2
internal const val ARG_NEW_PATH = 3

internal const val AT_FDCWD_VAL = -100L
internal const val AT_FDCWD_UNSIGNED_VAL = 4294967196L
internal const val AT_FDCWD_INT_VAL = -100
internal const val SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100L
internal const val SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101L
