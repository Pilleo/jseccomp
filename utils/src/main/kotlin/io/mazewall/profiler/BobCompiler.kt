package io.mazewall.profiler

import io.mazewall.Syscall
import java.util.*

/**
 * BobCompiler parses system call trace events produced by the Profiler session
 * and aggregates them into a [BillOfBehavior].
 */
object BobCompiler {

    private const val O_WRONLY = 1L
    private const val O_RDWR = 2L
    private const val O_CREAT = 64L
    private const val O_TRUNC = 512L

    /**
     * Parses the given profiler trace events and returns a [BillOfBehavior].
     */
    fun compile(events: List<TraceEvent>): BillOfBehavior {
        val opens = mutableSetOf<String>()
        val fsWritePaths = mutableSetOf<String>()
        val syscalls = mutableSetOf<Syscall>()
        val execs = mutableSetOf<String>()

        for (event in events) {
            // Map the syscall name to Syscall enum
            val syscall = runCatching {
                Syscall.valueOf(event.syscallName.uppercase(Locale.US))
            }.getOrNull()

            if (syscall != null) {
                syscalls.add(syscall)
            }

            // Categorize paths
            val isWrite = isFileSystemMutation(event.syscallName) || isOpenWrite(event.syscallName, event.args)
            val isExec = event.syscallName == "EXECVE" || event.syscallName == "EXECVEAT"

            for (path in event.paths) {
                when {
                    isExec -> execs.add(path)
                    isWrite -> fsWritePaths.add(path)
                    else -> opens.add(path)
                }
            }
        }

        return BillOfBehavior(
            opens = opens,
            fsWritePaths = fsWritePaths,
            syscalls = syscalls,
            execs = execs
        )
    }

    private fun isFileSystemMutation(syscallName: String): Boolean {
        return syscallName in setOf(
            "MKDIR", "MKDIRAT",
            "RMDIR",
            "UNLINK", "UNLINKAT",
            "RENAME", "RENAMEAT", "RENAMEAT2",
            "LINK", "LINKAT",
            "SYMLINK", "SYMLINKAT",
            "CHMOD", "FCHMODAT",
            "CHOWN", "LCHOWN", "FCHOWNAT"
        )
    }

    private fun isOpenWrite(syscallName: String, args: LongArray): Boolean {
        if (syscallName == "OPENAT2") return true // Pointer to struct open_how, conservatively treat as write

        val flags = when (syscallName) {
            "OPEN" -> if (args.size > 1) args[1] else 0L
            "OPENAT" -> if (args.size > 2) args[2] else 0L
            else -> 0L
        }
        val accessMode = flags and 3L
        val isWriteMode = accessMode == O_WRONLY || accessMode == O_RDWR
        val hasCreateOrTrunc = (flags and O_CREAT) != 0L || (flags and O_TRUNC) != 0L
        return isWriteMode || hasCreateOrTrunc
    }
}
