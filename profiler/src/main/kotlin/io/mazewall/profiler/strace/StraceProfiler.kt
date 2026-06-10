package io.mazewall.profiler.strace

import io.mazewall.core.Syscall
import io.mazewall.profiler.BillOfBehavior
import io.mazewall.profiler.TraceableWorkload
import java.io.File

/**
 * Tier P Profiler: Traces system calls and path accesses of a workload class
 * by running it in a child JVM process wrapped directly under Linux `strace`.
 *
 * This allows safe, high-speed profiling in rootless, unprivileged containers
 * bypassing Yama ptrace scope restrictions.
 */
object StraceProfiler {
    fun <T : TraceableWorkload> profile(workloadClass: Class<T>): BillOfBehavior {
        val javaBin = System.getProperty("java.home") + "/bin/java"
        val classpath = System.getProperty("java.class.path")

        // Create a temporary strace log file
        val tempLog = File.createTempFile("strace_prof_", ".log")
        tempLog.deleteOnExit()

        // Assemble the strace child JVM command
        val cmd = listOf(
            "strace",
            "-f",
            "-e",
            "trace=file,network",
            "-o",
            tempLog.absolutePath,
            javaBin,
            "-cp",
            classpath,
            "io.mazewall.profiler.strace.StraceWorkloadRunner",
            workloadClass.name,
        )

        // Spawn the process
        val pb = ProcessBuilder(cmd)
        val process = pb.start()

        // Wait for the process to finish
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            val errText = process.errorStream.bufferedReader().readText()
            val outText = process.inputStream.bufferedReader().readText()
            throw IllegalStateException("Child JVM failed with exit code $exitCode. Stdout: $outText, Stderr: $errText")
        }

        // Read and parse the log file
        val opens = mutableSetOf<String>()
        val fsWritePaths = mutableSetOf<String>()
        val syscalls = mutableSetOf<Syscall>()

        if (tempLog.exists()) {
            tempLog.forEachLine { line ->
                parseLine(line, opens, fsWritePaths, syscalls)
            }
            tempLog.delete()
        }

        return BillOfBehavior(
            opens = opens,
            fsWritePaths = fsWritePaths,
            syscalls = syscalls,
        )
    }

    private fun parseLine(
        line: String,
        opens: MutableSet<String>,
        fsWritePaths: MutableSet<String>,
        syscalls: MutableSet<Syscall>,
    ) {
        val cleaned = line.trim()
        if (cleaned.isEmpty() || cleaned.startsWith("+++") || cleaned.startsWith("---")) return

        // Extract syscall name
        val beforeParen = cleaned.substringBefore("(", "")
        if (beforeParen.isEmpty()) return

        // Handle PID prefix in "strace -f" lines (e.g. "12345 openat(...)")
        val syscallName = beforeParen.split("\\s+".toRegex()).last().uppercase()
        val syscall = try {
            Syscall.valueOf(syscallName)
        } catch (ignored: IllegalArgumentException) {
            null
        }

        if (syscall != null) {
            syscalls.add(syscall)
        }

        // Extract path if it is a filesystem call
        if (isFsSyscall(syscallName)) {
            val args = cleaned.substringAfter("(", "")
            val path = extractQuotedPath(args)
            if (path != null) {
                if (isWriteSyscall(syscallName, args)) {
                    fsWritePaths.add(path)
                } else {
                    opens.add(path)
                }
            }
        }
    }

    private fun isFsSyscall(name: String): Boolean {
        return name in setOf(
            "OPEN",
            "OPENAT",
            "OPENAT2",
            "STAT",
            "STATX",
            "LSTAT",
            "ACCESS",
            "READLINK",
            "READLINKAT",
            "MKDIR",
            "MKDIRAT",
            "RMDIR",
            "UNLINK",
            "UNLINKAT",
            "RENAME",
            "RENAMEAT",
            "RENAMEAT2",
            "CHMOD",
            "FCHMODAT",
            "CHOWN",
            "FCHOWNAT",
        )
    }

    private fun isWriteSyscall(
        name: String,
        args: String,
    ): Boolean {
        val isWriteOp = name in setOf(
            "MKDIR",
            "MKDIRAT",
            "RMDIR",
            "UNLINK",
            "UNLINKAT",
            "RENAME",
            "RENAMEAT",
            "RENAMEAT2",
            "CHMOD",
            "FCHMODAT",
            "CHOWN",
            "FCHOWNAT",
        )
        val isOpen = name == "OPEN" || name == "OPENAT" || name == "OPENAT2"
        val isOpenWrite = isOpen &&
            (
            args.contains("O_WRONLY") ||
            args.contains("O_RDWR") ||
            args.contains("O_CREAT") ||
            args.contains("O_TRUNC") ||
            args.contains("O_APPEND")
        )
        return isWriteOp || isOpenWrite
    }

    private fun extractQuotedPath(args: String): String? {
        val match = "\"(.*?)\"".toRegex().find(args)
        return match?.groupValues?.get(1)
    }
}
