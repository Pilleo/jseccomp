package io.mazewall

/**
 * Defines which syscalls to block. Create via [builder] or use the built-in presets.
 *
 * ### Modern Syscall Handling
 * This library uses BPF argument inspection to allow critical JVM operations while blocking
 * malicious ones:
 * - **`mmap`:** Standard memory mappings are allowed, but requests with `PROT_EXEC` (executable
 *   memory) are blocked to prevent shellcode execution.
 * - **`clone`:** Thread creation (`CLONE_THREAD`) is allowed to keep the JVM stable, but
 *   process forking (`fork`) is blocked.
 * - **`clone3`:** Blocked with `ENOSYS` to force runtimes to fallback to the inspectable legacy `clone`.
 *
 * ### JVM Classloading & JIT (Landlock Risks)
 * When using `allowFsRead` or `allowFsWrite`, the thread is restricted by Landlock. If a restricted worker
 * thread triggers the loading of a new class, the JVM must read `.jar` or `.class` files from the filesystem.
 * If Landlock blocks access to the classpath, the JVM will throw a `NoClassDefFoundError`.
 * **Mitigation:** Ensure all necessary classes are loaded before containment is applied, or explicitly
 * allow read access to the JVM classpath directories.
 *
 * Policies can be combined with [combine]:
 * ```kotlin
 * val p = Policy.combine(Policy.NO_NETWORK, Policy.NO_EXEC)
 * ```
 */
class Policy private constructor(
    internal val syscalls: Set<Syscall>,
    val mode: Mode = Mode.DENY_LIST,
    internal val allowMmapExec: Boolean = false,
    internal val allowNonThreadClone: Boolean = false,
    internal val allowUnsafePrctl: Boolean = false,
    internal val allowedFsReadPaths: Set<String> = emptySet(),
    internal val allowedFsWritePaths: Set<String> = emptySet(),
    internal val enforceLandlock: Boolean = false
) {

    enum class Mode {
        /** Only explicitly allowed syscalls are permitted. Default deny. */
        ALLOW_LIST,

        /** All syscalls except those explicitly blocked are permitted. Default allow. */
        DENY_LIST
    }


    /** 
     * Returns true if the given [syscall] is allowed by this policy. 
     * This considers both the mode (ALLOW_LIST vs DENY_LIST) and the syscalls set.
     */
    fun isSyscallAllowed(syscall: Syscall): Boolean {
        return if (mode == Mode.DENY_LIST) {
            !syscalls.contains(syscall)
        } else {
            syscalls.contains(syscall)
        }
    }

    /** Returns the concrete syscall numbers to restrict for the given [arch]. */
    fun syscallNumbers(arch: Arch): IntArray =
        syscalls
            .map { it.numberFor(arch) }
            .filter { it >= 0 } // -1 means "not available on this arch"
            .sorted()
            .toIntArray()


    companion object {
        /** Blocks all network I/O, process execution, and file opens. Suitable for pure computation tasks. */
        val PURE_COMPUTE: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2)
            .block(Syscall.RENAME, Syscall.RENAMEAT, Syscall.RENAMEAT2)
            .block(Syscall.LINK, Syscall.LINKAT, Syscall.UNLINK, Syscall.UNLINKAT)
            .block(Syscall.SYMLINK, Syscall.SYMLINKAT, Syscall.READLINK, Syscall.READLINKAT)
            .block(Syscall.MKDIR, Syscall.MKDIRAT, Syscall.RMDIR)
            .block(Syscall.CHMOD, Syscall.FCHMOD, Syscall.FCHMODAT)
            .block(Syscall.CHOWN, Syscall.LCHOWN, Syscall.FCHOWN, Syscall.FCHOWNAT)
            .block(Syscall.UMASK, Syscall.UTIME, Syscall.UTIMES, Syscall.UTIMENSAT)
            .block(Syscall.TRUNCATE, Syscall.FTRUNCATE)
            .block(Syscall.MEMFD_CREATE, Syscall.PTRACE)
            .block(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER, Syscall.BPF)
            .block(Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV)
            .block(Syscall.USERFAULTFD, Syscall.UNSHARE, Syscall.SETNS)
            .block(Syscall.MOUNT, Syscall.UMOUNT2, Syscall.PIVOT_ROOT, Syscall.CHROOT)
            .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
            .build()

        /** Blocks outbound network syscalls only. */
        val NO_NETWORK: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
            .block(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
            .build()

        /** Blocks process execution syscalls and bypasses like fileless execution. */
        val NO_EXEC: Policy = builder()
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.FORK, Syscall.VFORK)
            .block(Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER, Syscall.PTRACE)
            .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
            .build()

        /**
         * A highly restrictive baseline that blocks all network, execution, and most filesystem access.
         * Automatically whitelists the JVM classpath to prevent lazy classloading deadlocks.
         * Suitable for worker threads that only perform pure computation using pre-loaded data.
         */
        val STRICT_SANDBOX: Policy = builder()
            .base(PURE_COMPUTE)
            .allowJvmClasspath()
            .build()


        fun builder(): Builder = Builder()

        /**
         * Returns a new Policy that is the combination of all given [policies].
         *
         * ### Combination Logic
         * - If all policies are [Mode.DENY_LIST], the result is the **union** of blocked syscalls.
         * - If all policies are [Mode.ALLOW_LIST], the result is the **intersection** of allowed syscalls.
         * - Mixed modes are currently not supported in `combine` and will throw [IllegalArgumentException].
         *
         * ### Landlock Convergence (Intersection)
         * Unlike syscall blocks (which are unioned), allowed Landlock filesystem paths are
         * **intersected**. This matches the behavior of the Linux kernel when multiple Landlock
         * rulesets are stacked on a single thread. If one policy allows `/a` and another allows `/b`,
         * the combined policy will allow **nothing** (unless one is a parent of the other).
         *
         * Exception: If no Landlock paths are defined in any input policy, the result remains empty
         * (unrestricted filesystem from a Landlock perspective).
         */
        fun combine(vararg policies: Policy): Policy {
            require(policies.isNotEmpty()) { "At least one policy is required" }
            val mode = policies.first().mode
            require(policies.all { it.mode == mode }) { "Cannot combine policies with different modes: ${policies.map { it.mode }}" }

            val combinedSyscalls = if (mode == Mode.DENY_LIST) {
                policies.flatMap { it.syscalls }.toSet()
            } else {
                policies.map { it.syscalls }.reduce { acc, set -> acc.intersect(set) }
            }

            val mmapExec = policies.all { it.allowMmapExec }
            val cloneNonThread = policies.all { it.allowNonThreadClone }
            val unsafePrctl = policies.all { it.allowUnsafePrctl }

            // Intersect Landlock paths to match kernel stacking behavior
            val allReadSets = policies.map { it.allowedFsReadPaths }.filter { it.isNotEmpty() }
            val fsReads =
                if (allReadSets.isEmpty()) emptySet() else allReadSets.reduce { acc, set -> acc.intersect(set) }

            val allWriteSets = policies.map { it.allowedFsWritePaths }.filter { it.isNotEmpty() }
            val fsWrites =
                if (allWriteSets.isEmpty()) emptySet() else allWriteSets.reduce { acc, set -> acc.intersect(set) }

            val enforceLandlock = policies.any { it.enforceLandlock }

            return Policy(
                combinedSyscalls,
                mode = mode,
                allowMmapExec = mmapExec,
                allowNonThreadClone = cloneNonThread,
                allowUnsafePrctl = unsafePrctl,
                allowedFsReadPaths = fsReads,
                allowedFsWritePaths = fsWrites,
                enforceLandlock = enforceLandlock
            )
        }
    }

    class Builder {
        private val syscalls = mutableSetOf<Syscall>()
        private var mode = Mode.DENY_LIST
        private var allowMmapExec = false
        private var allowNonThreadClone = false
        private var allowUnsafePrctl = false
        private val allowedFsReadPaths = mutableSetOf<String>()
        private val allowedFsWritePaths = mutableSetOf<String>()

        fun mode(mode: Mode): Builder {
            this.mode = mode
            return this
        }

        /** Alias for [block] when in [Mode.DENY_LIST] or simply adds to the restricted set. */
        fun block(vararg syscalls: Syscall): Builder {
            this.syscalls.addAll(syscalls)
            return this
        }

        /** Alias for [block]. In [Mode.ALLOW_LIST], this explicitly allows the syscalls. */
        fun allow(vararg syscalls: Syscall): Builder {
            this.syscalls.addAll(syscalls)
            return this
        }

        fun unblock(vararg syscalls: Syscall): Builder {
            this.syscalls.removeAll(syscalls.toSet())
            return this
        }

        /**
         * Inherits all settings (syscalls, mode, allowed paths, etc.) from the given [policy].
         */
        fun base(policy: Policy): Builder {
            this.mode = policy.mode
            this.syscalls.addAll(policy.syscalls)
            if (policy.allowMmapExec) allowMmapExec = true
            if (policy.allowNonThreadClone) allowNonThreadClone = true
            if (policy.allowUnsafePrctl) allowUnsafePrctl = true
            allowedFsReadPaths.addAll(policy.allowedFsReadPaths)
            allowedFsWritePaths.addAll(policy.allowedFsWritePaths)
            return this
        }


        /**
         * Allows reading from the specified file or directory path (and its children).
         * Note: Setting any FS paths enables Landlock enforcement for this policy.
         */
        fun allowFsRead(path: String): Builder {
            require(path.isNotEmpty()) { "Path cannot be empty" }
            require(path.startsWith("/")) { "Path must be absolute" }
            require(!path.contains('\u0000')) { "Path cannot contain null bytes" }
            allowedFsReadPaths.add(path)
            return this
        }

        /**
         * Convenience method to allow reading from the JVM's classpath.
         * This is CRITICAL if your worker threads might trigger lazy classloading
         * after the Landlock ruleset is applied.
         */
        fun allowJvmClasspath(): Builder {
            val javaHome = System.getProperty("java.home")
            if (!javaHome.isNullOrEmpty()) allowFsRead(javaHome)

            val classPath = System.getProperty("java.class.path")
            if (classPath != null) {
                classPath.split(java.io.File.pathSeparator).forEach {
                    if (it.isNotEmpty()) {
                        val file = java.io.File(it)
                        if (file.exists()) {
                            val path = if (file.isDirectory) file.absolutePath else file.absoluteFile.parent
                            if (path != null) allowFsRead(path)
                        }
                    }
                }
            }
            return this
        }

        /**
         * Allows writing to the specified file or directory path (and its children).
         * Note: Setting any FS paths enables Landlock enforcement for this policy.
         */
        fun allowFsWrite(path: String): Builder {
            require(path.isNotEmpty()) { "Path cannot be empty" }
            require(path.startsWith("/")) { "Path must be absolute" }
            require(!path.contains('\u0000')) { "Path cannot contain null bytes" }
            allowedFsWritePaths.add(path)
            return this
        }

        /**
         * Allows `mmap` with `PROT_EXEC`. By default, this is blocked for all policies
         * to prevent shellcode execution.
         */
        fun allowMmapExec(): Builder {
            this.allowMmapExec = true
            return this
        }

        /**
         * Allows `clone` without `CLONE_THREAD`. By default, this is blocked to prevent
         * process forking while allowing JVM thread creation.
         */
        fun allowNonThreadClone(): Builder {
            this.allowNonThreadClone = true
            return this
        }

        /**
         * Allows unrestricted `prctl` calls. By default, unsafe/hazardous options of
         * `prctl` are blocked, while safe options needed by the JVM (like `PR_SET_NAME`)
         * are allowed via BPF argument inspection.
         */
        fun allowUnsafePrctl(): Builder {
            this.allowUnsafePrctl = true
            return this
        }

        fun build(): Policy = Policy(
            syscalls.toSet(),
            mode,
            allowMmapExec,
            allowNonThreadClone,
            allowUnsafePrctl,
            allowedFsReadPaths.toSet(),
            allowedFsWritePaths.toSet(),
            enforceLandlock = allowedFsReadPaths.isNotEmpty() || allowedFsWritePaths.isNotEmpty()
        )
    }
}
