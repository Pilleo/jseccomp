package io.contained

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
    internal val blocked: Set<Syscall>,
    internal val allowMmapExec: Boolean = false,
    internal val allowNonThreadClone: Boolean = false,
    internal val allowUnsafePrctl: Boolean = false,
    internal val allowedFsReadPaths: Set<String> = emptySet(),
    internal val allowedFsWritePaths: Set<String> = emptySet()
) {

    /** Returns the concrete syscall numbers to block for the given [arch]. */
    fun blockedSyscalls(arch: Arch): IntArray =
        blocked
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
            .block(Syscall.MEMFD_CREATE, Syscall.PTRACE)
            .block(Syscall.IO_URING_SETUP, Syscall.BPF)
            .block(Syscall.PROCESS_VM_WRITEV, Syscall.PROCESS_VM_READV)
            .block(Syscall.USERFAULTFD, Syscall.UNSHARE, Syscall.SETNS)
            .block(Syscall.MOUNT, Syscall.UMOUNT2, Syscall.PIVOT_ROOT, Syscall.CHROOT)
            .block(Syscall.IOCTL)
            .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
            .build()

        /** Blocks outbound network syscalls only. */
        val NO_NETWORK: Policy = builder()
            .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SOCKET)
            .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
            .build()

        /** Blocks process execution syscalls and bypasses like fileless execution. */
        val NO_EXEC: Policy = builder()
            .block(Syscall.EXECVE, Syscall.EXECVEAT)
            .block(Syscall.FORK, Syscall.VFORK)
            .block(Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.PTRACE)
            .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
            .build()


        fun builder(): Builder = Builder()

        /** Returns a new Policy that is the union of all blocked syscalls in the given [policies]. */
        fun combine(vararg policies: Policy): Policy {
            val union = policies.flatMap { it.blocked }.toSet()
            val mmapExec = policies.all { it.allowMmapExec }
            val cloneNonThread = policies.all { it.allowNonThreadClone }
            val unsafePrctl = policies.all { it.allowUnsafePrctl }
            val fsReads = policies.flatMap { it.allowedFsReadPaths }.toSet()
            val fsWrites = policies.flatMap { it.allowedFsWritePaths }.toSet()
            return Policy(
                union,
                allowMmapExec = mmapExec,
                allowNonThreadClone = cloneNonThread,
                allowUnsafePrctl = unsafePrctl,
                allowedFsReadPaths = fsReads,
                allowedFsWritePaths = fsWrites
            )
        }
    }

    class Builder {
        private val blocked = mutableSetOf<Syscall>()
        private var allowMmapExec = false
        private var allowNonThreadClone = false
        private var allowUnsafePrctl = false
        private val allowedFsReadPaths = mutableSetOf<String>()
        private val allowedFsWritePaths = mutableSetOf<String>()

        fun block(vararg syscalls: Syscall): Builder {
            blocked.addAll(syscalls)
            return this
        }

        fun unblock(vararg syscalls: Syscall): Builder {
            blocked.removeAll(syscalls.toSet())
            return this
        }

        /**
         * Inherits all settings (blocked syscalls, allowed paths, etc.) from the given [policy].
         */
        fun base(policy: Policy): Builder {
            blocked.addAll(policy.blocked)
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
            blocked.toSet(),
            allowMmapExec,
            allowNonThreadClone,
            allowUnsafePrctl,
            allowedFsReadPaths.toSet(),
            allowedFsWritePaths.toSet()
        )
    }
}
