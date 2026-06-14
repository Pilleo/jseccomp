package io.mazewall

import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.seccomp.BpfInstruction

/**
 * Marker interfaces for policy scopes.
 */
sealed interface PolicyScope {
    /** Safe for process-wide or thread-scoped containment. */
    interface ProcessWideSafe : PolicyScope

    /** Enforces Landlock filesystem restrictions; restricted to thread-local containment. */
    interface ThreadLocalOnly : PolicyScope
}

/**
 * A compiled seccomp policy containing the BPF filter instructions ready for installation.
 */
sealed interface PolicyState
interface Uncompiled : PolicyState
interface Compiled : PolicyState
interface Applied : PolicyState

/**
 * Defines which syscalls to block. Create via [builder] or use the built-in presets.
 *
 * ### Built-in Preset Decision Guide
 * | Preset | Blocks | JVM-Safe | Use when |
 * |--------|--------|----------|----------|
 * | [NO_EXEC] | exec, fork, memfd | ✅ | Process-wide startup lockdown |
 * | [NO_NETWORK] | all network syscalls | ✅ | Parsers needing local FS |
 * | [PURE_COMPUTE] | network + exec + most FS | ✅ | **Recommended default** for worker pools |
 * | [PURE_COMPUTE_UNSAFE] | same as PURE_COMPUTE | ⚠️ | Low-level building block only |
 *
 * ### Modern Syscall Handling
 * This library uses BPF argument inspection to allow critical JVM operations while blocking
 * malicious ones:
 * - **`mmap`:** Standard memory mappings are allowed, but requests with `PROT_EXEC` (executable
 *   memory) are blocked by default to prevent shellcode execution.
 *   **Note:** The OpenJDK JVM often requires `mmap(PROT_EXEC)` for JIT compilation and native library
 *   linking (e.g. Tomcat native). Blocking this process-wide can lead to `os::commit_memory`
 *   failures or JVM crashes, even after the application has fully started. Consider using
 *   [Builder.allowMmapExec] for process-wide baselines.
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
class Policy<out S : PolicyScope, out State : PolicyState> private constructor(
    val defaultAction: SeccompAction = SeccompAction.ACT_ALLOW,
    val syscallActions: Map<Syscall, SeccompAction>,
    val allowMmapExec: Boolean = false,
    val allowNonThreadClone: Boolean = false,
    val allowUnsafePrctl: Boolean = false,
    val allowedFsReadPaths: Set<String> = emptySet(),
    val allowedFsWritePaths: Set<String> = emptySet(),
    internal val enforceLandlock: Boolean = false,
    private val compiledFiltersField: List<BpfInstruction>? = null,
) {
    val compiledFilters: List<BpfInstruction>
        get() = compiledFiltersField ?: throw IllegalStateException("Policy is not compiled yet")

    /**
     * Compiles this policy for the given [arch] and transitions it to the Compiled state.
     */
    fun compile(arch: Arch): Policy<S, Compiled> {
        val filters = BpfFilter.build(arch, this)
        return Policy(
            defaultAction = defaultAction,
            syscallActions = syscallActions,
            allowMmapExec = allowMmapExec,
            allowNonThreadClone = allowNonThreadClone,
            allowUnsafePrctl = allowUnsafePrctl,
            allowedFsReadPaths = allowedFsReadPaths,
            allowedFsWritePaths = allowedFsWritePaths,
            enforceLandlock = enforceLandlock,
            compiledFiltersField = filters,
        )
    }

    /** Returns true if the given [syscall] is unconditionally allowed by this policy. */
    fun isSyscallAllowed(syscall: Syscall): Boolean {
        val action = syscallActions[syscall] ?: defaultAction
        return action == SeccompAction.ACT_ALLOW
    }

    /** Returns the concrete syscall numbers and their associated actions for the given [arch]. */
    fun syscallActionNumbers(arch: Arch): Map<Int, SeccompAction> {
        val result = java.util.TreeMap<Int, SeccompAction>()
        for ((syscall, action) in syscallActions) {
            val nr = syscall.numberFor(arch)
            if (nr >= 0) {
                val current = result[nr]
                if (current == null || action.priority > current.priority) {
                    result[nr] = action
                }
            }
        }
        return result
    }

    companion object {
        private val logger = java.util.logging.Logger
            .getLogger(Policy::class.java.name)

        /**
         * Low-level building block. Blocks all network I/O, process execution, and file opens
         * (including `open`, `openat`, `openat2`).
         *
         * ⚠️ **NOT SAFE FOR DIRECT USE ON THE JVM:** Blocking `open`/`openat`/`openat2` prevents
         * JVM lazy class loading. Any worker thread that hasn't pre-loaded all required classes
         * will crash with `NoClassDefFoundError` when it hits a new class load.
         *
         * **Use [PURE_COMPUTE] instead** — it adds [Builder.allowJvmClasspath] to prevent
         * class-loading deadlocks while retaining the same security posture.
         *
         * Only use this preset directly if you have complete startup warmup control and
         * have verified that every class the thread will ever touch is already loaded.
         */
        val PURE_COMPUTE_UNSAFE: Policy<PolicyScope.ProcessWideSafe, Uncompiled> =
            builder()
                .defaultAction(SeccompAction.ACT_ALLOW)
                .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SENDMMSG, Syscall.RECVMMSG, Syscall.SOCKET)
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

        /**
         * Blocks outbound network syscalls only.
         *
         * ### JIT Compiler Warning
         * `allowMmapExec` defaults to `false` on ALL policies, including this one. When this
         * policy is installed **process-wide** via [io.mazewall.enforcer.ContainedExecutors.installOnProcess],
         * the BPF filter emits the `mmap(PROT_EXEC)` argument-inspection sequence, which blocks
         * the JVM's JIT compiler background threads from allocating code-cache pages.
         * This causes a fatal JVM abort: `os::commit_memory failed; error='Operation not permitted'`.
         *
         * **If you do not also intend to block JIT compilation, use:**
         * ```kotlin
         * Policy.builder().base(Policy.NO_NETWORK).allowMmapExec().build()
         * ```
         *
         * The built-in `NO_NETWORK` preset without `allowMmapExec()` is only safe for
         * process-wide use if the JIT compiler is known to be disabled (e.g. `-Xint` in tests)
         * or if the policy is applied before any JIT compilation has started.
         */
        val NO_NETWORK: Policy<PolicyScope.ProcessWideSafe, Uncompiled> =
            builder()
                .defaultAction(SeccompAction.ACT_ALLOW)
                .block(Syscall.CONNECT, Syscall.SENDTO, Syscall.SENDMSG, Syscall.SENDMMSG, Syscall.RECVMMSG, Syscall.SOCKET)
                .block(Syscall.BIND, Syscall.LISTEN, Syscall.ACCEPT, Syscall.ACCEPT4)
                .block(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
                .build()

        /**
         * Blocks process execution syscalls and bypasses like fileless execution.
         *
         * ### JIT & Native Linking Conflict
         * This preset strictly blocks `mmap` with `PROT_EXEC`. While this provides strong
         * defense-in-depth against shellcode, it may conflict with the JVM's JIT compiler
         * or native library linking (e.g., Tomcat/APR), causing `os::commit_memory` crashes.
         *
         * **Recommendation:**
         * 1. **Delay:** Apply process-wide lockdown as late as possible (e.g., Spring's
         *    `ApplicationReadyEvent`) to allow the JVM to warm up and link libraries.
         * 2. **Balanced Baseline:** If crashes persist after warmup, use `Policy.builder().base(NO_EXEC).allowMmapExec().build()`.
         */
        val NO_EXEC: Policy<PolicyScope.ProcessWideSafe, Uncompiled> =
            builder()
                .defaultAction(SeccompAction.ACT_ALLOW)
                .block(Syscall.EXECVE, Syscall.EXECVEAT)
                .block(Syscall.FORK, Syscall.VFORK)
                .block(Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER, Syscall.PTRACE)
                .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
                .build()

        /**
         * The recommended default for pure-computation worker threads.
         *
         * Blocks all network I/O, process execution, and most filesystem access —
         * the same security posture as [PURE_COMPUTE_UNSAFE] — while **automatically
         * whitelisting the JVM classpath** via [Builder.allowJvmClasspath] to prevent
         * lazy class-loading deadlocks (`NoClassDefFoundError`).
         *
         * ### When to use each preset
         * - **Use [PURE_COMPUTE]** (this preset) for any worker pool. It is safe by default.
         * - **Use [PURE_COMPUTE_UNSAFE]** only when you have fully pre-loaded all required
         *   classes before the thread starts and need to eliminate the classpath read permission.
         */
        val PURE_COMPUTE: Policy<PolicyScope.ThreadLocalOnly, Uncompiled> =
            builder()
                .base(PURE_COMPUTE_UNSAFE)
                .allowJvmClasspath()
                .build()

        fun builder(): Builder<PolicyScope.ProcessWideSafe> = Builder()

        private fun intersectPaths(
            set1: Set<String>,
            set2: Set<String>,
        ): Set<String> {
            if (set1.isEmpty() || set2.isEmpty()) return emptySet()

            val result = mutableSetOf<String>()
            val sortedSet2 = java.util.TreeSet(set2)

            for (p1 in set1) {
                val potentialParent = sortedSet2.floor(p1)
                if (potentialParent != null && isParent(potentialParent, p1)) {
                    result.add(p1)
                }

                val tail = sortedSet2.tailSet(p1, false)
                for (p2 in tail) {
                    if (isParent(p1, p2)) {
                        result.add(p2)
                    } else {
                        break
                    }
                }
            }
            return result
        }

        private fun isParent(
            parent: String,
            child: String,
        ): Boolean {
            if (parent == child) return true
            val parentWithSlash = if (parent.endsWith("/")) parent else "$parent/"
            return child.startsWith(parentWithSlash)
        }

        /**
         * Returns a new Policy that is the combination of all given [policies].
         *
         * ### Combination Logic
         * - The defaultAction resolves to the highest priority default action among policies.
         * - Syscall actions are merged. If multiple policies map the same syscall to different actions,
         *   the more restrictive action (higher priority) wins.
         *
         * ### Landlock Convergence (Intersection)
         * Unlike syscall blocks (which are unioned), allowed Landlock filesystem paths are
         * **intersected**. This matches the behavior of the Linux kernel when multiple Landlock
         * rulesets are stacked on a single thread. If one policy allows `/a` and another allows `/b`,
         * the combined policy will allow **nothing** (unless one is a parent of the other).
         *
         * A `WARNING` is logged if Landlock is enforced but the path intersection collapses to empty
         * (meaning all filesystem access will be blocked). A `FINE` log is always emitted summarising
         * the merged result — useful when debugging unexpected containment violations.
         */
        @JvmStatic
        @JvmName("combineProcessWide")
        fun combine(vararg policies: Policy<PolicyScope.ProcessWideSafe, *>): Policy<PolicyScope.ProcessWideSafe, Uncompiled> {
            @Suppress("UNCHECKED_CAST")
            return combineInternal(*policies) as Policy<PolicyScope.ProcessWideSafe, Uncompiled>
        }

        @JvmStatic
        fun combine(vararg policies: Policy<*, *>): Policy<*, Uncompiled> {
            return combineInternal(*policies)
        }

        private fun combineInternal(vararg policies: Policy<*, *>): Policy<*, Uncompiled> {
            require(policies.isNotEmpty()) { "At least one policy is required" }

            val combinedDefaultAction = policies.maxByOrNull { it.defaultAction.priority }!!.defaultAction

            val combinedSyscalls = mutableMapOf<Syscall, SeccompAction>()
            for (policy in policies) {
                for ((syscall, action) in policy.syscallActions) {
                    val current = combinedSyscalls[syscall]
                    if (current == null || action.priority > current.priority) {
                        combinedSyscalls[syscall] = action
                    }
                }
            }

            val mmapExec = policies.all { it.allowMmapExec }
            val cloneNonThread = policies.all { it.allowNonThreadClone }
            val unsafePrctl = policies.all { it.allowUnsafePrctl }

            // Intersect Landlock paths to match kernel stacking behavior
            val allReadSets = policies.map { it.allowedFsReadPaths }.filter { it.isNotEmpty() }
            val fsReads =
                if (allReadSets.isEmpty()) emptySet() else allReadSets.reduce { acc, set -> intersectPaths(acc, set) }

            val allWriteSets = policies.map { it.allowedFsWritePaths }.filter { it.isNotEmpty() }
            val fsWrites =
                if (allWriteSets.isEmpty()) emptySet() else allWriteSets.reduce { acc, set -> intersectPaths(acc, set) }

            val enforceLandlock = policies.any { it.enforceLandlock }

            // Warn when Landlock is active but the path intersection collapses — this means
            // ALL filesystem reads (or writes) will be denied, which is almost always a mistake.
            if (enforceLandlock && fsReads.isEmpty() && allReadSets.isNotEmpty()) {
                logger.warning(
                    "Policy.combine(): Landlock is enforced but the read-path intersection is empty. " +
                        "The combined policy will DENY ALL filesystem reads. " +
                        "${allReadSets.size} input policies had non-empty read-path sets with no common ancestor. " +
                        "Ensure at least one path is a common parent of all allowed paths.",
                )
            }
            if (enforceLandlock && fsWrites.isEmpty() && allWriteSets.isNotEmpty()) {
                logger.warning(
                    "Policy.combine(): Landlock is enforced but the write-path intersection is empty. " +
                        "The combined policy will DENY ALL filesystem writes. " +
                        "${allWriteSets.size} input policies had non-empty write-path sets with no common ancestor.",
                )
            }

            if (enforceLandlock) {
                // Landlock requires OPEN, OPENAT, OPENAT2 to function correctly.
                combinedSyscalls[Syscall.OPEN] = SeccompAction.ACT_ALLOW
                combinedSyscalls[Syscall.OPENAT] = SeccompAction.ACT_ALLOW
                combinedSyscalls[Syscall.OPENAT2] = SeccompAction.ACT_ALLOW
            }

            logger.fine {
                "Policy.combine(${policies.size} policies): " +
                    "defaultAction=$combinedDefaultAction, " +
                    "blockedSyscalls=${combinedSyscalls.count { it.value != SeccompAction.ACT_ALLOW }}, " +
                    "readPaths=${fsReads.size}, writePaths=${fsWrites.size}, " +
                    "enforceLandlock=$enforceLandlock"
            }

            return Policy<PolicyScope, Uncompiled>(
                defaultAction = combinedDefaultAction,
                syscallActions = combinedSyscalls,
                allowMmapExec = mmapExec,
                allowNonThreadClone = cloneNonThread,
                allowUnsafePrctl = unsafePrctl,
                allowedFsReadPaths = fsReads,
                allowedFsWritePaths = fsWrites,
                enforceLandlock = enforceLandlock,
            )
        }
    }

    class Builder<S : PolicyScope> internal constructor(
        private var defaultAction: SeccompAction = SeccompAction.ACT_ALLOW,
        private val syscallActions: MutableMap<Syscall, SeccompAction> = mutableMapOf(),
        private var allowMmapExec: Boolean = false,
        private var allowNonThreadClone: Boolean = false,
        private var allowUnsafePrctl: Boolean = false,
        private val allowedFsReadPaths: MutableSet<String> = mutableSetOf(),
        private val allowedFsWritePaths: MutableSet<String> = mutableSetOf(),
    ) {
        /** Sets the default action for any syscall not explicitly mapped. Defaults to ACT_ALLOW (Blacklist mode). */
        fun defaultAction(action: SeccompAction): Builder<S> {
            this.defaultAction = action
            return this
        }

        /** Maps the given syscalls to a specific action. */
        fun addAction(
            action: SeccompAction,
            vararg syscalls: Syscall,
        ): Builder<S> {
            for (sys in syscalls) {
                syscallActions[sys] = action
            }
            return this
        }

        /** Alias for mapping syscalls to ACT_ERRNO. Useful for Blacklists. */
        fun block(vararg syscalls: Syscall): Builder<S> = addAction(SeccompAction.ACT_ERRNO, *syscalls)

        /** Alias for mapping syscalls to ACT_ALLOW. Useful for Whitelists (SBoB). */
        fun allow(vararg syscalls: Syscall): Builder<S> = addAction(SeccompAction.ACT_ALLOW, *syscalls)

        fun unblock(vararg syscalls: Syscall): Builder<S> {
            for (sys in syscalls) {
                syscallActions.remove(sys)
            }
            return this
        }

        /**
         * Inherits all settings (actions, allowed paths, etc.) from the given [policy].
         */
        fun <T : PolicyScope> base(policy: Policy<T, *>): Builder<T> {
            this.defaultAction = policy.defaultAction
            this.syscallActions.putAll(policy.syscallActions)
            if (policy.allowMmapExec) allowMmapExec = true
            if (policy.allowNonThreadClone) allowNonThreadClone = true
            if (policy.allowUnsafePrctl) allowUnsafePrctl = true
            allowedFsReadPaths.addAll(policy.allowedFsReadPaths)
            allowedFsWritePaths.addAll(policy.allowedFsWritePaths)
            @Suppress("UNCHECKED_CAST")
            return this as Builder<T>
        }

        /**
         * Allows reading from the specified file or directory path (and its children).
         * Note: Setting any FS paths enables Landlock enforcement for this policy.
         */
        fun allowFsRead(path: String): Builder<PolicyScope.ThreadLocalOnly> {
            validatePath(path)
            allowedFsReadPaths.add(path)
            @Suppress("UNCHECKED_CAST")
            return this as Builder<PolicyScope.ThreadLocalOnly>
        }

        /**
         * Convenience method to allow reading from the JVM's classpath.
         * This is CRITICAL if your worker threads might trigger lazy classloading
         * after the Landlock ruleset is applied.
         */
        fun allowJvmClasspath(): Builder<PolicyScope.ThreadLocalOnly> {
            val javaHome = System.getProperty("java.home")
            if (!javaHome.isNullOrEmpty()) allowFsRead(javaHome)

            val classPath = System.getProperty("java.class.path")
            if (classPath != null) {
                addClasspathEntries(classPath)
            }
            @Suppress("UNCHECKED_CAST")
            return this as Builder<PolicyScope.ThreadLocalOnly>
        }

        private fun addClasspathEntries(classPath: String) {
            classPath.split(java.io.File.pathSeparator).forEach { entry ->
                if (entry.isNotEmpty()) {
                    val file = java.io.File(entry)
                    addClasspathFile(file)
                }
            }
        }

        private fun addClasspathFile(file: java.io.File) {
            if (file.exists()) {
                val path = if (file.isDirectory) file.absolutePath else file.absoluteFile.parent
                if (path != null) allowFsRead(path)
            }
        }

        /**
         * Allows writing to the specified file or directory path (and its children).
         * Note: Setting any FS paths enables Landlock enforcement for this policy.
         */
        fun allowFsWrite(path: String): Builder<PolicyScope.ThreadLocalOnly> {
            validatePath(path)
            allowedFsWritePaths.add(path)
            @Suppress("UNCHECKED_CAST")
            return this as Builder<PolicyScope.ThreadLocalOnly>
        }

        /**
         * Allows `mmap` with `PROT_EXEC`. By default, this is blocked for all policies
         * to prevent shellcode execution.
         */
        fun allowMmapExec(): Builder<S> {
            this.allowMmapExec = true
            return this
        }

        /**
         * Allows `clone` without `CLONE_THREAD`. By default, this is blocked to prevent
         * process forking while allowing JVM thread creation.
         */
        fun allowNonThreadClone(): Builder<S> {
            this.allowNonThreadClone = true
            return this
        }

        /**
         * Allows unrestricted `prctl` calls. By default, unsafe/hazardous options of
         * `prctl` are blocked, while safe options needed by the JVM (like `PR_SET_NAME`)
         * are allowed via BPF argument inspection.
         */
        fun allowUnsafePrctl(): Builder<S> {
            this.allowUnsafePrctl = true
            return this
        }

        private fun validatePath(path: String) {
            require(path.isNotEmpty()) { "Path cannot be empty" }
            require(path.startsWith("/")) { "Path must be absolute" }
            require(!path.contains('\u0000')) { "Path cannot contain null bytes" }
        }

        fun build(): Policy<S, Uncompiled> {
            val enforceLandlock = allowedFsReadPaths.isNotEmpty() || allowedFsWritePaths.isNotEmpty()

            val finalSyscalls = syscallActions.toMutableMap()
            if (enforceLandlock) {
                finalSyscalls[Syscall.OPEN] = SeccompAction.ACT_ALLOW
                finalSyscalls[Syscall.OPENAT] = SeccompAction.ACT_ALLOW
                finalSyscalls[Syscall.OPENAT2] = SeccompAction.ACT_ALLOW
            }

            return Policy<S, Uncompiled>(
                defaultAction = defaultAction,
                syscallActions = finalSyscalls.toMap(),
                allowMmapExec = allowMmapExec,
                allowNonThreadClone = allowNonThreadClone,
                allowUnsafePrctl = allowUnsafePrctl,
                allowedFsReadPaths = allowedFsReadPaths.toSet(),
                allowedFsWritePaths = allowedFsWritePaths.toSet(),
                enforceLandlock = enforceLandlock,
                compiledFiltersField = null,
            )
        }
    }
}
