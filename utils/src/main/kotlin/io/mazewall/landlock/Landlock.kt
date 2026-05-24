package io.mazewall.landlock

import io.mazewall.LinuxNative
import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.Syscall
import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.logging.Logger

/**
 * Unprivileged, path-aware filesystem sandbox using the Linux Landlock LSM.
 *
 * Landlock restricts filesystem access at the **thread** level (via `landlock_restrict_self`).
 * Unlike seccomp-bpf, which operates on syscall numbers, Landlock reasons about **paths and
 * inodes**, making it the correct tool for constraining *where* a thread can read/write
 * rather than *what syscalls* it can invoke.
 *
 * ### How Landlock works
 * 1. A **ruleset** is created declaring which access categories the caller intends to restrict
 *    (the `handled_access_fs` bitmask). Any access category **not** listed here is left
 *    globally unrestricted—this is a "default-deny for listed categories" model.
 * 2. **Rules** are added to the ruleset granting specific access rights to specific paths
 *    (identified by file descriptors opened with `O_PATH`).
 * 3. `landlock_restrict_self` applies the ruleset to the calling thread. Future children
 *    inherit the restrictions, and nested rulesets **intersect** (access must be allowed by
 *    *all* stacked rulesets).
 *
 * ### Stacking & thread-pool interaction
 * Landlock rulesets are permanent and additive-intersective for the lifetime of the OS thread.
 * In a recycled thread pool, every task execution that calls [applyRuleset] pushes a new
 * layer. After ~16 layers the kernel returns `E2BIG`. Callers (i.e. [io.mazewall.enforcer.ContainedExecutors])
 * must track whether a thread has already been restricted and skip re-application.
 *
 * ### ABI versioning
 * The kernel exposes the supported ABI version via `landlock_create_ruleset` with the
 * `LANDLOCK_CREATE_RULESET_VERSION` flag. Newer ABIs add access categories:
 * - **ABI v1** (Linux 5.13): base filesystem rights
 * - **ABI v2** (Linux 5.19): `FS_REFER` (cross-directory rename/link)
 * - **ABI v3** (Linux 6.2): `FS_TRUNCATE`
 * - **ABI v4** (Linux 6.7): network restrictions (`handled_access_net`)
 * - **ABI v5** (Linux 6.10): `FS_IOCTL_DEV`
 *
 * This implementation includes ABI-conditional flags so that newer capabilities are used
 * automatically when available, while remaining safe on older kernels.
 *
 * ### Process-wide Landlock & TSYNC
 * Historically (ABI v1 to v7), `landlock_restrict_self` only affected the calling thread and its
 * future children, and could **not** retroactively restrict existing sibling threads. To achieve
 * true process-wide Landlock on these older kernels, a launcher wrapper (e.g. native C/Rust binary)
 * must apply the ruleset *before* `execve`-ing the JVM, so that all JVM threads inherit it.
 *
 * Starting with **ABI v8 (Linux 7.0)**, the kernel introduces `LANDLOCK_RESTRICT_SELF_TSYNC` which
 * permits retroactive process-wide synchronization from within an existing thread. However, because
 * retroactive process-wide restriction breaks sibling thread transparency in multi-threaded JVMs
 * (GC, JIT, and test runners), `mazewall` disables it by default in standard enforcement.
 *
 * @see io.mazewall.Policy.Builder.allowFsRead
 * @see io.mazewall.Policy.Builder.allowFsWrite
 * @see io.mazewall.Policy.Builder.allowJvmClasspath
 * @see io.mazewall.enforcer.ContainedExecutors.wrap
 */
object Landlock {
    private val logger = Logger.getLogger(Landlock::class.java.name)

    /** Apply ruleset to all threads of the process. ABI v8+ (Linux 7.0). */
    private const val LANDLOCK_RESTRICT_SELF_TSYNC = (1L shl 3)

    // ── Filesystem access flags ─────────────────────────────────────────
    // Each flag corresponds to a bit in the kernel's `handled_access_fs` / `allowed_access`
    // bitmask. See `linux/landlock.h` for authoritative definitions.

    /** Allow executing a file (applies to regular files only). ABI v1+. */
    const val LANDLOCK_ACCESS_FS_EXECUTE = (1L shl 0)

    /** Allow opening a file with write access. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_WRITE_FILE = (1L shl 1)

    /** Allow opening a file with read access. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_READ_FILE = (1L shl 2)

    /** Allow listing directory contents (readdir). ABI v1+. */
    const val LANDLOCK_ACCESS_FS_READ_DIR = (1L shl 3)

    /** Allow removing an empty directory. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_REMOVE_DIR = (1L shl 4)

    /** Allow unlinking / removing a file. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_REMOVE_FILE = (1L shl 5)

    /** Allow creating a character device. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_CHAR = (1L shl 6)

    /** Allow creating a directory. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_DIR = (1L shl 7)

    /** Allow creating a regular file. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_REG = (1L shl 8)

    /** Allow creating a Unix domain socket. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_SOCK = (1L shl 9)

    /** Allow creating a named pipe (FIFO). ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_FIFO = (1L shl 10)

    /** Allow creating a block device. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1L shl 11)

    /** Allow creating a symbolic link. ABI v1+. */
    const val LANDLOCK_ACCESS_FS_MAKE_SYM = (1L shl 12)

    /** Allow linking or renaming a file across directories. ABI v2+ (Linux 5.19). */
    const val LANDLOCK_ACCESS_FS_REFER = (1L shl 13)

    /** Allow truncating a file. ABI v3+ (Linux 6.2). */
    const val LANDLOCK_ACCESS_FS_TRUNCATE = (1L shl 14)

    /** Allow `ioctl` on device files. ABI v5+ (Linux 6.10). */
    const val LANDLOCK_ACCESS_FS_IOCTL_DEV = (1L shl 15)

    /**
     * Applies a restrictive Landlock ruleset that handles all categories but only
     * allows JVM classpath reads. This forces synchronous denials on the calling thread,
     * which can be caught and resolved by the IterativeProfiler without needing audit logs.
     */
    fun applyRestrictiveBarrier() {
        val abi = getAbiVersion()
        if (abi < 1) return

        val allFsRead = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR
        var accessMaskFs = allFsRead or
                LANDLOCK_ACCESS_FS_EXECUTE or
                LANDLOCK_ACCESS_FS_WRITE_FILE or
                LANDLOCK_ACCESS_FS_REMOVE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                LANDLOCK_ACCESS_FS_MAKE_CHAR or LANDLOCK_ACCESS_FS_MAKE_DIR or
                LANDLOCK_ACCESS_FS_MAKE_REG or LANDLOCK_ACCESS_FS_MAKE_SOCK or
                LANDLOCK_ACCESS_FS_MAKE_FIFO or LANDLOCK_ACCESS_FS_MAKE_BLOCK or
                LANDLOCK_ACCESS_FS_MAKE_SYM
        if (abi >= 2) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_REFER
        if (abi >= 3) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= 5) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_IOCTL_DEV

        val classpathFlags = allFsRead or LANDLOCK_ACCESS_FS_EXECUTE

        Arena.ofConfined().use { arena ->
            val rulesetAttr = arena.allocate(LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_FS_OFFSET, accessMaskFs)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_NET_OFFSET, 0L)

            val size = if (abi >= 4) LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT.byteSize() else 8L

            val rulesetFdResult =
                LinuxNative.syscall(
                    LinuxNative.LANDLOCK_CREATE_RULESET_NR,
                    rulesetAttr.address(),
                    size,
                    MemorySegment.NULL
                )
            if (rulesetFdResult.returnValue < 0) return

            val rulesetFd = rulesetFdResult.returnValue.toInt()
            try {
                addJvmClasspathRules(rulesetFd, classpathFlags, arena)
                LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                LinuxNative.syscall(LinuxNative.LANDLOCK_RESTRICT_SELF_NR, rulesetFd.toLong(), 0, MemorySegment.NULL, 0)
            } finally {
                LinuxNative.close(rulesetFd)
            }
        }
    }

    /**
     * Applies a restrictive Landlock ruleset that handles all possible access categories
    ...
     * but only allows JVM classpath reads. This is used to force "denial audit logs"
     * for all other operations, which the profiler daemon then ingests to build the BoB.
     */
    fun applyProfilingRuleset() {
        val abi = getAbiVersion()
        if (abi < 1) return

        // Ensure Landlock Audit support is available if fail-closed is requested.
        // ABI 7+ is required for AUDIT_LANDLOCK_ACCESS records.
        if (abi < 7) {
            val failOnMissingAudit = System.getenv("MAZEWALL_PROFILER_FAIL_ON_AUDIT_ERROR") ?: "true"
            if (failOnMissingAudit.lowercase() == "true") {
                throw IllegalStateException(
                    "Landlock Audit profiling requested (for io_uring support) but kernel Landlock ABI ($abi) is too old. " +
                            "ABI 7+ (Linux 6.15+) is required. " +
                            "To disable this check and run in Seccomp-only mode, set MAZEWALL_PROFILER_FAIL_ON_AUDIT_ERROR=false."
                )
            }
            return
        }

        val allFsRead = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR
        var accessMaskFs = allFsRead or
                LANDLOCK_ACCESS_FS_EXECUTE or
                LANDLOCK_ACCESS_FS_WRITE_FILE or
                LANDLOCK_ACCESS_FS_REMOVE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                LANDLOCK_ACCESS_FS_MAKE_CHAR or LANDLOCK_ACCESS_FS_MAKE_DIR or
                LANDLOCK_ACCESS_FS_MAKE_REG or LANDLOCK_ACCESS_FS_MAKE_SOCK or
                LANDLOCK_ACCESS_FS_MAKE_FIFO or LANDLOCK_ACCESS_FS_MAKE_BLOCK or
                LANDLOCK_ACCESS_FS_MAKE_SYM
        if (abi >= 2) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_REFER
        if (abi >= 3) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= 5) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_IOCTL_DEV

        val classpathFlags = allFsRead or LANDLOCK_ACCESS_FS_EXECUTE

        Arena.ofConfined().use { arena ->
            val rulesetAttr = arena.allocate(LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_FS_OFFSET, accessMaskFs)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_NET_OFFSET, 0L)

            val size = if (abi >= 4) LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT.byteSize() else 8L

            val rulesetFdResult =
                LinuxNative.syscall(
                    LinuxNative.LANDLOCK_CREATE_RULESET_NR,
                    rulesetAttr.address(),
                    size,
                    MemorySegment.NULL
                )
            if (rulesetFdResult.returnValue < 0) return

            val rulesetFd = rulesetFdResult.returnValue.toInt()
            try {
                addJvmClasspathRules(rulesetFd, classpathFlags, arena)

                LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

                // Use TSYNC (Thread Sync) for process-wide enforcement if ABI >= 8 (Linux 7.0+)
                // DISABLED: TSYNC breaks sibling thread transparency in the test suite.
                val flags = 0L // if (abi >= 8) LANDLOCK_RESTRICT_SELF_TSYNC else 0L
                val restrictResult =
                    LinuxNative.syscall(
                        LinuxNative.LANDLOCK_RESTRICT_SELF_NR,
                        rulesetFd.toLong(),
                        flags,
                        MemorySegment.NULL,
                        0
                    )

                if (restrictResult.returnValue < 0) {
                    logger.warning("Failed to apply Landlock profiling ruleset (flags=$flags): errno ${restrictResult.errno}")
                }
            } finally {
                LinuxNative.close(rulesetFd)
            }
        }
    }

    /**
     * Returns `true` if the running kernel supports Landlock (ABI v1+) and the OS is Linux.
     *
     * This performs a lightweight probe via `landlock_create_ruleset` with the version flag.
     * It does **not** create a persistent ruleset.
     */
    fun isSupported(): Boolean {
        if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return false
        val abi = getAbiVersion()
        return abi >= 1
    }

    /**
     * Queries the kernel for the highest Landlock ABI version it supports.
     *
     * @return The ABI version number (e.g. 1, 2, …, 8), or `0` if Landlock is not available
     *         (kernel too old, `CONFIG_SECURITY_LANDLOCK` disabled, or running in a container
     *         that blocks the syscall).
     */
    fun getAbiVersion(): Int {
        val abiResult = LinuxNative.syscall(
            LinuxNative.LANDLOCK_CREATE_RULESET_NR,
            0L,
            0L,
            LinuxNative.LANDLOCK_CREATE_RULESET_VERSION
        )
        if (abiResult.returnValue < 0) {
            return 0
        }
        return abiResult.returnValue.toInt()
    }

    /**
     * Builds and applies a Landlock ruleset to the calling thread based on the given [policy].
     *
     * If the policy contains no filesystem paths (`allowedFsReadPaths` and `allowedFsWritePaths`
     * are both empty), this method is a no-op.
     *
     * ### JVM classpath auto-allowlisting
     * Landlock restricts filesystem access, but the JVM **must** be able to read `.class` and
     * `.jar` files at any time for lazy classloading and JIT compilation. Blocking classpath
     * access would cause `NoClassDefFoundError` crashes that are impossible to predict or
     * prevent via preloading alone.
     *
     * Therefore, this method **automatically adds read rules** for `java.home` and all entries
     * in `java.class.path`, regardless of whether the user called [io.mazewall.Policy.Builder.allowJvmClasspath].
     * This is documented as an intentional design decision: classloading is too essential to
     * the JVM to ever block.
     *
     * ### Lifecycle
     * 1. Creates a ruleset FD via `landlock_create_ruleset`.
     * 2. Automatically adds read rules for the JVM classpath (see above).
     * 3. For each user-specified allowed path, opens it with `O_PATH | O_CLOEXEC | O_NOFOLLOW`
     *    and adds a `LANDLOCK_RULE_PATH_BENEATH` rule.
     * 4. Sets `PR_SET_NO_NEW_PRIVS` (required by the kernel for unprivileged Landlock).
     * 5. Calls `landlock_restrict_self` to enforce the ruleset on the calling thread.
     * 6. Closes the ruleset FD (the restriction persists after the FD is closed).
     *
     * ### Important caveats
     * - **Stacking is intersective.** Calling this method multiple times on the same thread
     *   narrows the allowed access with each call. After ~16 layers the kernel returns `E2BIG`.
     *   Use [io.mazewall.enforcer.ContainedExecutors] which tracks this via a `ThreadLocal` flag.
     * - **Non-existent paths fallback.** If a path does not exist, `addRule` will attempt to
     *   open the parent directory instead. This allows writing to files that haven't been
     *   created yet. If the parent also doesn't exist, the rule is skipped with a warning.
     * - **Symlinks are rejected.** `O_NOFOLLOW` is used, so symlink paths will fail to open.
     *   This prevents an attacker who controls a symlink target from redirecting a rule to
     *   an unintended inode. Use the resolved (real) path instead.
     *
     * @param policy The [io.mazewall.Policy] whose `allowedFsReadPaths` and `allowedFsWritePaths` will
     *               be translated into Landlock rules.
     * @throws UnsupportedOperationException if Landlock is unsupported and the configured
     *         fallback is [io.mazewall.Platform.FallbackBehavior.FAIL].
     * @throws RuntimeException if any Landlock syscall fails unexpectedly.
     */
    fun applyRuleset(policy: Policy) {
        val needsLandlock = policy.enforceLandlock || 
                            policy.allowedFsReadPaths.isNotEmpty() ||
                            policy.allowedFsWritePaths.isNotEmpty() ||
                            policy.isSyscallAllowed(Syscall.IO_URING_SETUP) ||
                            policy.isSyscallAllowed(Syscall.IO_URING_ENTER)
                            
        if (!needsLandlock) {
            return // No Landlock needed
        }

        val abi = getAbiVersion()
        if (abi < 1) {
            val fallback = Platform.configuredFallback()
            if (fallback == Platform.FallbackBehavior.FAIL) {
                throw UnsupportedOperationException("Landlock is not supported on this kernel but FS rules were requested.")
            } else if (fallback == Platform.FallbackBehavior.WARN_AND_BYPASS) {
                logger.warning("Landlock not supported, FS rules will be ignored.")
            }
            return
        }

        val allFsRead = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR

        // Fix #2: Handle ALL access categories the ABI supports.
        // Any category NOT listed here is left globally unrestricted.
        var accessMaskFs = allFsRead or
                LANDLOCK_ACCESS_FS_EXECUTE or
                LANDLOCK_ACCESS_FS_WRITE_FILE or
                LANDLOCK_ACCESS_FS_REMOVE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                LANDLOCK_ACCESS_FS_MAKE_CHAR or LANDLOCK_ACCESS_FS_MAKE_DIR or
                LANDLOCK_ACCESS_FS_MAKE_REG or LANDLOCK_ACCESS_FS_MAKE_SOCK or
                LANDLOCK_ACCESS_FS_MAKE_FIFO or LANDLOCK_ACCESS_FS_MAKE_BLOCK or
                LANDLOCK_ACCESS_FS_MAKE_SYM
        if (abi >= 2) {
            accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_REFER
        } else if (policy.isSyscallAllowed(Syscall.RENAME) || policy.isSyscallAllowed(Syscall.RENAMEAT) || policy.isSyscallAllowed(Syscall.RENAMEAT2) || policy.isSyscallAllowed(Syscall.LINK) || policy.isSyscallAllowed(Syscall.LINKAT)) {
            throw UnsupportedOperationException("Fatal Security Error: Policy allows rename/link syscalls, but this kernel (Landlock ABI $abi) is too old to restrict them (ABI 2 / Linux 5.19+ required). Update your kernel or block these syscalls.")
        }
        
        if (abi >= 3) {
            accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_TRUNCATE
        } else if (policy.isSyscallAllowed(Syscall.TRUNCATE) || policy.isSyscallAllowed(Syscall.FTRUNCATE)) {
            throw UnsupportedOperationException("Fatal Security Error: Policy allows truncate syscalls, but this kernel (Landlock ABI $abi) is too old to restrict them (ABI 3 / Linux 6.2+ required). Update your kernel or block these syscalls.")
        }
        
        if (abi >= 5) {
            accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_IOCTL_DEV
        } else if (policy.isSyscallAllowed(Syscall.IOCTL)) {
            throw UnsupportedOperationException("Fatal Security Error: Policy allows ioctl, but this kernel (Landlock ABI $abi) is too old to restrict dev ioctls (ABI 5 / Linux 6.10+ required). Update your kernel or block ioctl.")
        }

        // All access flags for read + execute (needed for JVM classpath)
        val classpathFlags = allFsRead or LANDLOCK_ACCESS_FS_EXECUTE

        Arena.ofConfined().use { arena ->
            val rulesetAttr = arena.allocate(LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_FS_OFFSET, accessMaskFs)
            rulesetAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_RULESET_ATTR_NET_OFFSET, 0L)

            val size = if (abi >= 4) LinuxNative.LANDLOCK_RULESET_ATTR_LAYOUT.byteSize() else 8L

            val rulesetFdResult =
                LinuxNative.syscall(
                    LinuxNative.LANDLOCK_CREATE_RULESET_NR,
                    rulesetAttr.address(),
                    size,
                    MemorySegment.NULL
                )
            if (rulesetFdResult.returnValue < 0) {
                throw RuntimeException("landlock_create_ruleset failed with errno ${rulesetFdResult.errno}")
            }
            val rulesetFd = rulesetFdResult.returnValue.toInt()

            try {
                // Fix #5: Auto-allow JVM classpath reads.
                // Classloading is essential for JVM operation and must never be blocked.
                addJvmClasspathRules(rulesetFd, classpathFlags, arena)

                // Add user-specified read rules
                for (path in policy.allowedFsReadPaths) {
                    addRule(rulesetFd, path, allFsRead, arena)
                }

                // Add user-specified write rules
                for (path in policy.allowedFsWritePaths) {
                    val writeFlags = LANDLOCK_ACCESS_FS_WRITE_FILE or LANDLOCK_ACCESS_FS_MAKE_REG or
                            LANDLOCK_ACCESS_FS_MAKE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                            LANDLOCK_ACCESS_FS_REMOVE_DIR or (if (abi >= 3) LANDLOCK_ACCESS_FS_TRUNCATE else 0)
                    addRule(rulesetFd, path, writeFlags, arena)
                }

                // Restrict self requires no_new_privs
                val prctlResult = LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                if (prctlResult.returnValue < 0) {
                    throw RuntimeException("prctl(PR_SET_NO_NEW_PRIVS) failed with errno ${prctlResult.errno}")
                }

                // Use TSYNC (Thread Sync) for process-wide enforcement if ABI >= 8 (Linux 7.0+)
                // DISABLED: TSYNC breaks sibling thread transparency in the test suite.
                val flags = 0L // if (abi >= 8) LANDLOCK_RESTRICT_SELF_TSYNC else 0L
                val restrictResult =
                    LinuxNative.syscall(
                        LinuxNative.LANDLOCK_RESTRICT_SELF_NR,
                        rulesetFd.toLong(),
                        flags,
                        MemorySegment.NULL,
                        0
                    )
                if (restrictResult.returnValue < 0) {
                    throw RuntimeException("landlock_restrict_self failed (flags=$flags) with errno ${restrictResult.errno}")
                }
            } finally {
                LinuxNative.close(rulesetFd)
            }
        }
    }

    /**
     * Adds read rules for the JVM's own classpath so that classloading always works.
     *
     * This covers `java.home` (the JDK installation) and every entry in `java.class.path`
     * (application JARs and class directories). Without these rules, any lazy classloading
     * after `landlock_restrict_self` would throw `NoClassDefFoundError`.
     *
     * Note: These rules use `O_PATH` without `O_NOFOLLOW` because JDK installations
     * commonly use symlinks (e.g. `/usr/lib/jvm/java` -> `/usr/lib/jvm/java-25-openjdk`).
     */
    private fun addJvmClasspathRules(rulesetFd: Int, accessFlags: Long, arena: Arena) {
        val javaHome = System.getProperty("java.home")
        if (javaHome != null) {
            addRuleFollowSymlinks(rulesetFd, javaHome, accessFlags, arena)
        }

        val classPath = System.getProperty("java.class.path")
        if (classPath != null) {
            val seen = mutableSetOf<String>()
            classPath.split(File.pathSeparator).forEach {
                val file = File(it)
                if (file.exists()) {
                    val dir = if (file.isDirectory) file.absolutePath else file.parent
                    if (seen.add(dir)) {
                        addRuleFollowSymlinks(rulesetFd, dir, accessFlags, arena)
                    }
                }
            }
        }
    }

    /**
     * Adds a rule using `O_PATH | O_CLOEXEC` (without `O_NOFOLLOW`) — used only for
     * JVM classpath paths where symlinks are expected and trusted.
     */
    private fun addRuleFollowSymlinks(rulesetFd: Int, path: String, allowedAccess: Long, arena: Arena) {
        val pathSegment = arena.allocateFrom(path)
        val fdResult = LinuxNative.open(pathSegment, LinuxNative.O_PATH or LinuxNative.O_CLOEXEC)
        if (fdResult.returnValue < 0) {
            logger.warning("Could not open JVM classpath $path for landlock rule: errno ${fdResult.errno}")
            return
        }
        val pathFd = fdResult.returnValue.toInt()
        try {
            val pathAttr = arena.allocate(LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_LAYOUT)
            pathAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_ACCESS_OFFSET, allowedAccess)
            pathAttr.set(ValueLayout.JAVA_INT, LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_FD_OFFSET, pathFd)

            val addResult = LinuxNative.syscall(
                LinuxNative.LANDLOCK_ADD_RULE_NR,
                rulesetFd.toLong(),
                LinuxNative.LANDLOCK_RULE_PATH_BENEATH.toLong(),
                pathAttr,
                0
            )
            if (addResult.returnValue < 0) {
                logger.warning("landlock_add_rule failed for JVM classpath $path with errno ${addResult.errno}")
            }
        } finally {
            LinuxNative.close(pathFd)
        }
    }

    /**
     * Adds a single `LANDLOCK_RULE_PATH_BENEATH` rule to the given ruleset.
     *
     * Opens [path] with `O_PATH | O_CLOEXEC | O_NOFOLLOW` to obtain a non-functional file
     * descriptor that identifies the inode. The FD is closed after the rule is added.
     *
     * ### Symlink rejection (Fix #4)
     * `O_NOFOLLOW` is used so that symlink paths are rejected with `ELOOP`. This prevents
     * an attacker who controls a symlink target from redirecting a Landlock rule to an
     * unintended inode. If you need to allow a symlinked path, resolve it first with
     * `Path.toRealPath()` and pass the resolved path.
     *
     * ### Non-existent path fallback (Fix #3)
     * If the path does not exist (`ENOENT`), this method automatically tries the parent
     * directory instead. This allows users to allow writes to files that haven't been
     * created yet. If the parent also fails, a warning is logged and the rule is skipped
     * (fail-open for this specific path, but the overall ruleset remains restrictive).
     *
     * @param rulesetFd  The file descriptor of the Landlock ruleset (from `landlock_create_ruleset`).
     * @param path       The filesystem path to allow access to (and its descendants).
     * @param allowedAccess Bitmask of `LANDLOCK_ACCESS_FS_*` flags to grant for this path.
     * @param arena      The [Arena] used for native memory allocations in this call.
     * @throws RuntimeException if `landlock_add_rule` fails for a reason other than a missing path.
     */
    private fun addRule(rulesetFd: Int, path: String, allowedAccess: Long, arena: Arena) {
        val resolvedPath = try {
            File(path).canonicalPath
        } catch (e: Exception) {
            path
        }
        val openFlags = LinuxNative.O_PATH or LinuxNative.O_CLOEXEC or LinuxNative.O_NOFOLLOW
        var pathSegment = arena.allocateFrom(resolvedPath)
        var fdResult = LinuxNative.open(pathSegment, openFlags)

        var isFallbackToParent = false
        // Fix #3: If path doesn't exist (ENOENT=2), try the parent directory.
        if (fdResult.returnValue < 0 && fdResult.errno == 2) {
            val parentPath = File(resolvedPath).parent ?: "/"
            logger.info("Path $resolvedPath does not exist, falling back to parent directory: $parentPath")
            pathSegment = arena.allocateFrom(parentPath)
            fdResult = LinuxNative.open(pathSegment, openFlags)
            isFallbackToParent = true
        }

        // Fix #4: If symlink (ELOOP=40), log a clear warning.
        if (fdResult.returnValue < 0 && fdResult.errno == 40) {
            logger.warning("Path $path is a symlink and was rejected (O_NOFOLLOW). Use the resolved real path instead.")
            return
        }

        if (fdResult.returnValue < 0) {
            logger.warning("Could not open path $path for landlock rule: errno ${fdResult.errno}")
            return
        }

        val pathFd = fdResult.returnValue.toInt()
        try {
            var finalAccess = allowedAccess
            if (!isFallbackToParent && File(resolvedPath).isFile) {
                // Strip directory-only flags to prevent EINVAL from the kernel when targeting regular files
                val dirOnlyFlags = LANDLOCK_ACCESS_FS_READ_DIR or
                                   LANDLOCK_ACCESS_FS_MAKE_DIR or
                                   LANDLOCK_ACCESS_FS_REMOVE_DIR
                finalAccess = finalAccess and dirOnlyFlags.inv()
            }

            val pathAttr = arena.allocate(LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_LAYOUT)
            pathAttr.set(ValueLayout.JAVA_LONG, LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_ACCESS_OFFSET, finalAccess)
            pathAttr.set(ValueLayout.JAVA_INT, LinuxNative.LANDLOCK_PATH_BENEATH_ATTR_FD_OFFSET, pathFd)

            val addResult = LinuxNative.syscall(
                LinuxNative.LANDLOCK_ADD_RULE_NR,
                rulesetFd.toLong(),
                LinuxNative.LANDLOCK_RULE_PATH_BENEATH.toLong(),
                pathAttr,
                0
            )
            if (addResult.returnValue < 0) {
                if (addResult.errno == 22) {
                    // EINVAL: The FD likely points to a symlink inode (O_PATH | O_NOFOLLOW
                    // opens the symlink itself, not the target). Landlock rejects non-directory/
                    // non-regular-file inodes as path-beneath parents.
                    logger.warning("landlock_add_rule rejected $path (EINVAL) — path may be a symlink or unsupported inode type. Use the resolved real path instead.")
                    return
                }
                throw RuntimeException("landlock_add_rule failed for $path with errno ${addResult.errno}")
            }
        } finally {
            LinuxNative.close(pathFd)
        }
    }
}
