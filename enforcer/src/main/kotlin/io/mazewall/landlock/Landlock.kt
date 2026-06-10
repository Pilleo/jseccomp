package io.mazewall.landlock

import io.mazewall.LinuxNative
import io.mazewall.Platform
import io.mazewall.Policy
import io.mazewall.core.Syscall
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.logging.Logger

// SUPPRESSION JUSTIFICATION: This object serves as the single cohesive boundary wrapping the Landlock LSM.
// Splitting the path wrapping, layout allocation, ABI query, and rule-building functions into
// multiple files would severely fragment the safety-critical FFM logic and reduce readability.

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
 * Stacking with **ABI v8 (Linux 7.0)**, the kernel introduces `LANDLOCK_RESTRICT_SELF_TSYNC` which
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

    private const val ERRNO_EINVAL = 22
    private const val ERRNO_ELOOP = 40
    private const val ABI_V3 = 3
    private const val ABI_V5 = 5

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

        val accessMaskFs = getFullAccessMask(abi)
        val allFsRead = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR
        val classpathFlags = allFsRead or LANDLOCK_ACCESS_FS_EXECUTE

        Arena.ofConfined().use { arena ->
            val rulesetFdResult = createRuleset(arena, accessMaskFs, abi)
            if (rulesetFdResult.returnValue < 0) return

            val rulesetFd = rulesetFdResult.returnValue.toInt()
            try {
                addJvmClasspathRules(rulesetFd, classpathFlags, arena)
                enforceRuleset(rulesetFd)
            } finally {
                LinuxNative.close(rulesetFd)
            }
        }
    }

    /**
     * Returns `true` if the running kernel supports Landlock (ABI v1+) and the OS is Linux.
     */
    fun isSupported(): Boolean {
        if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return false
        return getAbiVersion() >= 1
    }

    /**
     * Queries the kernel for the highest Landlock ABI version it supports.
     */
    fun getAbiVersion(): Int {
        val abiResult =
            LinuxNative.syscall(
                NativeConstants.LANDLOCK_CREATE_RULESET_NR,
                0L,
                0L,
                NativeConstants.LANDLOCK_CREATE_RULESET_VERSION,
            )
        return if (abiResult.returnValue < 0) 0 else abiResult.returnValue.toInt()
    }

    /**
     * Builds and applies a Landlock ruleset to the calling thread based on the given [policy].
     */
    fun applyRuleset(policy: Policy) {
        if (!shouldApplyLandlock(policy)) return

        val abi = getAbiVersion()
        if (abi < 1) {
            handleUnsupportedLandlock()
            return
        }

        val accessMaskFs = getAccessMask(abi, policy)
        val allFsRead = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR
        val classpathFlags = allFsRead or LANDLOCK_ACCESS_FS_EXECUTE

        Arena.ofConfined().use { arena ->
            val rulesetFd = createRulesetOrThrow(arena, accessMaskFs, abi)
            try {
                addJvmClasspathRules(rulesetFd, classpathFlags, arena)
                applyUserRules(rulesetFd, policy, abi, arena, allFsRead)
                enforceRuleset(rulesetFd)
            } finally {
                LinuxNative.close(rulesetFd)
            }
        }
    }

    private fun getFullAccessMask(abi: Int): Long {
        var mask = LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR or
                LANDLOCK_ACCESS_FS_EXECUTE or LANDLOCK_ACCESS_FS_WRITE_FILE or
                LANDLOCK_ACCESS_FS_REMOVE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                LANDLOCK_ACCESS_FS_MAKE_CHAR or LANDLOCK_ACCESS_FS_MAKE_DIR or
                LANDLOCK_ACCESS_FS_MAKE_REG or LANDLOCK_ACCESS_FS_MAKE_SOCK or
                LANDLOCK_ACCESS_FS_MAKE_FIFO or LANDLOCK_ACCESS_FS_MAKE_BLOCK or
                LANDLOCK_ACCESS_FS_MAKE_SYM
        if (abi >= 2) mask = mask or LANDLOCK_ACCESS_FS_REFER
        if (abi >= ABI_V3) mask = mask or LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= ABI_V5) mask = mask or LANDLOCK_ACCESS_FS_IOCTL_DEV
        return mask
    }

    private fun shouldApplyLandlock(policy: Policy): Boolean =
        policy.enforceLandlock ||
                policy.allowedFsReadPaths.isNotEmpty() ||
                policy.allowedFsWritePaths.isNotEmpty() ||
                policy.isSyscallAllowed(Syscall.IO_URING_SETUP) ||
                policy.isSyscallAllowed(Syscall.IO_URING_ENTER)

    private fun handleUnsupportedLandlock() {
        val fallback = Platform.configuredFallback()
        if (fallback == Platform.FallbackBehavior.FAIL) {
            throw UnsupportedOperationException("Landlock is not supported on this kernel but FS rules were requested.")
        } else if (fallback == Platform.FallbackBehavior.WARN_AND_BYPASS) {
            logger.warning("Landlock not supported, FS rules will be ignored.")
        }
    }

    private fun createRulesetOrThrow(
        arena: Arena,
        mask: Long,
        abi: Int,
    ): Int {
        val res = createRuleset(arena, mask, abi)
        if (res.returnValue < 0) {
            throw IllegalStateException("landlock_create_ruleset failed with errno ${res.errno}")
        }
        return res.returnValue.toInt()
    }

    private fun addJvmClasspathRules(
        rulesetFd: Int,
        accessFlags: Long,
        arena: Arena,
    ) {
        System.getProperty("java.home")?.let { addRuleFollowSymlinks(rulesetFd, it, accessFlags, arena) }

        val classPath = System.getProperty("java.class.path") ?: return
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

    private fun addRuleFollowSymlinks(
        rulesetFd: Int,
        path: String,
        allowedAccess: Long,
        arena: Arena,
    ) {
        val pathSegment = arena.allocateFrom(path)
        val fdResult = LinuxNative.open(pathSegment, NativeConstants.O_PATH or NativeConstants.O_CLOEXEC)
        if (fdResult.returnValue < 0) {
            logger.warning("Could not open JVM classpath $path for landlock rule: errno ${fdResult.errno}")
            return
        }
        val pathFd = fdResult.returnValue.toInt()
        try {
            val addResult = addRuleToRuleset(arena, rulesetFd, pathFd, allowedAccess)
            if (addResult.returnValue < 0) {
                logger.warning("landlock_add_rule failed for JVM classpath $path with errno ${addResult.errno}")
            }
        } finally {
            LinuxNative.close(pathFd)
        }
    }

    private fun addRule(
        rulesetFd: Int,
        path: String,
        allowedAccess: Long,
        arena: Arena,
    ) {
        val resolvedPath = resolveCanonicalPath(path)
        val openFlags = NativeConstants.O_PATH or NativeConstants.O_CLOEXEC or NativeConstants.O_NOFOLLOW
        val initialResult = LinuxNative.open(arena.allocateFrom(resolvedPath), openFlags)

        val (fdResult, isFallback) = handleInitialOpenFailure(initialResult, resolvedPath, openFlags, arena)

        if (fdResult.returnValue < 0) {
            logOpenFailure(path, fdResult.errno)
            return
        }

        val pathFd = fdResult.returnValue.toInt()
        try {
            val finalAccess = calculateFinalAccess(allowedAccess, isFallback, resolvedPath)
            addRuleToRulesetAndVerify(arena, rulesetFd, pathFd, finalAccess, path)
        } finally {
            LinuxNative.close(pathFd)
        }
    }

    private fun resolveCanonicalPath(path: String): String =
        try {
            File(path).canonicalPath
        } catch (e: java.io.IOException) {
            logger.log(java.util.logging.Level.FINE, "Failed to canonicalize path $path: ${e.message}", e)
            path
        }

    private fun handleInitialOpenFailure(
        res: LinuxNative.SyscallResult,
        resolvedPath: String,
        flags: Int,
        arena: Arena,
    ): Pair<LinuxNative.SyscallResult, Boolean> {
        if (res.returnValue < 0 && res.errno == 2) { // ENOENT
            val parentPath = File(resolvedPath).parent ?: "/"
            logger.info("Path $resolvedPath does not exist, falling back to parent directory: $parentPath")
            return LinuxNative.open(arena.allocateFrom(parentPath), flags) to true
        }
        return res to false
    }

    private fun logOpenFailure(
        path: String,
        errno: Int,
    ) {
        if (errno == ERRNO_ELOOP) {
            logger.warning("Path $path is a symlink and was rejected (O_NOFOLLOW). Use the resolved real path instead.")
        } else {
            logger.warning("Could not open path $path for landlock rule: errno $errno")
        }
    }

    private fun calculateFinalAccess(
        allowedAccess: Long,
        isFallback: Boolean,
        resolvedPath: String,
    ): Long {
        if (isFallback || File(resolvedPath).isFile) {
            val dirOnlyFlags = LANDLOCK_ACCESS_FS_READ_DIR or LANDLOCK_ACCESS_FS_MAKE_DIR or LANDLOCK_ACCESS_FS_REMOVE_DIR
            return allowedAccess and dirOnlyFlags.inv()
        }
        return allowedAccess
    }

    private fun addRuleToRulesetAndVerify(
        arena: Arena,
        rulesetFd: Int,
        pathFd: Int,
        access: Long,
        path: String,
    ) {
        val res = addRuleToRuleset(arena, rulesetFd, pathFd, access)
        if (res.returnValue < 0) {
            if (res.errno == ERRNO_EINVAL) {
                logger.warning("landlock_add_rule rejected $path (EINVAL) — path may be a symlink or unsupported inode type.")
            } else {
                throw IllegalStateException("landlock_add_rule failed for $path with errno ${res.errno}")
            }
        }
    }

    private fun enforceRuleset(rulesetFd: Int) {
        val prctlResult = LinuxNative.prctl(NativeConstants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if (prctlResult.returnValue < 0) {
            throw IllegalStateException("prctl(PR_SET_NO_NEW_PRIVS) failed with errno ${prctlResult.errno}")
        }
        val restrictResult = LinuxNative.syscall(NativeConstants.LANDLOCK_RESTRICT_SELF_NR, rulesetFd.toLong(), 0, MemorySegment.NULL, 0)
        if (restrictResult.returnValue < 0) {
            throw IllegalStateException("landlock_restrict_self failed with errno ${restrictResult.errno}")
        }
    }

    private fun applyUserRules(
        rulesetFd: Int,
        policy: Policy,
        abi: Int,
        arena: Arena,
        allFsRead: Long,
    ) {
        policy.allowedFsReadPaths.forEach { addRule(rulesetFd, it, allFsRead, arena) }
        val writeFlags = LANDLOCK_ACCESS_FS_WRITE_FILE or LANDLOCK_ACCESS_FS_MAKE_REG or
                LANDLOCK_ACCESS_FS_MAKE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
                LANDLOCK_ACCESS_FS_REMOVE_DIR or (if (abi >= ABI_V3) LANDLOCK_ACCESS_FS_TRUNCATE else 0)
        policy.allowedFsWritePaths.forEach { addRule(rulesetFd, it, writeFlags, arena) }
    }

    internal fun getAccessMask(
        abi: Int,
        policy: Policy,
    ): Long {
        var accessMaskFs = getFullAccessMask(1) // Base mask
        if (abi >= 2) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_REFER
        if (abi >= ABI_V3) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= ABI_V5) accessMaskFs = accessMaskFs or LANDLOCK_ACCESS_FS_IOCTL_DEV

        validateAbiSupport(abi, policy)
        return accessMaskFs
    }

    private fun validateAbiSupport(
        abi: Int,
        policy: Policy,
    ) {
        val unsupportedErrors = mutableListOf<String>()
        if (abi < 2 && (policy.isSyscallAllowed(Syscall.RENAME) || policy.isSyscallAllowed(Syscall.LINK))) {
            unsupportedErrors.add("Policy allows rename/link syscalls, but this kernel is too old")
        }
        if (abi < ABI_V3 && (policy.isSyscallAllowed(Syscall.TRUNCATE) || policy.isSyscallAllowed(Syscall.FTRUNCATE))) {
            unsupportedErrors.add("Policy allows truncate syscalls, but this kernel is too old")
        }
        if (abi < ABI_V5 && policy.isSyscallAllowed(Syscall.IOCTL)) {
            unsupportedErrors.add("Policy allows ioctl, but this kernel is too old")
        }
        if (unsupportedErrors.isNotEmpty()) {
            throw UnsupportedOperationException("Fatal Security Error: ${unsupportedErrors.joinToString("; ")}")
        }
    }

    private fun createRuleset(
        arena: Arena,
        accessMaskFs: Long,
        abi: Int,
    ): LinuxNative.SyscallResult {
        val rulesetAttr = arena.allocate(Layouts.LANDLOCK_RULESET_ATTR)
        rulesetAttr.set(ValueLayout.JAVA_LONG, Layouts.LANDLOCK_RULESET_ATTR_FS_OFFSET, accessMaskFs)
        rulesetAttr.set(ValueLayout.JAVA_LONG, Layouts.LANDLOCK_RULESET_ATTR_NET_OFFSET, 0L)
        val size = if (abi >= 4) Layouts.LANDLOCK_RULESET_ATTR.byteSize() else 8L
        return LinuxNative.syscall(NativeConstants.LANDLOCK_CREATE_RULESET_NR, rulesetAttr, size, MemorySegment.NULL)
    }

    private fun addRuleToRuleset(
        arena: Arena,
        rulesetFd: Int,
        pathFd: Int,
        accessMask: Long,
    ): LinuxNative.SyscallResult {
        val pathAttr = arena.allocate(Layouts.LANDLOCK_PATH_BENEATH_ATTR)
        pathAttr.set(ValueLayout.JAVA_LONG, Layouts.LANDLOCK_PATH_BENEATH_ATTR_ACCESS_OFFSET, accessMask)
        pathAttr.set(ValueLayout.JAVA_INT, Layouts.LANDLOCK_PATH_BENEATH_ATTR_FD_OFFSET, pathFd)
        return LinuxNative.syscall(NativeConstants.LANDLOCK_ADD_RULE_NR, rulesetFd.toLong(), NativeConstants.LANDLOCK_RULE_PATH_BENEATH.toLong(), pathAttr, 0)
    }
}
