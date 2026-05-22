package io.contained.profiler

import io.contained.Policy
import io.contained.Syscall
import kotlin.collections.iterator

/**
 * An immutable record of what kernel-level operations were observed during a
 * profiling run. This is the raw output of the [Profiler] — completely decoupled
 * from any [io.contained.Policy].
 *
 * Field naming follows the [Software Bill of Behavior (SBoB) spec draft v0.0.1](https://billofbehavior.com/bob/docs/drafts/spec-v0.0.1/):
 * - [opens]   → SBoB §4.6 `opens`
 * - [execs]   → SBoB §4.5 `execs`
 * - [syscalls] → non-standard extension; all intercepted syscall names
 *
 * ## Absent vs Explicit-Empty
 * Per SBoB §5.4, absent (null) means "unconstrained / not observed" and
 * explicit empty (emptySet()) means "observed zero activity". This class
 * always returns empty sets (never null), because a completed profiling run
 * with zero observations is a valid, meaningful result: the operation touched
 * nothing in that category.
 *
 * ## Stack profiles
 * [stackProfile] captures per-syscall JVM stack traces on a best-effort basis.
 * The worker thread is frozen in the kernel during USER_NOTIF; its Java stack
 * is stable at that moment. Frames are Java-only — no kernel frames are available.
 * This is a precursor to the SBoB stack-profile extension (spec-stackprofile-v0.0.1,
 * not yet published). The encoding will align to OTel Profiles when that extension
 * stabilises.
 *
 * ## Composability
 * Use [plus] to merge two bills from separate profiling runs into a single policy.
 */
data class BillOfBehavior(
    /**
     * Filesystem paths opened for read (open/openat/openat2 with O_RDONLY, stat,
     * readlink, etc.). Maps to SBoB §4.6 `opens` with `flags` indicating read access.
     */
    val opens: Set<String> = emptySet(),

    /**
     * Filesystem paths opened for write, created, or mutated (O_WRONLY, O_RDWR,
     * O_CREAT, O_TRUNC, mkdir, rmdir, rename, chmod, chown, etc.).
     * Maps to SBoB §4.6 `opens` with write-mode flags.
     *
     * ## Design decision: conservative write-path discovery
     * When [IterativeProfiler] catches an AccessDeniedException from Landlock, the
     * exception does not reliably carry the access mode that was denied. Rather than
     * guessing, the profiler conservatively adds the denied path to BOTH [opens] and
     * [fsWritePaths]. This guarantees convergence at the cost of slightly over-permissive
     * Landlock rules — correct for a profiling tool whose goal is discovery, not enforcement.
     */
    val fsWritePaths: Set<String> = emptySet(),

    /**
     * All syscall names intercepted during the run. A superset of what any
     * specific base [io.contained.Policy] would block — the caller decides which subset matters
     * via [toPolicy].
     */
    val syscalls: Set<Syscall> = emptySet(),

    /**
     * Child processes spawned (execve/execveat paths). Maps to SBoB §4.5 `execs`.
     */
    val execs: Set<String> = emptySet(),

    /**
     * Per-syscall JVM stack traces captured at the moment the kernel paused the
     * worker thread for USER_NOTIF. The worker thread is blocked in-kernel and its
     * Java stack is frozen at that point — traces are accurate for Java frames.
     *
     * May be empty if profiling was done via IterativeProfiler (Tier A),
     * which does not use USER_NOTIF.
     *
     * Keyed by [TraceEvent] identity; multiple events for the same syscall name
     * may produce different stack entries if triggered from different call sites.
     */
    val stackProfile: Map<TraceEvent, List<Array<StackTraceElement>>> = emptyMap()
) {
    /**
     * Compiles this bill of behavior into a [io.contained.Policy] starting from [base].
     *
     * Only syscalls that are **actually blocked** by [base] are unblocked —
     * syscalls observed but absent from the base block-list are ignored.
     * This is the correct filter: if a syscall was observed but the base
     * policy never blocked it, calling unblock() on it would be a no-op
     * at best and a footgun if the base policy changes later.
     *
     * All [opens] paths are granted read access; all [fsWritePaths] paths
     * are granted write access.
     */
    fun toPolicy(base: Policy = Policy.PURE_COMPUTE): Policy {
        val builder = Policy.builder().base(base)
        val toUnblock = syscalls.filter { base.blocked.contains(it) }
        builder.unblock(*toUnblock.toTypedArray())
        for (path in opens) builder.allowFsRead(path)
        for (path in fsWritePaths) builder.allowFsWrite(path)
        return builder.build()
    }

    /**
     * Emits a copy-pasteable Kotlin DSL snippet that reproduces the compiled policy.
     * [basePolicyName] is used as the string label in the emitted code.
     */
    fun toDsl(
        basePolicyName: String = "Policy.PURE_COMPUTE",
        base: Policy = Policy.PURE_COMPUTE
    ): String {
        val sb = StringBuilder()
        sb.append("val policy = Policy.builder()\n")
        sb.append("    .base($basePolicyName)\n")
        val toUnblock = syscalls.filter { base.blocked.contains(it) }.sortedBy { it.name }
        if (toUnblock.isNotEmpty()) {
            sb.append("    .unblock(\n")
            toUnblock.forEachIndexed { i, s ->
                sb.append("        Syscall.${s.name}")
                if (i < toUnblock.size - 1) sb.append(",")
                sb.append("\n")
            }
            sb.append("    )\n")
        }
        for (path in opens.sorted()) sb.append("    .allowFsRead(\"$path\")\n")
        for (path in fsWritePaths.sorted()) sb.append("    .allowFsWrite(\"$path\")\n")
        sb.append("    .build()")
        return sb.toString()
    }

    /**
     * Merges two bills of behavior (union of all observations).
     * Useful for compiling a single policy across multiple profiling runs
     * covering different code paths of the same application.
     */
    operator fun plus(other: BillOfBehavior): BillOfBehavior {
        val mergedStackProfile = stackProfile.toMutableMap()
        for ((event, traces) in other.stackProfile) {
            mergedStackProfile[event] = (mergedStackProfile[event] ?: emptyList()) + traces
        }

        return BillOfBehavior(
            opens = opens + other.opens,
            fsWritePaths = fsWritePaths + other.fsWritePaths,
            syscalls = syscalls + other.syscalls,
            execs = execs + other.execs,
            stackProfile = mergedStackProfile
        )
    }
}