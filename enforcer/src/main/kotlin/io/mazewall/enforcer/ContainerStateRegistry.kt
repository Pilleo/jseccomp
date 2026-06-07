package io.mazewall.enforcer

import io.mazewall.SeccompAction
import io.mazewall.Syscall
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Internal registry for tracking seccomp and Landlock state across threads.
 *
 * It maps each [Syscall] to its enforced [SeccompAction]. When filter stacking occurs,
 * the highest priority action (e.g., ACT_KILL_PROCESS > ACT_ALLOW) takes precedence
 * according to BPF semantics.
 */
// INVARIANT: ThreadLocals are INTENTIONALLY not cleared between tasks.
// Seccomp filters are permanent for the OS thread lifetime.
// Do NOT add cleanup in task wrappers; it would give a false sense of
// isolation between tasks on the same thread. See code_issues_backlog.md
// "Permanent thread pool contamination" for the known limitation and
// the correct fix strategy (scope checks, not cleanup).
internal object ContainerStateRegistry {
    val THREAD_SYSCALL_ACTIONS = ThreadLocal.withInitial<Map<Syscall, SeccompAction>> { emptyMap() }
    val THREAD_DEFAULT_ACTION = ThreadLocal.withInitial { SeccompAction.ACT_ALLOW }
    val THREAD_ALLOWS_MMAP_EXEC = ThreadLocal.withInitial { true }
    val THREAD_ALLOWS_NON_THREAD_CLONE = ThreadLocal.withInitial { true }
    val THREAD_ALLOWS_UNSAFE_PRCTL = ThreadLocal.withInitial { true }
    val FILTER_DEPTH = ThreadLocal.withInitial { 0 }
    val THREAD_LANDLOCK_APPLIED_READS = ThreadLocal.withInitial<Set<String>?> { null }
    val THREAD_LANDLOCK_APPLIED_WRITES = ThreadLocal.withInitial<Set<String>?> { null }

    val PROCESS_WIDE_ENFORCEMENT_ACTIVE = AtomicBoolean(false)
    val PROCESS_WIDE_SYSCALL_ACTIONS = AtomicReference<Map<Syscall, SeccompAction>>(emptyMap())
    val PROCESS_WIDE_DEFAULT_ACTION = AtomicReference(SeccompAction.ACT_ALLOW)
    val PROCESS_WIDE_ALLOWS_MMAP_EXEC = AtomicBoolean(true)
    val PROCESS_WIDE_ALLOWS_NON_THREAD_CLONE = AtomicBoolean(true)
    val PROCESS_WIDE_ALLOWS_UNSAFE_PRCTL = AtomicBoolean(true)

    // Global seccomp filter depth (number of stacked filters applied to the process)
    val PROCESS_WIDE_FILTER_DEPTH = AtomicInteger(0)
}
