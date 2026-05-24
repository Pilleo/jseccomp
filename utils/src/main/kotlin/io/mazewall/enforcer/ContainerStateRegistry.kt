package io.mazewall.enforcer

import io.mazewall.Syscall
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Internal registry for tracking seccomp and Landlock state across threads.
 */
internal object ContainerStateRegistry {
    val THREAD_BLOCKED = ThreadLocal.withInitial<Set<Syscall>> { emptySet() }
    val THREAD_ALLOWS_MMAP_EXEC = ThreadLocal.withInitial { true }
    val THREAD_ALLOWS_NON_THREAD_CLONE = ThreadLocal.withInitial { true }
    val THREAD_ALLOWS_UNSAFE_PRCTL = ThreadLocal.withInitial { true }
    val FILTER_DEPTH = ThreadLocal.withInitial { 0 }
    val THREAD_LANDLOCK_APPLIED_READS = ThreadLocal.withInitial<Set<String>?> { null }
    val THREAD_LANDLOCK_APPLIED_WRITES = ThreadLocal.withInitial<Set<String>?> { null }

    val PROCESS_BLOCKED: MutableSet<Syscall> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    val PROCESS_ALLOWS_MMAP_EXEC = AtomicBoolean(true)
    val PROCESS_ALLOWS_NON_THREAD_CLONE = AtomicBoolean(true)
    val PROCESS_ALLOWS_UNSAFE_PRCTL = AtomicBoolean(true)
    val PROCESS_FILTER_DEPTH = AtomicInteger(0)
}
