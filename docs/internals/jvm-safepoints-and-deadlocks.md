# JVM Safepoints and Deadlocks

## The GC and Safepoint Deadlock Risk

Applying extreme restrictions like `Policy.PURE_COMPUTE_UNSAFE` inside a HotSpot JVM comes with a massive, implicit runtime risk: **Safepoints and GC cycles.**

A JVM thread is never a completely isolated island. Periodically, the JVM pauses application threads to perform Garbage Collection, generate thread dumps, or execute runtime optimizations (safepoints). To coordinate these operations, application threads must run JVM runtime code, which frequently invokes system calls for synchronization and resource management:
* `futex` for native lock acquisition and thread waking.
* `sched_yield` to relinquish CPU slices during contention.
* `rt_sigreturn` to exit from signals triggered by safepoint interrupts.

If a custom `mazewall` policy aggressively blocks these utility system calls in a worker thread, the thread will fail to coordinate during the next JVM safepoint. The result is a **catastrophic, VM-wide deadlock or immediate JVM crash**.

### Why Seccomp "Strict Mode" is Incompatible

Linux provides a "strict mode" for seccomp (`SECCOMP_SET_MODE_STRICT` or `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)`), which limits a thread to exactly four system calls: `read()`, `write()`, `_exit()`, and `sigreturn()`.

**This mode is completely unusable within any JVM thread.** 

Because HotSpot (and other modern runtimes like Go or Node.js) requires constant access to `futex()`, `mprotect()`, `madvise()`, and `gettid()` for basic orchestration, a JVM thread placed in Strict Mode will be instantly terminated by the kernel (`SIGKILL`) the moment it attempts to:
*   Synchronize on a Java object (monitor).
*   Allocate memory that triggers a page guard.
*   Wait for a GC Safepoint to finish.

In `mazewall`, we exclusively use **Filter Mode** (`SECCOMP_SET_MODE_FILTER`), allowing us to whitelist the "JVM floor" while restricting application-specific dangerous operations.

> [!CAUTION]
> **Extensive Testing Mandatory.** When creating custom policies, you must never block core JVM synchronization and scheduling primitives. Your policies must be tested under heavy thread contention, high-throughput garbage collection, and active thread dumps in staging environments before any consideration of non-production deployment.

---

## Native vs. JIT Strictness: GraalVM's Advantage

This safepoint deadlock risk exposes a fundamental difference in sandboxing strictness between **JIT-compiled HotSpot JVMs** and **AOT-compiled GraalVM Native Images**:

1. **HotSpot JVM (JIT):** Requires a highly permissive system call floor. Because HotSpot dynamically compiles native code, manages dynamic classloading, and performs complex runtime optimizations, application threads running in HotSpot require access to dynamic memory allocation, thread signaling, and logging.
2. **GraalVM Native Image (AOT):** Can run under an extremely restrictive system call floor. A native binary compiles directly to an ahead-of-time machine executable. It has no JIT compiler thread, no dynamic classloader, and a highly streamlined runtime garbage collector. 

This means that for pure mathematical computation or isolated data parsing tasks, a **GraalVM native binary can safely block system calls that a standard HotSpot JVM would require to avoid crashing**. If you need absolute syscall minimization, compiling to a Native Image is your most resilient path.

---