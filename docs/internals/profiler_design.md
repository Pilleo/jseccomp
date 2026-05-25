
# Technical Design Document: mazewall Bill of Behavior (BoB) Profiler & Exception Handling

This document provides the definitive, production-grade technical design for the **Bill of Behavior (BoB) Profiler** and the **Containment Exception Handling Subsystem** inside `mazewall`. It incorporates deep systems-level findings, physics-level kernel constraints, and JVM-specific runtime behaviors.

---

## 1. Architectural Findings & Physics-Level Constraints

To build a reliable BoB (system call allowlist + Landlock path rules), we analyzed five potential interception boundaries. We discovered that every mechanism is bound by a fundamental trade-off between **JVM safety (safepoint deadlocks)**, **execution transparency (no application crashes)**, and **environment privileges (CI/CD compatibility)**.

```
                          Syscall Interception Mechanisms
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
  [ SECCOMP_RET_TRAP ]          [ SECCOMP_RET_USER_NOTIF ]         [ SECCOMP_RET_LOG ]
  - Trigger SIGSYS signal       - Delegate to supervisor thread    - Execute normally, log to audit
  - FATAL: Emulating returns    - FATAL: HotSpot GC safepoints     - EXCELLENT: Safe, transparent
    (rax=0) causes JVM null       pause supervisor while target    - LIMIT: Requires CAP_SYSLOG
    pointers & buffer garbage.    blocks in kernel -> DEADLOCK.      or host log namespace access.
```

### The Safepoint Deadlock (Why In-Process `USER_NOTIF` Supervision Failed)

The mechanism `SECCOMP_RET_USER_NOTIF` itself is sound and *is* used by the Tier S architecture (see §2). What failed is placing the supervisor thread **inside the same JVM process** as the traced thread. The Tier S solution retains `USER_NOTIF` as the kernel mechanism while moving the supervisor to a separate OS process.

Under in-process `SECCOMP_RET_USER_NOTIF`, the supervisor thread must synchronously decide to allow or block a syscall.
*   **The Trap:** If a Garbage Collection (GC) safepoint or a Thread Dump is triggered by the JVM while a worker thread is blocked in the kernel waiting for a seccomp decision, the JVM attempts to halt all threads.
*   **The Deadlock:** If the supervisor thread itself is paused by the JVM safepoint handler, it can never read the seccomp file descriptor. Meanwhile, the worker thread remains blocked in the kernel, unable to poll for the JVM safepoint. The entire JVM process is deadlocked permanently.

### The Emulation Failure (Why Native `SIGSYS` Mocking Failed)
Attempting to dynamically bypass blocked syscalls using a C-level signal handler by altering `ucontext_t` registers (`rax = 0`, `rip += 2`) is unstable for general JVM operations:
1.  **Memory Allocations (`mmap`/`brk`):** Returning `0` (NULL) causes immediate `SIGSEGV` when the JVM dereferences the address.
2.  **File Descriptors (`open`/`socket`):** Returning `0` mocks a valid file descriptor pointing to standard input (`stdin`). Future operations read garbage data.
3.  **Buffer-Writing Syscalls (`stat`/`clock_gettime`/`read`):** Returning success without copying correct memory values into the pointer arguments exposes uninitialized stack/heap garbage to HotSpot, causing silent corruption.

### Loom Virtual Thread Carrier Poisoning
Seccomp filters apply strictly to the underlying Linux OS thread (LWP). If the profiler or test suite executes seccomp loading from within a Virtual Thread, the filter permanently binds to the underlying `ForkJoinPool` carrier thread. Subsequent virtual threads mapped to this carrier will inherit the restricted context and crash.

**Architectural Guard:** The profiling test harness and the underlying library must detect Virtual Threads (`Thread.currentThread().isVirtual()`) and fail-closed with an `IllegalStateException` to prevent stacking on carrier threads unless specifically configuring a restricted carrier pool.

---

## 2. Tiered Profiling System Architecture

To bypass these constraints, we designed a **Tiered Profiling System** that provides a stable, unprivileged, and deadlock-free compilation flow.

```
                     +---------------------------------------+
                     |        mazewall BoB Profiler          |
                     +---------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         ▼                               ▼                               ▼
+------------------+           +------------------+            +------------------+
|      Tier P      |           |      Tier S      |            |      Tier A      |
|    Privileged    |           |  Out-of-Process  |            | Iterative Retry  |
|   eBPF / Trace   |           |   USER_NOTIF     |            | (Zero-Privilege) |
+------------------+           +------------------+            +------------------+
```

### Tier P: Privileged / Trace Profiler (Strace Subprocess Descendant Tracing)
In local development environments and CI/CD runners where host-level root-privileged eBPF is blocked or unavailable, Tier P utilizes a high-fidelity **`strace` subprocess descendant tracing** architecture (`StraceProfiler`).

#### The Unprivileged Container Yama Ptrace Scope Constraint
Inside rootless, unprivileged containers (e.g., standard Podman/Docker developer environments), attempting to attach `strace` to a running JVM process using `strace -p <PID>` fails with `EPERM` ("Operation not permitted"). This occurs because:
1. The host kernel's default Yama Linux Security Module (LSM) configuration is set to `kernel.yama.ptrace_scope = 1`, which strictly restricts tracing to parent-child descendant relationships (a process can only trace its own descendants).
2. The user namespace boundaries of rootless OCI runtimes prevent namespaced processes from easily calling `prctl(PR_SET_PTRACER, ...)` across JVM thread contexts without elevated capabilities.

#### The Subprocess Descendant Architecture
To achieve unprivileged, 100% container-compatible tracing, the profiler spawns a new child JVM process executed **directly under `strace -f`**. Under standard Linux kernel security boundaries, any process is fully permitted to trace its own spawned child descendants.

```
+-----------------------------+
|        StraceProfiler       |
+-----------------------------+
               │
               ▼ (ProcessBuilder)
    "strace -f -yy -e trace=file,network java ..."
               │
               ▼
+-----------------------------+
|     StraceWorkloadRunner    |  (Traced Child JVM)
+-----------------------------+
               │
               ▼ (Reflection)
+-----------------------------+
|      TraceableWorkload      |  (User Workload)
+-----------------------------+
```

1. **The Contract (`TraceableWorkload`):** The target workload implements the `TraceableWorkload` interface containing a single `run()` method.
2. **The Execution Helper (`StraceWorkloadRunner`):** Spawns a lightweight entrypoint inside a separate child JVM process. It receives the workload class name, loads it dynamically via reflection, and runs it.
3. **The Orchestration (`StraceProfiler`):** Executes `strace -f -yy -e trace=file,network` to trace all spawned threads and capture filesystem/network calls, sending trace output to a temporary log file.

#### High-Fidelity JVM Bootstrap Noise Filtering
A standard JVM boot triggers hundreds of system calls to locate class files, locate system properties, discover locales, and load native JDK library modules (e.g., `libzip.so`, `libnio.so`, timezone files). Scraping this raw log produces highly bloated, over-privileged security policies.
To guarantee a minimal, pristine `BillOfBehavior` profile, the log parser (`parseLine`) automatically filters out:
* **JDK System Folders:** Path patterns like `/lib`, `/usr/lib`, `/lib64`, and files loaded from the active `$JAVA_HOME`.
* **JVM Internals:** Common glibc resolver/loader caches like `/etc/ld.so.cache`, `/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/hosts`.
* **Classpath Jars:** Any directories and `.jar` archives declared in the active `java.class.path` system property.

This ensures that only actual, dynamic application-level read/write paths and network targets are whitelisted in the final security policy.

### Tier S: Out-of-Process `USER_NOTIF` Supervisor (The Unprivileged Default)
Placing the supervisor thread inside the *same* JVM leads to fatal safepoint deadlocks. Relying on `strace` leads to noisy, process-wide telemetry and brittle text scraping. Instead, we use `SECCOMP_RET_USER_NOTIF` backed by a lightweight sidecar process communicating via Unix Domain Sockets using a structured binary protocol to prevent log injection.

**Synchronous & Stateless `profile<T>` API:**
The profiling session is run synchronously inside a dedicated OS platform thread via `Profiler.profile { block() }`. Spawning a dedicated thread ensures the seccomp filter is discarded once the thread exits, preventing filter leakage.

**Timing-Safe JVM Stack Capture:**
The Unix domain socket protocol includes a round-trip acknowledgment. The supervisor daemon blocks the worker thread in-kernel using seccomp, sends the `TraceEvent` to the parent JVM, and waits for an ACK byte. While the worker thread is blocked in-kernel, the trace listener in the parent JVM safely and stably captures the worker's Java stack trace via `Thread.stackTrace` on a best-effort basis, before sending the ACK. Once acknowledged, the daemon sends `FLAG_CONTINUE` to resume worker execution. This eliminates race conditions during stack profiling.

**The `io_uring` Blind Spot & The Landlock Audit Catch-22:**
Seccomp-BPF is blind to operations submitted via `io_uring` rings.

> [!CAUTION]
> **PHYSICS-LEVEL CONSTRAINT:** Early design iterations suggested using **Landlock Audit** (Type 1423) for transparent `io_uring` profiling. **This is physically impossible.**
>
> Landlock does not have a "permissive" or "log-only" mode. It only emits an audit log when it **denies** access. If you apply a restrictive Landlock policy during profiling to force audit logs, Landlock will return `EACCES` to the application. This causes the JVM to crash with `FileNotFoundException` or `IOException`, breaking the profiling session.

*   **Targeted Filtering:** The JVM installs a `USER_NOTIF` seccomp filter *only* on the specific worker thread executing the task.
*   **FD Exfiltration:** Using FFM API and `sendmsg` (`SCM_RIGHTS`), the worker JVM passes the seccomp file descriptor to an external, lightweight Java daemon process.
*   **Deadlock Immunity:** Because the supervisor runs in a completely separate OS process, its JVM safepoints are physically isolated from the main JVM. It cannot cause a safepoint deadlock.
*   **Zero-Crash Execution (`FLAG_CONTINUE`):** When a worker thread blocks on a syscall, the external supervisor reads the notification struct. If the syscall takes pointer arguments (like `openat` file paths), the supervisor inspects the worker's memory via `process_vm_readv()` and resolves absolute paths by inspecting `/proc/[pid]/fd/`. After logging the operation to a binary stream back to the JVM, the supervisor replies to the kernel with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (Linux 5.5+). This guarantees the kernel executes the syscall natively without requiring dangerous user-space emulation.

### Tier A: Native Iterative Deny-and-Retry Loop (The Unprivileged Fallback)
For heavily locked-down environments where `root` is unavailable and Tier S is blocked by strict OCI container profiles, the `IterativeProfiler` provides a fully in-process, zero-privilege alternative:

1.  **Baseline Run:** Execute the target code under a restrictive baseline policy (e.g. `Policy.PURE_COMPUTE`).
2.  **Exception Accumulation:** Instead of stopping on the first `ContainmentViolationException`, the profiler catches `AccessDeniedException` and other I/O errors, extracts the missing path, and accumulates it.
3.  **Policy Expansion and Retry:** The blocked paths/syscalls are added to the policy model and the run is repeated.
4.  **Convergence:** Execution converges in O(N) runs.

**This is the ONLY unprivileged way to profile `io_uring` or Landlock paths.** Because Landlock is non-permissive, we must "learn" the policy by failing and retrying.

---

## 3. Profiling Identity vs. Performance

When profiling an application that supports `io_uring`, the choice of profiling tier affects how the policy is generated and how the application performs in enforcement.

### The Hybrid Profiling Shortcut (Recommended for io_uring)

Because `mazewall`'s complementary sandboxing design uses **Landlock** to enforce the actual filesystem boundaries, Seccomp's only job is to authorize the *mechanism* of I/O, while Landlock authorizes the *destination*.

This enables a highly efficient developer workflow that avoids the need for root (Tier P) or slow iterative retries (Tier A):

1.  **Disable `io_uring` during Profiling:** Run your test suite with `io_uring` temporarily disabled in the kernel (`sysctl -w kernel.io_uring_disabled=2`) or via framework configuration.
2.  **Profile the Slow Path:** The application gracefully falls back to standard POSIX I/O (`openat`, `read`, `epoll`). The unprivileged Tier S `USER_NOTIF` profiler flawlessly intercepts these fallback calls and records every required absolute filesystem path.
3.  **Abstract the Mechanism:** Take the generated DSL and manually append the `io_uring` system calls:
    ```kotlin
    .unblock(Syscall.IO_URING_SETUP, Syscall.IO_URING_ENTER)
    ```
4.  **Secure Enforcement in Production:** When deployed to a production environment where `io_uring` is enabled:
    *   Seccomp allows the `io_uring_setup` syscall.
    *   The application submits an async read to the ring.
    *   The kernel's `io-wq` worker thread executes the read.
    *   **Crucially, the `io-wq` worker inherits the Landlock ruleset of the thread that created it.**
    *   If the async worker tries to read an unauthorized path (e.g., due to an exploit), Landlock intercepts and denies it at the VFS LSM hook layer.

This hybrid approach leverages the ease of synchronous Tier S profiling while maintaining full asynchronous performance and perfect security in production.

| Profiling Strategy | Resulting Policy | Enforcement Behavior |
|--------------------|------------------|----------------------|
| **Hybrid (Tier S + Manual Add)**| Paths captured sync, async manually whitelisted | Application runs on the **Fast Path**. |
| **Tier P (Root)** | Paths and async captured natively | Application runs on the **Fast Path**. |
| **Tier A (Iterative)**| Paths and async learned via `EACCES` | Application runs on the **Fast Path**. |
| **Tier S (w/o manual add)** | Standard I/O only | Application is **Functionally Identical** but runs on the **Slow Path** (Seccomp blocks `io_uring_setup`, forcing app fallback). |



Handling containment errors inside a managed, multithreaded platform like the HotSpot JVM is highly delicate. If a thread attempts to make a blocked syscall, it receives `-EPERM`. We must translate this error deterministically without corrupting the JVM state.

```
                  Syscall Execution Flow (Error Path)
                                   │
                                   ▼
                       [ Blocked Syscall made ]
                                   │
                                   ▼ (Kernel returns -EPERM)
                       [ Syscall returns -1 ]
                                   │
      ┌────────────────────────────┴────────────────────────────┐
      ▼                                                         ▼
[ Core JVM/JNI calls ]                                   [ Pure Java I/O ]
- e.g. GC coordination, thread allocation                - e.g. socket connect, file access
- WARNING: Fatal JVM crash!                              - Catch raw glibc error codes
- Trap prevents permanent deadlocks.                      - Translate to ContainmentException
```

### The JVM Error Translation Strategy
Java's standard library does not expose raw OS `errno` values. For instance, when `openat` fails with `EPERM`, Java throws a generic `java.io.IOException` with a localized message.

To prevent locale-fragile string matching, `mazewall` uses a **multi-layered exception translation strategy**:

```kotlin
private fun isDirectContainmentViolation(t: Throwable): Boolean {
    // MUST restrict to IOException (which includes SocketException) to avoid false positives
    if (t !is java.io.IOException) return false

    // 1. Structural Match
    if (t is java.nio.file.AccessDeniedException) return true

    val msg = t.message ?: return false

    // 2. Exact JVM System Code Checks (locale-insensitive)
    if (msg.contains("error=1") || msg.contains("error=13")) {
        // error=1 is EPERM (Operation not permitted)
        // error=13 is EACCES (Permission denied)
        return true
    }

    // 3. Exact OS Error Message Match Fallback
    // Prohibited to use broad fragments like "denied" without strict class limits
    if (msg.contains("Permission denied") || msg.contains("Operation not permitted")) {
        return true
    }

    return false
}
```

### Safepoint Safeguard and JVM Coordination Trap
Some syscalls are strictly forbidden from being blocked because they handle HotSpot thread coordination. If blocked, the JVM will fail to run garbage collection or safely allocate structures, causing the process to abort immediately.

To protect the container environment from JVM lockups, the `mazewall` policy builder will **enforce compile-time assertions** preventing developers from blocking these foundational operations:

```kotlin
// The Policy.Builder enforces that coordination primitives are ALWAYS allowed:
internal fun assertSafeCoordination(blocked: Set<Syscall>) {
    val prohibited = setOf(
        Syscall.FUTEX,          // JVM thread parking / locking
        Syscall.SCHED_YIELD,    // Thread scheduling coordination
        Syscall.RT_SIGRETURN,   // Signal return context restoration
        Syscall.MADVISE,        // JVM virtual memory management
        Syscall.MPROTECT,       // JVM GC page allocation & memory protection
        Syscall.GETTID          // Thread ID retrieval (needed for logging/GC)
    )
    val intersection = blocked.intersect(prohibited)
    if (intersection.isNotEmpty()) {
        throw IllegalArgumentException("Cannot block JVM coordination syscalls: $intersection. Doing so will freeze the JVM.")
    }
}
```

---

## 4. Policy DSL Compilation Example

At the end of a profiling run, raw observations are converted into a `BillOfBehavior`. Calling `bill.toDsl("Policy.PURE_COMPUTE")` compiles the bill and produces a clean, copy-pasteable Kotlin DSL code snippet:

```kotlin
// Automatically compiled and emitted by BillOfBehavior.toDsl():
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    // Syscall whitelists compiled from trace events:
    .unblock(
        Syscall.READ,
        Syscall.WRITE,
        Syscall.EPOLL_WAIT,
        Syscall.EVENTFD2
    )
    // File paths collapsed to minimal directories:
    .allowFsRead("/workspace/app/src/main/resources/")
    .allowFsWrite("/workspace/app/build/tmp/")
    .build()
```

---

## 5. Operational Hazards & Kernel Constraints

### Yama LSM & Grandchild Inheritance
Under Linux Yama LSM (`/proc/sys/kernel/yama/ptrace_scope` >= 1), a process must explicitly grant ptrace permissions to its tracer using `prctl(PR_SET_PTRACER, tracer_pid)`.
*   **The Hazard:** This permission is **not inherited across `fork()`**.
*   **The Impact:** If the profiled JVM process forks a child (e.g., via `ProcessBuilder`), the child inherits the seccomp filter (and thus traps to the daemon) but does **not** inherit the ptrace permission.
*   **The Mitigation:** The `ProfilerDaemon` must gracefully handle `-EPERM` when attempting to read a grandchild's memory via `process_vm_readv`. In such cases, the daemon logs the syscall without absolute path resolution.

### Seccomp Listener `-ENOSYS` JVM Crash
When a seccomp `USER_NOTIF` listener file descriptor is closed while tracee threads are still blocked in the kernel waiting for a decision:
*   **The Hazard:** The kernel unblocks the tracees and forces the trapped syscall to return `-ENOSYS` (Function not implemented).
*   **The Impact:** HotSpot does not expect `-ENOSYS` for standard syscalls like `openat` or `write`. This typically results in an unrecoverable `IOException` or a fatal JVM abort if the syscall was part of a critical internal runtime operation.
*   **The Mitigation:** The profiler implements a **Graceful Shutdown Protocol**. Before destroying the daemon, the JVM sends a `SHUTDOWN` command (`0x53`). The daemon responds by issuing `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to all pending notifications, allowing threads to resume native execution before the listener is destroyed.

### Landlock Audit Versioning
Landlock Audit logging (`LANDLOCK_ACCESS` records) is a kernel-specific telemetry feature.
*   **The Hazard:** `AUDIT_LANDLOCK_ACCESS` was introduced in **Linux 6.13** (Landlock ABI 7).
*   **The Impact:** On kernels older than 6.13 (including standard LTS versions like 5.15), applying a restrictive Landlock "Audit" policy will silently block operations with `EACCES` without emitting any audit logs, causing the profiler to miss dependencies and the application to crash.
*   **The Mitigation:** Transparent profiling of `io_uring` via Landlock Audit is physically impossible due to the lack of a permissive mode. `mazewall` requires either **Tier P (Privileged eBPF)** for transparent capture or **Tier A (Iterative Profiler)** to handle the non-transparent `EACCES` denials via retries.

