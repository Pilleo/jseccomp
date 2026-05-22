
# Technical Design Document: jseccomp Bill of Behavior (BoB) Profiler & Exception Handling

This document provides the definitive, production-grade technical design for the **Bill of Behavior (BoB) Profiler** and the **Containment Exception Handling Subsystem** inside `jseccomp`. It incorporates deep systems-level findings, physics-level kernel constraints, and JVM-specific runtime behaviors.

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
                     |        jseccomp BoB Profiler          |
                     +---------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         ▼                               ▼                               ▼
+------------------+           +------------------+            +------------------+
|      Tier S      |           |      Tier A      |            |      Tier B      |
|  Out-of-Process  |           | Iterative Retry  |            | SECCOMP_RET_LOG  |
|   USER_NOTIF     |           | (Zero-Privilege) |            | (Aspirational)   |
+------------------+           +------------------+            +------------------+
```
### Tier S: Out-of-Process `USER_NOTIF` Supervisor (The Production Default)
Placing the supervisor thread inside the *same* JVM leads to fatal safepoint deadlocks. Relying on `strace` leads to noisy, process-wide telemetry and brittle text scraping. Instead, we use `SECCOMP_RET_USER_NOTIF` backed by a lightweight sidecar process communicating via Unix Domain Sockets using a structured binary protocol to prevent log injection.

**Synchronous & Stateless `profile<T>` API:**
The profiling session is run synchronously inside a dedicated OS platform thread via `Profiler.profile { block() }`. Spawning a dedicated thread ensures the seccomp filter is discarded once the thread exits, preventing filter leakage.

**Timing-Safe JVM Stack Capture:**
The Unix domain socket protocol includes a round-trip acknowledgment. The supervisor daemon blocks the worker thread in-kernel using seccomp, sends the `TraceEvent` to the parent JVM, and waits for an ACK byte. While the worker thread is blocked in-kernel, the trace listener in the parent JVM safely and stably captures the worker's Java stack trace via `Thread.stackTrace` on a best-effort basis, before sending the ACK. Once acknowledged, the daemon sends `FLAG_CONTINUE` to resume worker execution. This eliminates race conditions during stack profiling.

**SBoB-Aligned Composable Output:**
The profiler produces a `BillOfBehavior` representing raw observations of `opens`, `fsWritePaths`, `syscalls`, and `execs`, aligned to the Software Bill of Behavior (SBoB) spec draft v0.0.1. Bills from multiple runs can be composed using `+`, and transpiled to concrete enforcement policies via `bill.toPolicy(base)`.

**Audit-Assisted Asynchronous Profiling (`io_uring`):**
Because Seccomp-BPF is blind to operations submitted via `io_uring` rings, the Profiler automatically enables an **Audit-Assisted Sensor**. By applying a restrictive Landlock ruleset (denying everything except essential JVM classpath), the kernel is forced to emit `LANDLOCK_ACCESS` audit records for every other VFS or Network operation, including those originating from `io_uring` kernel worker threads. The `ProfilerDaemon` asynchronously ingests these kernel audit logs, extracts absolute paths, and merges them into the trace stream. This allows the profiler to correctly build Bills of Behavior for high-performance async applications while remaining unprivileged (to install). If the Netlink audit socket creation fails, the daemon logs a warning to stderr and degrades gracefully, leaving standard USER_NOTIF events fully operational.

*   **Targeted Filtering:** The JVM installs a `USER_NOTIF` seccomp filter *only* on the specific worker thread executing the task.
*   **FD Exfiltration:** Using FFM API and `sendmsg` (`SCM_RIGHTS`), the worker JVM passes the seccomp file descriptor to an external, lightweight Java daemon process.
*   **Deadlock Immunity:** Because the supervisor runs in a completely separate OS process, its JVM safepoints are physically isolated from the main JVM. It cannot cause a safepoint deadlock.
*   **Zero-Crash Execution (`FLAG_CONTINUE`):** When a worker thread blocks on a syscall, the external supervisor reads the notification struct. If the syscall takes pointer arguments (like `openat` file paths), the supervisor inspects the worker's memory via `process_vm_readv()` and resolves absolute paths by inspecting `/proc/[pid]/fd/`. After logging the operation to a binary stream back to the JVM, the supervisor replies to the kernel with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (Linux 5.5+). This guarantees the kernel executes the syscall natively without requiring dangerous user-space emulation.

### Multi-Thread Synchronization (`TSYNC`) Hazard
While `LANDLOCK_RESTRICT_SELF_TSYNC` (ABI 8, Linux 7.0) provides process-wide atomic sandboxing, it is **unsuitable for standard JVM test runners** and is **only available on cutting-edge kernels**. Most production servers and developer machines run LTS kernels (5.15, 6.1, 6.6) that do not support ABI 8; any use must include an explicit kernel version check. Because it sandboxes sibling threads, it breaks Gradle worker transparency and causes `Permission Denied` crashes on unrelated tasks. The profiler maintains TSYNC implementation for production baselines but disables it by default during profiling and testing to maintain suite stability.

```
Worker Thread (JVM 1)         Kernel            Supervisor Daemon (JVM 2)
...
      ├─ sys_openat() ─────────►│                         │
      │                         ├─ USER_NOTIF ───────────►│
      │   (Paused)              │                         ├─ Read syscall & args
      │                         │                         ├─ Read memory (process_vm_readv)
      │                         │◄─ FLAG_CONTINUE ────────┤
      │◄─ Native Execution ─────┤                         │
      │                         │                         │
```

### Tier A: Native Iterative Deny-and-Retry Loop (Zero-Privilege Fallback)
For heavily locked-down environments where Unix Domain Socket sidecars or `USER_NOTIF` are blocked by strict OCI container profiles, the `IterativeProfiler` provides a fully in-process, zero-privilege alternative:

1.  **Baseline Run:** Execute the target code under a restrictive baseline policy (e.g. `Policy.PURE_COMPUTE`).
2.  **Exception Accumulation:** Instead of stopping on the first `ContainmentViolationException`, the profiler collects all unique violations across the entire run.
3.  **Policy Expansion and Retry:** The blocked syscalls are appended to the policy model and the run is repeated.
4.  **Convergence:** Execution converges in O(N) runs, where N is the number of syscall categories the code needs. Typically fewer than 15 iterations.

This mechanism is 100% in-process with zero external sidecars. Build-system integration (e.g., Gradle) is a usage pattern on top of this mechanism, not part of the core design.

### Tier B: `SECCOMP_RET_LOG` Audit Logging (High Performance / Production Stage)
For build systems running in environments with access to host kernel logs (or have `log` enabled in `/proc/sys/kernel/seccomp/actions_logged`):

*   **Mechanism:** The profiling BPF filter returns `SECCOMP_RET_LOG` for all evaluated operations.
*   **Behavior:** The kernel executes every system call normally (zero overhead, zero crashes) and writes an audit record to the kernel ring buffer (`dmesg` / `auditd`).
*   **Compilation:** The profiler reads `/dev/kmsg` or streams system logs dynamically to generate the `Policy` file.

---

## 3. Exception Handling & Containment Violations

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

To prevent locale-fragile string matching, `jseccomp` uses a **multi-layered exception translation strategy**:

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

To protect the container environment from JVM lockups, the `jseccomp` policy builder will **enforce compile-time assertions** preventing developers from blocking these foundational operations:

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
*   **The Mitigation:** The profiler performs a kernel version check. If the kernel is `< 6.13`, it refuses to enable the Landlock-assisted sensor and logs a warning to stderr.

