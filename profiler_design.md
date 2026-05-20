
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

### The Safepoint Deadlock (Why `USER_NOTIF` Failed)
Under `SECCOMP_RET_USER_NOTIF`, the supervisor thread must synchronously decide to allow or block a syscall. 
*   **The Trap:** If a Garbage Collection (GC) safepoint or a Thread Dump is triggered by the JVM while a worker thread is blocked in the kernel waiting for a seccomp decision, the JVM attempts to halt all threads. 
*   **The Deadlock:** If the supervisor thread itself is paused by the JVM safepoint handler, it can never read the seccomp file descriptor. Meanwhile, the worker thread remains blocked in the kernel, unable to poll for the JVM safepoint. The entire JVM process is deadlocked permanently.

### The Emulation Failure (Why Native `SIGSYS` Mocking Failed)
Attempting to dynamically bypass blocked syscalls using a C-level signal handler by altering `ucontext_t` registers (`rax = 0`, `rip += 2`) is unstable for general JVM operations:
1.  **Memory Allocations (`mmap`/`brk`):** Returning `0` (NULL) causes immediate `SIGSEGV` when the JVM dereferences the address.
2.  **File Descriptors (`open`/`socket`):** Returning `0` mocks a valid file descriptor pointing to standard input (`stdin`). Future operations read garbage data.
3.  **Buffer-Writing Syscalls (`stat`/`clock_gettime`/`read`):** Returning success without copying correct memory values into the pointer arguments exposes uninitialized stack/heap garbage to HotSpot, causing silent corruption.

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
|      Tier A      |           |      Tier B      |            |      Tier C      |
|  strace Wrapper  |           | Iterative Retry  |            | SECCOMP_RET_LOG  |
|  (Default - CI)  |           | (Zero-Privilege) |            | (Aspirational)   |
+------------------+           +------------------+            +------------------+
```

### Tier A: Out-of-Process `strace` Hooking (The Recommended Default)
Rather than placing the supervisor inside the JVM, we move it entirely **out-of-process** using standard Linux `ptrace` via an `strace` execution wrapper.

*   **Deadlock Prevention:** Because `strace` is an external OS process, it is immune to JVM safepoint pauses. If HotSpot triggers GC, `strace` continues to process and resume ptraced system calls normally.
*   **Zero-Dependency Parsing:** 
    1.  The test execution runs under:
        `strace -f -yy -e trace=file,network,process,desc -o build/reports/syscalls.trace ./gradlew test`
    2.  An analyzer engine parses the text logs to reconstruct the BoB:
        *   Extracts unique syscall names (e.g. `epoll_create1`, `newfstatat`).
        *   Extracts dynamic file paths resolved in `openat` and `newfstatat` (for Landlock path compiler).
        *   Discards standard JVM bootstrap calls (everything before the library's initial `ContainedExecutors` wrap call is detected in the log via a signature trace marker).

```
[ strace log tracepoint ]
12345 openat(AT_FDCWD, "/workspace/data/in.txt", O_RDONLY) = 4
       │
       ▼ (Parser isolates the path + call)
BoB: Syscall.OPENAT + allowFsRead("/workspace/data/")
```

### Tier B: Native Iterative Deny-and-Retry Loop (Zero-Privilege Fallback)
For environments where `CAP_SYS_PTRACE` is restricted (such as locked-down Kubernetes pods or container runners without trace privileges):

1.  **Accumulation Hook:** We run tests under a baseline `Policy.PURE_COMPUTE`.
2.  **Continuous Run:** Instead of immediately stopping the suite on the first exception, our wrapper collects all unique `ContainmentViolationException` instances thrown by worker threads.
3.  **Gradle Orchestration:** The Gradle runner catches these exceptions, appends the blocked syscalls to the temporary policy model, and re-executes the suite.
4.  **Convergence:** The execution converges in $O(N)$ runs (where $N$ is the number of unwhitelisted syscall categories utilized by the test suite, typically < 15 for typical computing blocks). It runs 100% in user-space with zero external packages or capabilities required.

### Tier C: `SECCOMP_RET_LOG` Audit Logging (High Performance / Production Stage)
For build systems that run in environments with access to host kernel logs (or have `log` enabled in `/proc/sys/kernel/seccomp/actions_logged`):

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
    // 1. Structural Match
    if (t is AccessDeniedException) return true

    val msg = t.message ?: return false

    // 2. Exact JVM System Code Checks (locale-insensitive)
    if (msg.contains("error=1") || msg.contains("error=13")) {
        // error=1 is EPERM (Operation not permitted)
        // error=13 is EACCES (Permission denied)
        return true
    }

    // 3. Multilingual Regex Fallback
    if (VIOLATION_MESSAGE_REGEX.containsMatchIn(msg)) {
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

At the end of a profiling run (regardless of the Tier chosen), the accumulated JSON data is passed to the **DSL Code Generator**, producing clean, copy-pasteable Kotlin or Java code:

```kotlin
// Automatically compiled and emitted by BobCompiler:
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    // Syscall whitelists compiled from trace logs:
    .allowSyscalls(
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
