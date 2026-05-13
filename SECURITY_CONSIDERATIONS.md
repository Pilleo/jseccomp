# Security Considerations & Technical Risks


While `contained-executors` provides a robust layer of defense by moving enforcement into the Linux kernel, using seccomp-bpf within the JVM introduces specific architectural risks. This document outlines those risks and our mitigation strategies.

---

## 1. Thread Pool Poisoning

### The Risk
Seccomp filters are **permanent** for the lifetime of the OS thread and are **additive**. In Java, threads are often reused via `ExecutorService` (thread pools). 

If a task installs a seccomp filter on a thread and that thread then returns to a shared pool (like `ForkJoinPool.commonPool()` or a fixed `ThreadPoolExecutor`), all subsequent tasks assigned to that thread will be subject to the same restrictions. This can lead to non-deterministic `EPERM` errors in unrelated parts of the application.

### Mitigation
*   **Dedicated Pools:** Never apply `ContainedExecutors` to shared system pools. Always use a dedicated, isolated `ExecutorService` where the lifecycle of the threads is strictly managed.
*   **Thread Termination:** Use a `ThreadFactory` that creates threads which terminate once their "contained" lifecycle is over, or ensure the pool is exclusively used for restricted tasks.
*   **Safety Tracking:** The library tracks the number of filters installed per thread (`FILTER_DEPTH`) and will throw an `IllegalStateException` before hitting the Linux kernel limit (typically 32).

---

## 2. The "Lazy Initialization" Trap

### The Risk
The JVM is a dynamic environment that performs many operations lazily:
*   **Class Loading:** Loading a new class may trigger a file `open` or `read`.
*   **JNI Loading:** `System.loadLibrary` triggers multiple syscalls (`open`, `mmap`, `mprotect`).
*   **GC & Management:** The JVM may spawn internal threads or allocate memory segments dynamically.

If a restricted thread (e.g., using `Policy.PURE_COMPUTE`) is the first thread in the application to trigger a specific lazy initialization path, the operation will fail.

### Mitigation
*   **Warm-up:** Ensure critical classes, providers (like `java.security`), and native libraries are loaded during application startup before containment is applied.
*   **Selective Blocking:** We use argument inspection for critical syscalls like `clone` and `mmap` to allow JVM-internal operations while blocking malicious ones (see below).

---

## 3. Executive Control: Argument Inspection

Previously, syscalls were blocked based only on their number. This meant that syscalls like `mmap` and `clone` had to be allowed entirely to avoid crashing the JVM. `contained-executors` now uses BPF argument inspection to provide fine-grained control.

### Executable Memory Protection (`mmap`)
*   **The Risk:** An attacker can use `mmap` with `PROT_EXEC` to allocate executable memory for binary shellcode, bypassing `NO_EXEC` policies.
*   **Our Fix:** We inspect the `prot` argument. We allow standard `mmap` calls but trigger a trap if the `PROT_EXEC` (0x04) bit is set. This blocks shellcode execution while allowing the JIT and GC to function normally.

### JVM Stability Protection (`clone`)
*   **The Risk:** Blocking `clone` entirely prevents the JVM from creating internal threads, leading to crashes. However, allowing it allows an attacker to spawn new processes (`fork`).
*   **Our Fix:** We inspect the `flags` argument. We allow `clone` only if it includes `CLONE_THREAD` or `CLONE_VM` (indicating a new thread within the process). Standard process forking is blocked.
*   **`clone3` Handling:** We block `clone3` with `ENOSYS`, forcing fallbacks to the inspectable legacy `clone` syscall.

---

## 4. Virtual Thread Carrier Contamination

### The Risk
Virtual threads (Project Loom) multiplex many Java threads onto a small number of OS "carrier" threads. If you install a filter from within a virtual thread, you sandbox the carrier thread, inadvertently affecting every other virtual thread scheduled on that carrier.

### Mitigation
*   **Guardrails:** `ContainedExecutors.installOnCurrentThread()` detects if it is being called from a virtual thread and throws an `IllegalStateException`.
*   **Platform Threads:** Always run restricted tasks on Platform Threads via `ContainedExecutors.wrap(Executors.newFixedThreadPool(...))`.

---

## 5. Signal Handling and Violation Detection

### The Mechanism
We use `SECCOMP_RET_TRAP` for violations. This triggers a `SIGSYS` signal which is captured by our native signal handler.

### The Risk
If the signal handler is not async-signal-safe, it can cause deadlocks or crashes. 
*   **Our Mitigation:** Our handler is written in Kotlin but adheres to async-signal-safety rules. It uses a pre-allocated shared memory segment (`VIOLATION_MAP`) indexed by thread ID to record violations, avoiding Java's `ThreadLocal` or heap allocations.

### Why not `SECCOMP_RET_USER_NOTIF`?
Modern Linux (5.0+) supports `SECCOMP_RET_USER_NOTIF`, which allows a supervisor thread to intercept syscalls, inspect pointer arguments (like `clone3`'s `struct clone_args` in target memory), and allow/deny them dynamically.

*   **The Benefits:** It would allow us to natively inspect modern syscalls like `clone3` without forcing a fallback.
*   **The Struggle in Pure Java:** Implementing `USER_NOTIF` purely via the FFM API is extremely brittle. It requires hardcoding the exact memory layouts of kernel structures (`seccomp_notif`) and recalculating complex `ioctl` constants (like `SECCOMP_IOCTL_NOTIF_RECV`) that are defined as C macros. These macros incorporate the exact byte size of the structures, meaning a slight mismatch in alignment or padding between architecture versions causes the `ioctl` to fail silently. In our testing, this resulted in an unrecoverable infinite `poll()` loop that starved the JVM.
*   **The Native Alternative:** We could write the supervisor loop in Rust or C, compile it to a `.so` file, and bundle it. This provides access to native `<linux/seccomp.h>` headers, making `USER_NOTIF` rock-solid. However, this introduces massive distribution complexity (cross-compiling for x86_64, aarch64, etc., and unpacking binaries at runtime).
*   **The Decision:** To maintain a 100% pure Java library that is lightweight and easy to distribute, we rely on the mathematically provable `SIGSYS` trap mechanism and use `ENOSYS` to force runtimes to fallback to inspectable legacy syscalls (like `clone`). This is the exact same architectural decision made by **Elasticsearch** in their internal `SystemCallFilter`, which also relies on pure Java native bindings to avoid shipping custom C binaries.

---

## 6. Information Leaks (Side Channels)

### The Risk
Seccomp restricts **actions** (syscalls), but it does not provide **data isolation**. 
*   A contained thread can still read any static variable in the JVM.
*   A contained thread can still read the heap if it has references to shared objects.
*   It can use side channels (CPU timing, cache contention) to leak data to another, non-contained thread.

### Mitigation
*   Seccomp is a "blast radius" mitigator for I/O and execution. It is **not** a replacement for internal Java security boundaries (like module exports) or data encryption.

---

## Summary Table: Security vs. Stability

| Policy | Security Level | Stability Risk | Best Use Case |
| :--- | :--- | :--- | :--- |
| `NO_EXEC` | High | Low | Web controllers, log processing. |
| `NO_NETWORK` | High | Medium | Data parsing, report generation. |
| `PURE_COMPUTE`| Critical | High | Pure algorithmic tasks (image processing, crypto). |

### Final Recommendation
**Fail-Closed in Production:** In your production environment, set `-Dio.contained.fallback=FAIL`. This ensures that if the seccomp filter cannot be installed (e.g., due to an incompatible kernel), the application will not run in an insecure "bypass" mode.
