# Security Considerations & Technical Risks

While `contained-executors` provides a robust layer of defense by moving enforcement into the Linux kernel, using seccomp-bpf within the JVM introduces specific architectural risks. This document outlines those risks and provides mitigation strategies.

---

## 1. Thread Pool Poisoning

### The Risk
Seccomp filters are **permanent** for the lifetime of the OS thread and are **additive**. In Java, threads are often reused via `ExecutorService` (thread pools). 

If a task installs a seccomp filter on a thread and that thread then returns to a shared pool (like `ForkJoinPool.commonPool()` or a fixed `ThreadPoolExecutor`), all subsequent tasks assigned to that thread will be subject to the same restrictions. This can lead to non-deterministic `EPERM` errors in unrelated parts of the application.

### Mitigation
*   **Dedicated Pools:** Never apply `ContainedExecutors` to shared system pools. Always use a dedicated, isolated `ExecutorService` where the lifecycle of the threads is strictly managed.
*   **Thread Termination:** Use a `ThreadFactory` that creates threads which terminate once their "contained" lifecycle is over, or ensure the pool is exclusively used for restricted tasks.

---

## 2. The "Lazy Initialization" Trap

### The Risk
The JVM is a dynamic environment that performs many operations lazily:
*   **Class Loading:** Loading a new class may trigger a file `open` or `read`.
*   **JNI Loading:** `System.loadLibrary` triggers multiple syscalls (`open`, `mmap`, `mprotect`).
*   **GC & Management:** The JVM may spawn internal threads or allocate memory segments dynamically.

If a restricted thread (e.g., using `Policy.PURE_COMPUTE`) is the first thread in the application to trigger a specific lazy initialization path, the operation will fail with `EPERM`. This might not just fail the task; it could leave the JVM in a corrupted or partially initialized state.

### Mitigation
*   **Warm-up:** Ensure critical classes, providers (like `java.security`), and native libraries are loaded during application startup before containment is applied.
*   **Policy Granularity:** Avoid `PURE_COMPUTE` (blocking `open`) unless the task is strictly computational and all required resources are already in memory.

---

## 3. The `mmap` + `PROT_EXEC` Hole

### The Risk
The current implementation does not block `mmap` or `mprotect` because the JIT compiler requires these to create executable memory. However, an attacker can use `memfd_create` and `mmap` with `PROT_EXEC` to load and execute binary shellcode directly in memory, bypassing `NO_EXEC` (which only blocks `execve`).

### Mitigation
*   **W^X Enforcement:** Future versions should use seccomp argument inspection to allow `mmap`, but block calls where `(prot & PROT_WRITE) && (prot & PROT_EXEC)` is true.
*   **Note:** Standard seccomp cannot inspect the content of string paths, so it cannot distinguish between the JIT mapping memory and an attacker mapping a malicious library.

---

## 4. Virtual Thread Carrier Contamination

### The Risk
Virtual threads (Project Loom) multiplex many Java threads onto a small number of OS "carrier" threads. If you call `installOnCurrentThread` inside a virtual thread, you are actually sandboxing the carrier thread. Since carrier threads are shared across the JVM, this will inadvertently sandbox every other virtual thread that happens to be scheduled on that carrier.

### Mitigation
*   **Custom Schedulers:** Follow the pattern in the README: use a dedicated `Executor` as a scheduler for virtual threads, ensuring that the restricted carrier threads never run "trusted" system tasks.
*   **Avoid Default VT Executor:** Never use `ContainedExecutors.installOnCurrentThread()` inside the default `Executors.newVirtualThreadPerTaskExecutor()`.

---

## 5. Signal Handling and SIGSYS

### The Risk
If a seccomp filter is configured to return `SECCOMP_RET_TRAP`, the kernel sends a `SIGSYS` signal to the thread. If the JVM's signal handler is not prepared for this, the process will terminate. Even with `SECCOMP_RET_ERRNO` (returning `EPERM`), some low-level C libraries (used via JNI) may not handle `EPERM` gracefully and might trigger a hard crash or an abort.

### Mitigation
*   **Errno approach:** `contained-executors` defaults to returning `EPERM` (via `SECCOMP_RET_ERRNO`), which the JVM translates into an `IOException`. This is generally safer than signals.
*   **Testing:** Always test policies against the specific version of the JDK and native libraries being used, as internal syscall patterns change between versions.

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

## 7. The `clone` Syscall Paradox

### The Risk
Blocking `clone` prevents the creation of new threads. While this sounds secure, the JVM's `pthread_create` calls will fail. If a library tries to initialize a background worker (e.g., an OkHttp connection pool or a Logback AsyncAppender) from within a contained thread, the thread creation will fail.

### Mitigation
*   The library intentionally allows `clone`. Because seccomp filters are inherited, any thread created by a restricted thread will be **automatically restricted** by the same policy. This is a safe default.

---

## Summary Table: Security vs. Stability

| Policy | Security Level | Stability Risk | Best Use Case |
| :--- | :--- | :--- | :--- |
| `NO_EXEC` | Medium | Low | Web controllers, log processing. |
| `NO_NETWORK` | High | Medium | Data parsing, report generation. |
| `PURE_COMPUTE`| Very High | High | Pure algorithmic tasks (image processing, crypto). |

### Final Recommendation
**Fail-Closed in Production:** In your production environment, set `-Dio.contained.fallback=FAIL`. This ensures that if the seccomp filter cannot be installed (e.g., due to an incompatible kernel), the application will not run in an insecure "bypass" mode.

```bash
java -Dio.contained.fallback=FAIL -jar app.jar
```