# Security Considerations & Technical Risks

Using seccomp-bpf within the JVM introduces specific architectural risks. This document outlines high-level security properties and implementation trade-offs.

---

## 1. Thread-Level vs. Process-Level Isolation

Seccomp filters on Linux can be applied to a single thread or the entire process. This library supports both via `installOnCurrentThread` and `installOnProcess`.

### The "Elasticsearch Approach" (Process-Wide)
For years, industry leaders like **Elasticsearch** have successfully used a minimal, process-wide seccomp filter to prevent Remote Code Execution (RCE). By blocking a small set of syscalls (`fork`, `vfork`, `execve`, `execveat`) globally at startup, they ensure that even if a vulnerability like Log4Shell is exploited, the attacker cannot spawn a shell.

**Recommendation:** Use `ContainedExecutors.installOnProcess(Policy.NO_EXEC)` as your foundational baseline defense.

### Thread-Level Mitigation & The "Pivot" Risk
Thread-level containment (e.g., wrapping an `ExecutorService`) is a powerful "blast radius" mitigator, but it is not an absolute sandbox. Because Java threads share a single heap, an attacker with **Arbitrary Code Execution (ACE)** can theoretically "pivot" to an unrestricted thread (e.g., by submitting a task to the JVM's `ForkJoinPool.commonPool()`).

---

## 2. The "Blast Radius" Architecture

We recommend a two-tiered defense-in-depth model:

1.  **Tier 1: Global Lockdown (`installOnProcess`):** Apply `Policy.NO_EXEC` process-wide at startup to permanently disable shell spawning. This prevents the "pivot" attack because no unrestricted threads remain.
2.  **Tier 2: Surgical Restrictions (`wrap`):** Apply stricter policies (like `Policy.NO_NETWORK` or `Policy.PURE_COMPUTE`) to specific worker pools handling untrusted data (e.g., XML parsers, image processors). This stops **Data-Oriented Attacks** (SSRF, XXE, Path Traversal) where the attacker lacks the ACE required to pivot.

## 3. Advanced Syscall Evasion & Modern Attack Vectors

Blocking `execve` (spawning a shell) is a foundational defense, but sophisticated attackers use several techniques to bypass simple syscall filters.

### Fileless Malware (`memfd_create`)
Attackers can create anonymous, memory-backed file descriptors using `memfd_create`. They can then download an ELF binary into this "fileless" descriptor and execute it using `fexecve` or `execveat`. Because the binary never touches the disk, it bypasses traditional filesystem-based security scanners.
*   **Mitigation:** `jseccomp` includes `MEMFD_CREATE` in its strict policies (e.g., `PURE_COMPUTE`) and recommends blocking it wherever possible, as the standard JVM does not require it for normal operation.

### Modern Execution Variants (`execveat`)
Attackers may use `execveat` to execute programs relative to a directory file descriptor. This can sometimes bypass filters that only monitor the absolute path arguments of the classic `execve`.
*   **Mitigation:** `jseccomp` explicitly blocks `EXECVEAT` in all `NO_EXEC` policies.

### Asynchronous Evasion (`io_uring`)
Modern Linux systems support `io_uring` for high-performance asynchronous I/O. Attackers increasingly abuse this subsystem to bypass seccomp filters. Because operations are submitted via a shared memory ring queue rather than individual syscalls, a standard seccomp profile might not "see" the read/write/exec operations happening inside the ring.

A useful mental model is this: **eBPF sees the action; Seccomp only sees the ring.** Because Seccomp is "blind" to the contents of these shared memory buffers, `jseccomp` adopts a conservative stance: *"Since I can't see into your rings, you aren't allowed to have rings."*
*   **Mitigation:** `jseccomp` explicitly blocks `io_uring_setup` in its strict policies. The standard JVM (currently) relies heavily on standard NIO/epoll and does not require `io_uring` for application-level worker threads.

### Binary Shellcode Injection
If an attacker cannot spawn a process, they will attempt to inject raw machine code (shellcode) into the JVM's memory. To run this code, they must mark the memory as executable using `mprotect` or `mmap`.
*   **Mitigation:** As detailed in the "Argument Inspection" section, `jseccomp` monitors the `PROT_EXEC` bit. It allows the JVM to manage its memory but physically prevents any thread under a policy from making a memory region executable.

### ROP/JOP & Existing Memory
It is critical to understand that Seccomp monitors **system calls**, not internal CPU instruction flow. While `jseccomp` effectively blocks the introduction of *new* executable memory (shellcode), it cannot prevent an attacker from reusing **existing** executable code already mapped in the JVM's memory (e.g., from the JVM itself or its dependencies). 
By chaining together existing snippets of code (gadgets), an attacker can perform **Return-Oriented Programming (ROP)** or **Jump-Oriented Programming (JOP)** to execute arbitrary logic without ever calling `mprotect` or `mmap`. 
*   **Mitigation:** Protection against ROP/JOP relies on complementary OS and compiler-level features such as **ASLR (Address Space Layout Randomization)**, **Stack Canaries**, and **Control Flow Integrity (CFI)**. Seccomp provides a hard barrier against environment-altering actions (spawn shell, network access), but it is not a complete solution for all memory corruption exploitation techniques.

---

## 5. Escaping Process-Level Containment

Even with process-wide `NO_EXEC`, an attacker with ACE can theoretically escape to the host OS if other security layers are missing:

*   **File System Pivot:** If the JVM user has write access to directories like `/etc/cron.d/`, an attacker can write a malicious script that the host OS will eventually execute with full privileges.
*   **Local Network Pivot:** If the JVM can access local unauthenticated APIs (e.g., the Docker socket at `/var/run/docker.sock`), it can command the host to spawn a new, unconstrained container.
*   **Persistence & Restart:** If the attacker can modify application binaries or configuration and then force a JVM crash, they may trick an orchestrator (Systemd/Kubernetes) into restarting the JVM without the seccomp filter enabled.

---

## 6. Defense-in-Depth Requirements

To make seccomp an effective barrier, the host environment **must** implement these complementary controls:

*   **Least Privilege:** Never run the JVM as `root`.
*   **Read-Only Root:** Use a read-only filesystem for the application and system directories to prevent script injection.
*   **Network Segmentation:** Prevent the JVM from reaching local administrative sockets or sensitive metadata services.

---

## 7. Technical Safeguards: Argument Inspection

`contained-executors` uses BPF argument inspection to provide fine-grained control over critical syscalls, allowing the JVM to function while blocking malicious actions.

### Executable Memory Protection (`mmap`)
We inspect the `prot` argument of `mmap`. Standard mappings are allowed, but the library triggers an immediate `EPERM` if the `PROT_EXEC` (0x04) bit is set. This blocks binary shellcode execution while allowing the JIT and GC to function normally.
> **Note on 32-bit Truncation:** BPF jump/load instructions natively operate on 32-bit words. The filter loads the lower 32 bits of the `prot` argument to check for `PROT_EXEC`. Since the Linux kernel internally casts the `prot` flag to an `unsigned long` but only honors the standard lower bits defined in POSIX, this 32-bit truncation is secure and matches kernel behavior.

### JVM Stability Protection (`clone`)
We inspect the `flags` argument of `clone`. We allow `clone` only if it includes **both** `CLONE_THREAD` and `CLONE_VM` (indicating a new thread). Standard process forking (`fork`) and memory-sharing processes (`CLONE_VM` without `CLONE_THREAD`) are blocked. `clone3` is blocked with `ENOSYS` to force runtimes to fallback to the inspectable legacy `clone`.

---

## 8. Known Limitations & Caveats

### Inherited File Descriptors
Seccomp filtering applies to *syscalls*, not *data structures*. If a thread inherits an open socket file descriptor (or receives one via `SCM_RIGHTS`) before the `NO_NETWORK` policy is applied, it can still call `recvmsg`, `recvfrom`, `write`, or `writev` on that existing descriptor. `NO_NETWORK` prevents the creation of *new* sockets (`socket`, `connect`, `bind`, `accept`), but does not block generic read/write syscalls which are essential for standard JVM I/O.

### Non-English Locales and Violation Exceptions
Java's core `IOException` classes do not expose the raw OS `errno` values. To detect containment violations (which throw `EPERM` or `EACCES`), this library matches the localized exception messages (e.g., "Operation not permitted" or "Permission denied") combined with specific JVM error codes (`error=1` or `error=13`).
On non-English locales, if the JVM translates these messages entirely, a blocked syscall will still be successfully intercepted by the kernel, but the application may throw a generic `IOException` rather than the specific `ContainmentViolationException`. The security guarantee remains intact; only the exception wrapping is affected.

### Platform Support
Seccomp-BPF and Landlock are Linux-only features. The library safely performs an OS-level check (`Platform.isSupported()`) before initializing native FFM bindings. On macOS or Windows, the library degrades gracefully based on the `IO_CONTAINED_FALLBACK` policy (failing fast or logging a warning and running uncontained) without throwing `UnsatisfiedLinkError` or `WrongMethodTypeException`.

---

## 9. Information Leaks (Side Channels)

Seccomp restricts **actions** (syscalls), but it does not provide **data isolation**. 
*   A contained thread can still read any static variable or heap object it can reference.
*   It can use side channels (CPU timing, cache contention) to leak data to another thread.

---

## Summary: Security vs. Stability

| Policy | Security Level | Stability Risk | Best Use Case |
| :--- | :--- | :--- | :--- |
| `NO_EXEC` | High | Low | Global process-wide lockdown (Elasticsearch model). |
| `NO_NETWORK` | High | Medium | Data parsing, report generation. |
| `PURE_COMPUTE`| Critical | High | Pure algorithmic tasks (image processing, crypto). |
