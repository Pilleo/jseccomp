# Security Considerations & Technical Risks

## Security Model — Executive Summary

> **Tier 1** (`ContainedExecutors.installOnProcess(Policy.NO_EXEC)`): Blocks `execve`/`fork` process-wide at startup. Nothing in this JVM ever spawns a shell or child process, regardless of which thread is compromised. This is the mandatory architectural backstop.
>
> **Tier 2** (`ContainedExecutors.wrap(executor, policy)`): Restricts specific syscalls and filesystem paths on a given thread pool. Stops **data-plane attacks** (SSRF, XXE, path traversal, fileless malware) on processing threads where trusted code handles untrusted data.
>
> ⚠️ **Tier 2 alone does NOT isolate arbitrary Java code.** An attacker who achieves Java-level code execution (e.g., via deserialization RCE) can escape to unrestricted sibling threads using `CompletableFuture.runAsync(...)` or virtual threads — no ACE required. Always stack Tier 1 first. See [§1](#1-thread-level-vs-process-level-isolation) for the complete ACE pivot analysis.

---

Using seccomp-bpf within the JVM introduces specific architectural risks. This document outlines high-level security properties and implementation trade-offs.

---

## 1. Thread-Level vs. Process-Level Isolation

Seccomp filters on Linux can be applied to a single thread or the entire process. `mazewall` supports both via `installOnCurrentThread` (Tier 2) and `installOnProcess` (Tier 1).

### The "Elasticsearch Approach" (Process-Wide)
For years, industry leaders like **Elasticsearch** have successfully used a minimal, process-wide seccomp filter to prevent Remote Code Execution (RCE). By blocking a small set of syscalls (`fork`, `vfork`, `execve`, `execveat`) globally at startup, they ensure that even if a vulnerability like Log4Shell is exploited, the attacker cannot spawn a shell.

**Recommendation:** Use `ContainedExecutors.installOnProcess(Policy.NO_EXEC)` as your foundational baseline defense.

### Thread-Level Mitigation & The "ACE Shared-Memory Pivot" Threat Model
Thread-level containment (e.g., wrapping an `ExecutorService` with restrictive policies like `PURE_COMPUTE_UNSAFE`) is a powerful tool to minimize the blast radius of un-trusted library execution. However, **thread-scoped seccomp is not an absolute security boundary against an attacker who achieves Arbitrary Code Execution (ACE) on that thread.**

Because the JVM runs within a single Linux process, **all JVM threads share the same physical address space, virtual memory maps, and heap.**

To understand the exact security boundaries of Tier 2, we must draw a hard line between **Untrusted Data** and **Untrusted Code**:

#### What Tier 2 Stops: Untrusted Data
Tier 2 containment effectively isolates trusted code processing malicious data, as well as vulnerabilities in native libraries.
1.  **Data-Oriented Attacks (SSRF, XXE):** If an attacker submits a malicious XML payload (XXE) designed to make your trusted parser read `/etc/passwd` synchronously, Seccomp will intercept and block the syscall on that thread.
2.  **Native Dependency Exploits (JNI/FFM):** If a native C/C++ library (like ImageMagick) has a buffer overflow that tries to spawn a shell or open a socket, it will be blocked. Native code issues syscalls directly on the current thread and cannot dynamically hop to JVM thread pools.

#### What Tier 2 CANNOT Stop: Untrusted Code (The `CompletableFuture` Bypass)
Tier 2 provides **zero protection** against an attacker capable of executing arbitrary Java logic (e.g., via Insecure Deserialization RCE, SpEL/OGNL injection, or malicious plugin uploads). 

Without the deprecated Java Security Manager (JSM), in-process isolation of untrusted Java code is fundamentally broken. If an attacker can execute Java logic inside a Tier 2 contained thread, they can execute a trivial 1-line bypass using standard Java concurrency APIs:

```java
// Bypasses Tier 2 thread-scoped containment instantly
CompletableFuture.runAsync(() -> Runtime.getRuntime().exec("curl ..."));
```

**The Mechanics:** Standard concurrency APIs (`CompletableFuture`, `ForkJoinPool`, `Thread.startVirtualThread`) delegate execution to pre-existing OS threads (like `ForkJoinPool.commonPool()`) or spawn new uncontained OS threads. Because these destination threads lack the Seccomp filter of the contained worker thread, the payload executes completely unrestricted.

#### The ACE Pivot
Even without standard concurrency APIs, if an attacker achieves native code execution (e.g., via a buffer overflow in a native JNI dependency or using raw Java FFM/`Unsafe` pointer manipulation) inside a sandboxed worker thread, they can compromise the rest of the JVM process by:
1. **Memory Corruption:** Corrupting the stacks or memory blocks of unrestricted parent or sister threads running in the same process space.
2. **Internal JVM Structure Hijacking:** Overwriting JVM function tables, class metadata, or garbage collector structures to trigger code execution on unrestricted helper threads.

**The Architectural Floor:** Therefore, thread-level seccomp must **never** be treated as a strong VM boundary (like a Podman container or gVisor sandbox). It is a highly effective, low-overhead shield that prevents contained libraries from making direct system calls, but process-wide `NO_EXEC` (Tier 1) remains mandatory to prevent the attacker from escalating an ACE or concurrency pivot.

### The Unconstrained Runtime as a Threat Vector & The JIT vs. AOT Security Thesis

Security professionals and systems architects view managed runtimes (like the JVM, V8, or Python) through a distinct threat model: **the runtime itself is a powerful execution engine that, if unconstrained, acts as a force multiplier for an attacker.**

#### 1. The Runtime-as-a-Service (RaaS) Threat
A standard dynamic runtime is designed to be highly flexible, which requires broad, unrestricted kernel capabilities. It can resolve hostnames, dynamically load code from arbitrary paths, allocate and execute memory, and spawn subprocesses. 
When an attacker achieves Remote Code Execution (RCE) via a dependency vulnerability, they do not need to inject complex binary shellcode. Instead, they simply instruct the unconstrained runtime to perform actions on their behalf using standard runtime APIs (e.g., calling `ProcessBuilder` or opening network sockets). Because the runtime has no OS-level boundaries, it executes these instructions with the full privileges of the host process. An unconstrained runtime is a highly capable tool built directly into the attacker's target environment.

#### 2. The Security Contrast: JIT vs. AOT Compilation
The choice of compilation model (Just-In-Time vs. Ahead-Of-Time) establishes the physical limits of the sandbox you can enforce:

*   **JIT (Just-In-Time) Constraints:** A JIT compiler compiles bytecode to native machine instructions at runtime. This forces the OS to run the JVM with a permissive sandbox. The JIT requires memory pages to be toggled between write and execute permissions (`mprotect` with `PROT_EXEC`) and requires unblocking dynamic timing, scheduling, and signal management system calls to handle deoptimization and compilation worker threads. Because these capabilities must remain unblocked, an attacker with native Arbitrary Code Execution (ACE) can leverage the exact same system calls to execute arbitrary shellcode. A JIT runtime is fundamentally dynamic and cannot be locked down to a static capability contract.
*   **AOT (Ahead-Of-Time) Sandboxing:** AOT compilation (such as GraalVM Native Image) compiles all code to a static binary prior to execution. Because the code is immutable at runtime, the application never needs to allocate or modify executable memory. We can enforce a strict **W^X (Write XOR Execute)** boundary by blocking `PROT_EXEC` entirely in Seccomp. Furthermore, because of the **Closed-World Assumption (CWA)**, all reachable code paths are resolved at compile-time, and dead code (including unused system calls or classes) is completely stripped from the final binary. This allows us to enforce highly restrictive, minimal contracts because the application's capabilities are completely bounded at compilation time, leaving no dynamic compilation "holes" in the sandbox.

---

#### The GraalVM Advantage: Beyond Startup Speed
While startup speed makes sub-process isolation (Tier 1) viable, GraalVM Native Image fundamentally hardens **Tier 2 (Thread-Scoped)** security in ways a standard JIT-based JVM cannot:

1.  **Neutralizing the "Trivial" Bypass:** The thread-hopping bypass is trivial in HotSpot because an attacker can dynamically inject code (via reflection, deserialization, or script engines) that calls `CompletableFuture.runAsync`. In a GraalVM Native Image, **dynamic code execution is physically impossible**. There is no JIT to compile new code and no classloader to load it. Unless the "malicious" thread-hopping logic was explicitly compiled into the binary, the attacker cannot execute it.
2.  **Eliminating the JIT Attack Surface:** A standard JVM requires `mmap(PROT_EXEC)` and `mprotect` to function, as the JIT must constantly write new machine code. This creates a permanent "hole" in the sandbox. A GraalVM binary is **AOT-compiled and static**. It can run under a policy that **completely blocks all executable memory modifications**, making binary shellcode injection or JIT-spraying attacks impossible.
3.  **Static Reachability as a Sandbox Backstop:** GraalVM's "Closed-World" analysis proves at compile-time exactly which methods are reachable. If your application doesn't use `ProcessBuilder` or `java.net.Socket`, those code paths are **deleted** from the final binary. This provides a mathematical guarantee that even a compromised thread cannot find the gadgets required to perform certain sensitive actions.
4.  **Hardware-Level CFI:** Because native images are static ELF binaries, they are compatible with hardware-level **Control Flow Integrity (CFI)** features like Intel CET or ARM BTI. These prevent ROP/JOP gadget chains from being executed, which is much harder to enforce in a dynamic JIT environment where code is constantly moving.

**Summary:** In a GraalVM environment, Tier 2 (Thread-Scoped) limits are significantly harder to bypass because the attacker lacks the dynamic tools (JIT, Reflection, Classloading) required to pivot or escalate privileges.

#### Tier 3: Isolates & WebAssembly (The Ultimate Sandbox)
Even with GraalVM AOT compilation hardening the enforcement, all threads within a single JVM process still share the same heap. If an attacker discovers a vulnerability that allows for Arbitrary Code Execution (ACE) via native memory corruption, they can theoretically pivot into the main application's memory space.

To achieve mathematically isolated, "Zero-Trust" execution of untrusted code without the overhead of multiple OS processes, the industry has shifted to two modern JVM architectures:

1.  **GraalVM Isolates (Heap Security):** Spawning a GraalVM Isolate creates a completely independent Java heap and Garbage Collector within the same OS process. An attacker compromising an Isolate is physically trapped in that specific heap and cannot see or corrupt the main application's memory. When combined with Mazewall (Seccomp), this creates a high-density, multi-tenant sandbox.
2.  **WebAssembly (Instruction-Level Security):** Embedding a Wasm runtime (like Endive/Chicory) provides a "shared-nothing, linear memory" architecture. The guest module lacks the CPU instructions to perform system calls (like opening a socket) and is physically restricted to a tiny byte array. The modern **Wasm Object Mapper** pattern leverages Wasm parsers (like `simdjson`) to safely parse untrusted data and uses Java 25 Panama FFM to map the results directly to Java Records, entirely eliminating the RCE risks of standard Java deserialization libraries (like Jackson).

---

## 2. The "Blast Radius" Architecture

We recommend a two-tiered defense-in-depth model:

1.  **Tier 1: Global Lockdown (`installOnProcess`):** Apply `Policy.NO_EXEC` process-wide at startup to permanently disable shell spawning. This prevents the "pivot" attack because no unrestricted threads remain.
2.  **Tier 2: Surgical Restrictions (`wrap`):** Apply stricter policies (like `Policy.NO_NETWORK` or `Policy.PURE_COMPUTE_UNSAFE`) to specific worker pools handling untrusted data (e.g., XML parsers, image processors). This stops **Data-Oriented Attacks** (SSRF, XXE, Path Traversal) where the attacker lacks the ACE required to pivot.

## 3. Advanced Syscall Evasion & Modern Attack Vectors

Blocking `execve` (spawning a shell) is a foundational defense, but sophisticated attackers use several techniques to bypass simple syscall filters.

### Fileless Malware (`memfd_create`)
Attackers can create anonymous, memory-backed file descriptors using `memfd_create`. They can then download an ELF binary into this "fileless" descriptor and execute it using `fexecve` or `execveat`. Because the binary never touches the disk, it bypasses traditional filesystem-based security scanners.
*   **Mitigation:** `mazewall` includes `MEMFD_CREATE` in its strict policies (e.g., `PURE_COMPUTE_UNSAFE`) and recommends blocking it wherever possible, as the standard JVM does not require it for normal operation.

### Modern Execution Variants (`execveat`)
Attackers may use `execveat` to execute programs relative to a directory file descriptor. This can sometimes bypass filters that only monitor the absolute path arguments of the classic `execve`.
*   **Mitigation:** `mazewall` explicitly blocks `EXECVEAT` in all `NO_EXEC` policies.

### Asynchronous Evasion (`io_uring`)
Modern Linux systems support `io_uring` for high-performance asynchronous I/O. Attackers increasingly abuse this subsystem to bypass seccomp filters. Because operations are submitted via a shared memory ring queue and executed by kernel worker threads (`io-wq`), a standard seccomp filter on the application thread is completely blind to the operations happening inside the ring.

**The Profiling Strategy:**
To build accurate policies for `io_uring` applications, `mazewall` requires one of the following profiling strategies:

1.  **Tier H (Hybrid Shortcut):** **Highly Recommended.** Developers temporarily disable `io_uring` during testing. The application falls back to standard I/O. The unprivileged Tier S profiler transparently captures all required paths. The developer then manually adds `.unblock(Syscall.IO_URING_SETUP)` to the generated policy for high-performance production enforcement.
2.  **Tier P (Privileged):** Uses root-privileged eBPF tracepoints (such as LSM hooks or `io_uring_submit_sqe` tracepoints) to observe `io_uring` operations transparently.
    *   *The `strace` Blind Spot:* Descendant tracing via `strace` (ptrace) is physically blind to `io_uring` path and socket operations, as submissions bypass thread-scoped system call registers via shared-memory SQEs and are executed asynchronously in kernel-space by `io-wq` worker threads.
    *   *Container Privilege Constraints:* Running eBPF (Tier P) requires global `CAP_BPF` and `CAP_SYS_ADMIN` capabilities in the host's **initial** user namespace. Therefore, unprivileged rootless containers (such as standard rootless Podman or Docker setups), even when run with `--privileged`, cannot load eBPF filters. Nested containers (Podman-in-Podman) are similarly blocked by the user namespace boundary of the rootless runtime on the host. eBPF profiling is only available on host-level root or rootful container deployments.
3.  **Tier A (Iterative):** Unprivileged fallback. Uses Landlock to block unauthorized VFS access, catches the resulting Java exceptions, and iteratively retries the workload.

**The Landlock Audit Constraint:**
Early design iterations suggested using **Landlock Audit** (Type 1423) for transparent profiling. However, Landlock does not possess a "permissive" or "log-only" mode; it only emits an audit log when it **denies** an action. Applying a restrictive Landlock policy for profiling causes fatal `EACCES` crashes in the JVM, breaking the transparency guarantee. Landlock Audit is therefore strictly a **detection and enforcement** tool, not a transparent profiling sensor.

**The Complementary Seccomp-Landlock Enforcement (Why Tier H Works):**
When a thread is restricted by both Seccomp and Landlock in production:
*   Seccomp whitelists `io_uring_setup`.
*   Standard seccomp cannot inspect the async queue contents.
*   **Crucially**, the kernel's async workers (`io-wq`) inherit the Landlock credentials of the submitting thread. Any unauthorized asynchronous operation is intercepted by Landlock at the VFS LSM hook layer and denied.
*   Because Tier H successfully captured all legitimate paths (via standard I/O fallback), Landlock securely authorizes those paths regardless of the underlying I/O mechanism.

**Fail-Closed Mandate:**
By default, the profiler will now silently ignore `io_uring` syscalls during unprivileged runs, trusting that developers are utilizing the Tier H workflow (disabling `io_uring` during tests) or Tier A to generate the required filesystem rules.

*   **Mitigation:** In production, `mazewall` explicitly blocks `io_uring_setup` in its strict policies. The standard JVM (currently) relies heavily on standard NIO/epoll and does not require `io_uring` for application-level worker threads.

### Binary Shellcode Injection
If an attacker cannot spawn a process, they will attempt to inject raw machine code (shellcode) into the JVM's memory. To run this code, they must mark the memory as executable using `mprotect` or `mmap`.
*   **Mitigation:** As detailed in the "Argument Inspection" section, `mazewall` monitors the `PROT_EXEC` bit. It allows the JVM to manage its memory but physically prevents any thread under a policy from making a memory region executable.

### ROP/JOP & Existing Memory
It is critical to understand that Seccomp monitors **system calls**, not internal CPU instruction flow. While `mazewall` effectively blocks the introduction of *new* executable memory (shellcode), it cannot prevent an attacker from reusing **existing** executable code already mapped in the JVM's memory (e.g., from the JVM itself or its dependencies).
By chaining together existing snippets of code (gadgets), an attacker can perform **Return-Oriented Programming (ROP)** or **Jump-Oriented Programming (JOP)** to execute arbitrary logic without ever calling `mprotect` or `mmap`.
*   **Mitigation:** Protection against ROP/JOP relies on complementary OS and compiler-level features such as **ASLR (Address Space Layout Randomization)**, **Stack Canaries**, and **Control Flow Integrity (CFI)**. Seccomp provides a hard barrier against environment-altering actions (spawn shell, network access), but it is not a complete solution for all memory corruption exploitation techniques.


---

## 4. The Ironic Security Shield: `PR_SET_NO_NEW_PRIVS` & Privilege Locking

To load a seccomp filter without root privileges (`CAP_SYS_ADMIN`), the Linux kernel enforces a strict requirement: the process must first enable the **`PR_SET_NO_NEW_PRIVS`** flag via a `prctl` call:

```kotlin
// Enforced by Linux before loading unprivileged seccomp filters:
LinuxNative.prctl(NativeConstants.PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)
```

This flag tells the kernel: *"From this moment on, this process and all of its descendants can never transition to a higher privilege level via `execve()`."*

While technically an operational constraint, it functions as an incredibly powerful **automatic security shield** that permanently neutralizes three major kernel-level escalation pathways:

### A. Setuid/Setgid Binary De-escalation
In Unix-like operating systems, certain administrative binaries have the `setuid` or `setgid` permission bits set (e.g., `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/passwd`, `/usr/bin/pkexec`). When executed, the kernel automatically elevates the calling process to run with the permissions of the file's owner (typically `root`).

Under `no_new_privs`, **the kernel completely ignores the setuid and setgid bits.** Any elevated binary executed by the JVM (or its children) will execute strictly with the unprivileged context of the JVM user.

This single mechanism provides absolute immunity to famous local privilege escalation exploits:
*   **CVE-2021-4034 (PwnKit):** A 12-year-old memory corruption vulnerability in PolicyKit's `/usr/bin/pkexec` that granted instant root access to local attackers. Under `no_new_privs`, the exploit executes without setuid elevation, rendering it completely inert.
*   **CVE-2021-3156 (Baron Samedit):** A heap-based buffer overflow in `sudo` allowing unprivileged local users to elevate to root. With `no_new_privs` active, the binary runs as the standard unprivileged JVM user, preventing any root transition regardless of the exploit outcome.

### B. File Capabilities Neutralization
Modern Linux distributions replace heavy, monolithic `setuid` root permissions with granular **File Capabilities** (e.g., `setcap cap_net_raw+ep /usr/bin/ping` to allow ping to open raw sockets without running as full root).

Under `no_new_privs`, the kernel completely neutralizes file capability transitions. Executed binaries can only use capabilities already possessed by the JVM process (which is typically empty).

### C. LSM Profile Transition Lock (SELinux / AppArmor)
Security modules like AppArmor and SELinux are often configured to transition a process to a different, more permissive profile when executing specific binaries. `no_new_privs` disables any profile transition that would result in a net gain of privileges, securing the process boundary.

### Operational Implications for the Application
Developers must understand the exact boundaries this locking mechanism establishes:

1.  **You CAN start the JVM as root:** If you run your application as `root` (e.g. `sudo java -jar app.jar`), it starts at the highest privilege level. When `mazewall` sets `no_new_privs`, it locks you at root. The app will run fine as root (subject to your seccomp filters), but it cannot go "above" root.
2.  **You CAN execute standard child processes:** Spawning standard helper scripts or binaries (e.g. calling `ls` or executing a python utility via `ProcessBuilder`) works perfectly. They inherit the exact unprivileged context and seccomp filters of the parent JVM.
3.  **You CANNOT escalate using sudo/su inside Java code:** If your JVM runs as a standard unprivileged user (e.g. `leanid`), calling `Runtime.getRuntime().exec("sudo systemctl restart nginx")` will **fail immediately**, even if the user is fully authorized in the host's `/etc/sudoers` file. The `sudo` binary will execute but will be denied root transition by the kernel.

### Security Analysis of Nested Seccomp in OCI Runtimes

OCI runtimes (such as `runc`, `containerd`, Podman, and Docker) restrict the `seccomp(2)` system call and specific `prctl(2)` options within their default profiles. This design decision is part of a defense-in-depth strategy aimed at reducing the host kernel's attack surface, preventing untrusted processes within containers from interacting with the kernel's BPF verifier or constructing arbitrary syscall filters.

However, the necessity of this OCI-level block can be evaluated against kernel-level invariants:
1.  **Enforced State Monotonicity:** The Linux kernel strictly requires the `PR_SET_NO_NEW_PRIVS` flag to be set before an unprivileged process can load a seccomp filter. Once active, the process and all descendants are permanently barred from privilege transitions (such as setuid, setgid, or file capability elevations).
2.  **Filter Monotonicity:** Seccomp filters can only restrict the current syscall capabilities; they cannot be removed, bypassed, or relaxed by subsequent nested filters.
3.  **Kernel Limits:** Modern kernels cap seccomp filter depth and BPF program complexity, preventing simple kernel memory exhaustion vectors.

Given these kernel-level invariants, blocking unprivileged seccomp filter installation inside containers does not prevent privilege escalation, since the kernel already enforces an immutable boundary. The primary risk re-introduced by whitelisting `seccomp` and `prctl(PR_SET_SECCOMP)` is a minor increase in BPF verifier exposure.

A potential architectural alternative for OCI specifications would be to permit nested filter installation by default whenever the container is configured with `allowPrivilegeEscalation: false` (which pre-emptively enforces `PR_SET_NO_NEW_PRIVS`). This would allow secure, application-level sandboxing (such as thread-scoped containment) to be deployed natively within standardized container environments without requiring custom profiles.

### Landlock Multi-Thread Synchronization (`TSYNC`) Hazards
Linux 7.0 (ABI 8) introduces `LANDLOCK_RESTRICT_SELF_TSYNC`, which allows applying a Landlock ruleset to all threads in a process atomically.

> [!WARNING]
> **Kernel availability:** Linux 7.0 and Landlock ABI 8 are cutting-edge. Most production servers and developer laptops run LTS kernels (5.15, 6.1, 6.6) that do not support this feature. Any code or policy using ABI 8 features must include a kernel version check and a clear fallback. Do not assume this is available in your environment.

While highly secure for production baselines, it introduces significant technical debt in JVM environments:

*   **Sibling Thread Transparency:** The JVM is a massive, multi-threaded engine. Sibling threads (like Gradle workers, background GC threads, or JIT threads) may need to perform operations (like managing `build/tmp`) that the sandboxed worker thread is restricted from.
*   **Test Suite Collisions:** Standard JVM test runners assume they have full control over the process memory space. Applying TSYNC inside a test will sandbox the entire runner process, leading to `AccessDeniedException` and `Permission Denied` crashes on completely unrelated sibling threads.
*   **Architecture Decision:** For these reasons, `mazewall` keeps TSYNC **disabled by default**. It is reserved for Tier 1 (Process-Wide) startup lockdowns where the entire JVM life-cycle is intended to be constrained.
*   **Process-Wide Filesystem Containment Fallback:** Since `LANDLOCK_RESTRICT_SELF_TSYNC` is unavailable on standard LTS kernels (< Linux 7.0), dynamic process-wide filesystem restrictions cannot be applied safely in-process at runtime. If process-wide filesystem sandboxing is required, operators must use an external launcher wrapper (such as **bubblewrap** or **nsjail**) to configure the Landlock ruleset on the process tree before invoking `execve` on the JVM.

---

## 5. The `prctl(2)` Double-Edged Sword: Requirements, Attack Surface, and Mitigations

The `prctl(2)` (Process Control) system call is central to the setup and execution of `mazewall` sandboxes. However, because of its incredibly broad capability set, it represents a unique security-critical attack surface.

### A. Why `prctl(2)` is Technically Required
Even if `mazewall` only used the modern `seccomp(2)` system call to load and stack BPF filters, the library still cannot function without `prctl(2)` due to Linux kernel invariants:
1. **`PR_SET_NO_NEW_PRIVS`:** To prevent privilege escalation attacks, the kernel strictly blocks unprivileged processes from loading seccomp filters or Landlock rules unless `PR_SET_NO_NEW_PRIVS` is set to `1` beforehand. This transition is accomplished solely via `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
2. **Seccomp State Verification:** To verify that the seccomp filters are properly loaded and stacked in mode 2, `mazewall` queries the kernel state at initialization using `prctl(PR_GET_SECCOMP, 0, 0, 0, 0)`.
3. **Legacy Kernel Stacking:** On pre-Linux 3.17 kernels where the modern `seccomp(2)` system call is absent, calling `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` remains the only mechanism to load BPF filters.

### B. The Attack Surface: Broad Process Control Operations
`prctl(2)` acts as a generic "Swiss Army knife" multiplexer for process and thread properties. If an attacker achieves native Arbitrary Code Execution (ACE) inside a sandboxed thread and `prctl(2)` is left completely allowed by the active policy, they can manipulate highly sensitive kernel parameters:
*   **Virtual Memory Layout (`PR_SET_MM`):** Allows modifying specific memory-mapping boundaries of the running process (e.g. text/data segment addresses).
*   **Tree & Process Interception (`PR_SET_CHILD_SUBREAPER`):** Allows the thread to declare itself a subreaper, altering how orphaned child processes are inherited.
*   **Resource & Behavior Management (`PR_SET_TSC` / `PR_SET_THP_DISABLE`):** Disables or enables CPU time-stamp counters or Transparent Huge Pages.

**Kernel Invariant Safety:** Note that `prctl` does *not* expose options to disable active seccomp filters or unset `no_new_privs` once enabled. The kernel enforces these transitions as strictly monotonic and irreversible.

### C. Mitigation Strategies in `mazewall`
To neutralize the attack surface of generic process control without breaking initialization or nesting, `mazewall` employs two primary mitigation strategies:

#### Strategy 1: Post-Installation System Call Blocking
In strict, non-stackable policies (such as `Policy.PURE_COMPUTE_UNSAFE`), dangerous `prctl` options are restricted via BPF argument inspection — **not** by adding `Syscall.PRCTL` to the block-list. Adding `Syscall.PRCTL` to the block-list would inadvertently block the whitelisted safe options (`PR_SET_NAME`, `PR_SET_NO_NEW_PRIVS`, `PR_GET_SECCOMP`) that the JVM needs, and could prevent filter installation itself.

The argument-inspection approach (§5.B below) is always active unless `allowUnsafePrctl()` is set on the policy. After the final BPF filter is installed, only the whitelisted `prctl` options remain accessible — all others return `EPERM`. `ioctl` is blocked via the block-list since the JVM does not need it in compute-only threads:
```kotlin
// Correct: ioctl via block-list, prctl via argument inspection (automatic)
val PURE_COMPUTE = Policy.builder()
    .block(Syscall.IOCTL)  // ioctl has no legitimate use in compute threads
    // prctl is NOT in the block-list — it is restricted by BPF argument inspection
    ...
```

#### Strategy 2: BPF Argument Inspection (Fine-Grained Whitelisting)
For policies where thread-level stack-nesting is still required (allowing worker threads to establish their own child sandboxes), standard `prctl` can be permitted but strictly constrained via BPF argument inspection.

Instead of blocking the system call outright, the seccomp-BPF filter inspects the first argument (`option`, which maps to `args[0]` in `seccomp_data`):
*   **Allow** if `args[0]` matches `PR_SET_NO_NEW_PRIVS` (`38`), `PR_GET_NO_NEW_PRIVS` (`39`), or `PR_GET_SECCOMP` (`21`).
*   **Block** with `EPERM` for any other option values (e.g., `PR_SET_MM` or `PR_SET_CHILD_SUBREAPER`).

### D. JVM Internal Usage of `prctl(2)` and Diagnostic Implications

It is critical to recognize that the HotSpot JVM itself invokes `prctl(2)` internally for non-critical runtime operations:
1. **Thread Renaming (`PR_SET_NAME` / `PR_GET_NAME`):** The JVM calls `prctl(PR_SET_NAME, ...)` inside `os::set_native_thread_name` whenever a Java thread is renamed (e.g., via `Thread.currentThread().setName(...)`) or during internal thread pool management.
2. **Transparent Huge Pages (`PR_SET_THP_DISABLE`):** GC threads may query or disable Transparent Huge Pages (THP) for specific allocation arenas.

#### Impact of Complete `prctl` Blocking
When using **Strategy 1** (completely blocking the `prctl` syscall after setup, such as in `Policy.PURE_COMPUTE_UNSAFE`):
* **No JVM Crashes:** Fortunately, the HotSpot JVM executes `prctl(PR_SET_NAME)` and other process control options defensively and silently discards the return value. A blocked `prctl` call will return `EPERM` safely without crashing the JVM.
* **Loss of OS-Level Diagnostics:** Any thread renaming performed *after* the sandbox is armed will fail silently. As a result, native OS-level tracing tools (`top -H`, `htop`, `/proc/self/task/<tid>/comm`) and Java diagnostic thread dumps (`jstack`) will continue to show the thread's *original* name from before sandboxing, which can hinder debugging.

#### Recommendation for Diagnostic-Critical Environments
If maintaining accurate OS-level thread names is a production requirement, developers should avoid Strategy 1. Instead, they should utilize **Strategy 2 (BPF Argument Inspection)** to whitelist `PR_SET_NAME` (15) and `PR_GET_NAME` (16) alongside `PR_SET_NO_NEW_PRIVS` (38), while keeping hazardous process-manipulation options (like `PR_SET_MM`) blocked.

---

## 6. Escaping Process-Level Containment

Even with process-wide `NO_EXEC`, an attacker with ACE can theoretically escape to the host OS if other security layers are missing:

*   **File System Pivot:** If the JVM user has write access to directories like `/etc/cron.d/`, an attacker can write a malicious script that the host OS will eventually execute with full privileges.
*   **Local Network Pivot:** If the JVM can access local unauthenticated APIs (e.g., the Podman socket at `/run/user/1000/podman/podman.sock`), it can command the host to spawn a new, unconstrained container.
*   **Persistence & Restart:** If the attacker can modify application binaries or configuration and then force a JVM crash, they may trick an orchestrator (Systemd/Kubernetes) into restarting the JVM without the seccomp filter enabled.

---

## 7. Defense-in-Depth Requirements

To make seccomp an effective barrier, the host environment **must** implement these complementary controls:

*   **Least Privilege:** Never run the JVM as `root`.
*   **Read-Only Root:** Use a read-only filesystem for the application and system directories to prevent script injection.
*   **Network Segmentation:** Prevent the JVM from reaching local administrative sockets or sensitive metadata services.

---

## 8. Technical Safeguards: Argument Inspection

`mazewall` uses BPF argument inspection to provide fine-grained control over critical syscalls, allowing the JVM to function while blocking malicious actions.

### Executable Memory Protection (`mmap` & `mprotect`)
We inspect the `prot` argument (the 3rd argument, `args[2]` in `seccomp_data`) of both `mmap` and `mprotect`. Standard mappings are allowed, but the library triggers an immediate `EPERM` if the `PROT_EXEC` (0x04) bit is set. This blocks binary shellcode execution while allowing the JIT and GC to function normally on other threads.
> **Note on 32-bit Truncation:** BPF jump/load instructions natively operate on 32-bit words. The filter loads the lower 32 bits of the `prot` argument to check for `PROT_EXEC`. Since the Linux kernel internally casts the `prot` flag to an `unsigned long` but only honors the standard lower bits defined in POSIX, this 32-bit truncation is secure and matches kernel behavior.

### JVM Stability Protection (`clone`)
We inspect the `flags` argument of `clone`. We allow `clone` only if it includes **both** `CLONE_THREAD` and `CLONE_VM` (indicating a new thread). Standard process forking (`fork`) and memory-sharing processes (`CLONE_VM` without `CLONE_THREAD`) are blocked. `clone3` is blocked with `ENOSYS` to force runtimes to fallback to the inspectable legacy `clone`.

---

## 9. HotSpot JVM Whitelist Risks (Safepoints & GC Deadlocks)

A critical technical risk of thread-scoped seccomp sandboxing in the JVM is **Safepoint and GC deadlock**.

JVM application threads are not fully isolated; they must periodically synchronize during safepoints (e.g. for dynamic compilation, deoptimization, thread dumps, or garbage collection). During these periods, application threads execute JVM runtime paths which invoke systems-level synchronization and scheduling operations:
* `futex`: Used extensively by the JVM for thread park/unpark and monitor synchronization.
* `sched_yield`: Called by threads during spin-lock contention.
* `rt_sigreturn`: Executed to return from signal handlers (HotSpot uses `SIGSEGV` for safepoint polling and `SIGUSR1` for thread suspension).
* `madvise` / `mprotect`: Invoked by garbage collection threads (e.g. ZGC or G1) to manage page tables and memory barriers.
* `gettid`: Used to identify native threads.

If a custom `mazewall` policy aggressively blocks any of these coordination syscalls, the next safepoint or GC sweep will cause a **catastrophic, permanent deadlock of the entire JVM**.

### JVM Platform Comparison: JIT vs. AOT
* **HotSpot JVM (JIT):** Requires a highly permissive system call floor. Because of dynamic compilation, runtime stack walking, and lazy classloading, application threads must leave synchronization, timing, and memory management syscalls unblocked to avoid deadlocks.
* **GraalVM Native Image (AOT):** Enables a much stricter security floor. With no JIT thread, no dynamic classloading, and a highly streamlined runtime footprint, a native executable can run safely under policies that block timing, scheduling, and signal return syscalls that standard HotSpot would require.

---

## 10. The Trapping Architecture: Native `SIGSYS` Signal Interception

The default mode of `mazewall` is to return `SECCOMP_RET_ERRNO` with `EPERM` (1) upon a policy violation. While robust and secure, detecting these violations in Java relies on parsing exception String messages (e.g. "Operation not permitted"), which is fragile and locale-sensitive.

The ultimate production roadmap for the library is to pivot to a native **`SECCOMP_RET_TRAP`** architecture:

```
[ Syscall Violation ]
       │
       ▼ (BPF returns SECCOMP_RET_TRAP)
[ Kernel sends SIGSYS ]
       │
       ▼ (Intercepted by Native Signal Handler)
[ C Signal Handler (FFM/sigaction) ]
  ├── 1. Capture ucontext_t (registers, rip, rax, si_syscall)
  ├── 2. Write structured, async-signal-safe audit log to stderr/disk
  ├── 3. Modify ucontext_t context:
  │      ├── Set rax = -EPERM (simulate syscall error return)
  │      └── Advance rip += 2 (skip the 2-byte syscall instruction)
  └── 4. Set thread-local violation flag
        │
        ▼ (Return from Signal Handler)
[ Java Task Execution Resumes ]
  ├── Syscall returns EPERM in Java
  └── Java raises IOException → mazewall reads thread-local flag → Throws deterministic exception
```

### Technical implementation requirements for `SIGSYS`:
1. **Async-Signal-Safe Interception:** The handler must run in a signal context. Calling Java code directly from the handler is unsafe and will crash the VM. The handler must be a small native C helper that records the violation details in a lock-free thread-local buffer or write to a pipe.
2. **Instruction Pointer Manipulation:** To prevent the thread from spinning in an infinite syscall-retry loop, the C handler must modify the CPU register state in `ucontext_t`: setting the return register (`rax` on x86_64, `x0` on aarch64) to `-EPERM` and incrementing the instruction pointer (`rip` / `pc`) past the 2-byte `syscall` instruction (`0x0f 0x05`).
3. **Graceful Failures:** This trapping architecture enables perfect stack traces, dynamic threat intelligence logging, and locale-independent exception mapping, but it must be written in a static native library companion to be 100% stable.

---

## 11. Known Limitations & Caveats

### Inherited File Descriptors
Seccomp filtering applies to *syscalls*, not *data structures*. If a thread inherits an open socket file descriptor (or receives one via `SCM_RIGHTS`) before the `NO_NETWORK` policy is applied, it can still call `recvmsg`, `recvfrom`, `write`, or `writev` on that existing descriptor. `NO_NETWORK` prevents the creation of *new* sockets (`socket`, `connect`, `bind`, `accept`), but does not block generic read/write syscalls which are essential for standard JVM I/O.

### Non-English Locales and Violation Exceptions
Java's core `IOException` classes do not expose the raw OS `errno` values. Under the current experimental `SECCOMP_RET_ERRNO` approach, `mazewall` detects containment violations by matching localized exception messages (e.g., "Operation not permitted" or "Permission denied") combined with specific JVM error codes (`error=1` or `error=13`).
On non-English locales, if the JVM translates these messages entirely, a blocked syscall will still be successfully intercepted by the kernel, but the application may throw a generic `IOException` rather than the specific `ContainmentViolationException`. The security guarantee remains intact; only the exception wrapping is affected.

### Platform Support
Seccomp-BPF and Landlock are Linux-only features. The library safely performs an OS-level check (`Platform.isSupported()`) before initializing native FFM bindings. On macOS or Windows, the library degrades gracefully based on the `IO_MAZEWALL_FALLBACK` policy (failing fast or logging a warning and running uncontained) without throwing `UnsatisfiedLinkError` or `WrongMethodTypeException`.

### Known Inconsistencies

#### Landlock Path Combination (Union vs. Intersection)
The `Policy.combine()` method currently uses a **union** of all allowed filesystem paths from the input policies. However, when the Linux kernel stacks multiple Landlock rulesets on a thread (e.g., via nested `ContainedExecutors` or stacking multiple policies), the resulting filesystem view is an **intersection**—the thread is restricted to paths that are allowed by *every* ruleset in the stack.

While `ContainedExecutors` prevents permission expansion during stacking (throwing `IllegalStateException` if a new layer attempts to add paths not allowed by the previous one), the behavior of `Policy.combine(p1, p2)` may produce a policy that appears broader than what would result from sequentially applying `p1` and then `p2`. Always verify that your combined policy matches your intended security contract at the kernel level.

---

## 12. Information Leaks (Side Channels)

Seccomp restricts **actions** (syscalls), but it does not provide **data isolation**.
*   A contained thread can still read any static variable or heap object it can reference.
*   It can use side channels (CPU timing, cache contention) to leak data to another thread.

---

## Summary: Security vs. Stability

| Policy         | Security Level | Stability Risk                    | Best Use Case                                       |
|:---------------|:---------------|:----------------------------------|:----------------------------------------------------|
| `NO_EXEC`      | High           | Low                               | Global process-wide lockdown (Elasticsearch model). |
| `NO_NETWORK`   | High           | Medium                            | Data parsing, report generation.                    |
| `PURE_COMPUTE_UNSAFE` | Critical       | High (HotSpot) / Medium (GraalVM) | Pure algorithmic tasks (image processing, crypto).  |

---

## 13. Kubernetes (K8s) Production Deployment Pattern

To run a containerized JVM using `mazewall` securely inside a Kubernetes cluster, you must avoid running pods with privileged security contexts (e.g. `privileged: true` or running unconfined).

Instead, configure Kubernetes to use the **Localhost custom seccomp profile** pattern.

### Step 1: Place the Custom Seccomp Profile on Kubernetes Nodes
Kubelet looks for custom seccomp profiles in its local filesystem at:
`/var/lib/kubelet/seccomp/`

You must place a copy of `podman-seccomp.json` into a subdirectory on each host node (for example, as `/var/lib/kubelet/seccomp/profiles/mazewall.json`).

*   **Automation tip:** Use a lightweight Kubernetes **DaemonSet** with a `hostPath` mount to distribute and keep this profile file synchronized across all nodes automatically. **The YAML below is illustrative only.** For production, use a GitOps-managed DaemonSet with image signing, or the [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator) which handles profile distribution with integrity verification. The `busybox` + raw `hostPath` pattern shown below has no integrity check and is not suitable for a hardened environment:
    ```yaml
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      name: mazewall-profile-initializer
      namespace: kube-system
    spec:
      selector:
        matchLabels:
          name: mazewall-profile-initializer
      template:
        metadata:
          labels:
            name: mazewall-profile-initializer
        spec:
          containers:
          - name: initializer
            image: busybox:1.36
            command: ["sh", "-c", "mkdir -p /var/lib/kubelet/seccomp/profiles && cp /config/mazewall.json /var/lib/kubelet/seccomp/profiles/mazewall.json && sleep 3600"]
            volumeMounts:
            - name: kubelet-seccomp
              mountPath: /var/lib/kubelet
            - name: config
              mountPath: /config
          volumes:
          - name: kubelet-seccomp
            hostPath:
              path: /var/lib/kubelet
          - name: config
            configMap:
              name: mazewall-profile-configmap
    ```

### Step 2: Apply the Seccomp Profile in the Pod Manifest
In your application’s Pod or Deployment manifest, specify the custom profile within the container or pod `securityContext`.

Additionally, you **must** configure `allowPrivilegeEscalation: false`. This ensures the container sets `PR_SET_NO_NEW_PRIVS`, which is a kernel requirement for unprivileged threads to load/stack their own nested seccomp filters.

> [!WARNING]
> **The `allowPrivilegeEscalation` (NoNewPrivs) Trap:**
> While `allowPrivilegeEscalation: false` is required for unprivileged seccomp stacking, it completely disables `setuid`/`setgid` bits and Linux File Capabilities during execution. Because this breaks legacy tools, vanilla OCI runtimes **do not** enable this by default (for backward compatibility). However, modern hardening frameworks (like K8s "Restricted" Pod Security Standards or OpenShift `restricted-v2` SCC) **do** enforce it.
>
> **What breaks when this is enabled?**
> 1. **`sudo`, `su`, `doas`:** Scripts attempting to elevate privileges using `sudo` from a non-root user will fail (`sudo: effective uid is not 0`).
> 2. **File Capabilities:** Non-root binaries that rely on `setcap` (e.g., a web server using `cap_net_bind_service=+ep` to bind port 80) will get `Permission denied`.
> 3. **Legacy Networking Tools:** `ping`, `traceroute`, or `tcpdump` run by non-root users will fail (`socket: Operation not permitted`) because they rely on `setuid` or file capabilities to open raw sockets.
>
> **How to audit your container image:**
> Before enabling `allowPrivilegeEscalation: false`, run these commands inside your image to identify potential landmines:
> *   `find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null` (Finds binaries that rely on `setuid`/`setgid`)
> *   `getcap -r / 2>/dev/null` (Finds binaries relying on file capabilities)
>
> If your application relies on executing any of the returned binaries, turning on this security context will crash those specific workflows.


```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-parser-app
spec:
  replicas: 3
  template:
    spec:
      securityContext:
        # 1. Instruct Kubelet to apply our custom profile from node's seccomp directory
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/mazewall.json
      containers:
      - name: mazewall-service
        image: my-registry.internal/parser-service:1.2.0
        securityContext:
          # 2. Prevent privilege escalation (sets NO_NEW_PRIVS in host kernel)
          allowPrivilegeEscalation: false
          # 3. Standard hardening (read-only root fs, non-root user)
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 10001
          capabilities:
            drop:
              - ALL
```

### Compatibility with K8s Pod Security Standards (PSA)
This custom configuration is **100% compliant with the strict "Restricted" Pod Security Standard** (PSA). The Restricted standard requires pods to enforce `seccompProfile.type: RuntimeDefault` or `Localhost` with a profile. Because we use a verified `Localhost` custom profile that drops standard system privileges while leaving stacking whitelisted, the deployment remains secure, compliant, and unprivileged.

---

## 14. Yama ptrace_scope & Out-of-Process Memory Profiling (Tier S)

To implement safe, precise system call profiling without triggering JVM safepoint deadlocks, `mazewall` implements the out-of-process BPF supervisor architecture utilizing the kernel's `SECCOMP_RET_USER_NOTIF` interface. This supervisor is spawned as a sibling daemon process and reads the memory of the sandboxed target JVM process via `process_vm_readv` to extract file paths and socket addresses.

However, modern Linux distributions and container environments harden inter-process access using the Yama Linux Security Module (LSM).

### The Yama ptrace_scope Trap
By default, Yama restricts which processes can perform ptrace operations (including `process_vm_readv` and `process_vm_writev`) by configuring `/proc/sys/kernel/yama/ptrace_scope` (typically set to `1` on modern systems):
- **ptrace_scope = 0 (Classic):** A process can ptrace/read memory of any other process running under the same UID.
- **ptrace_scope = 1 (Restricted):** A process may only attach to or read memory of descendant processes (e.g., its children or grandchildren), unless explicitly authorized.

Because our profiling daemon is spawned as a **child** process of the main JVM (making the main JVM the parent), standard Yama restrictions prevent the child daemon from calling `process_vm_readv` on its parent JVM process, resulting in `EPERM` (Operation not permitted).

### The Mitigation: PR_SET_PTRACER
To resolve this permission boundary without requiring elevated privileges or broad CAP_SYS_PTRACE capabilities, the parent JVM process must explicitly declare the child daemon as an authorized tracer.

Immediately upon spawning the daemon process, `mazewall` invokes `prctl` with the `PR_SET_PTRACER` option:

```kotlin
// Set the daemon process as our allowed ptrace tracer under Yama
val daemonPid = daemonProcess.pid()
LinuxNative.prctl(0x59616d61, daemonPid, 0, 0, 0)
```

This instructs the Yama LSM to allow the specified daemon process to read the parent's memory, enabling high-performance, out-of-process argument resolution for all thread-scoped sandboxed operations.

### Grandchild Process Boundaries
Note that grandchild processes (e.g. processes spawned by `ProcessBuilder` within a sandboxed thread pool, like `echo` or helper scripts) do not inherit this ptrace tracer permission, and cannot easily invoke `prctl` to declare the daemon as a tracer. As a result, the daemon's `process_vm_readv` calls on grandchild processes will still return `EPERM` under `ptrace_scope = 1`.

The `mazewall` supervisor handles this constraint gracefully: if a `process_vm_readv` call returns `EPERM` on a grandchild process (like during `execve`), the supervisor intercepts the system call, logs the raw address registers, and continues executing it natively without crashing or blocking the worker.

