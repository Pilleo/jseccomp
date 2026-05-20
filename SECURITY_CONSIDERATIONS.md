# Security Considerations & Technical Risks

Using seccomp-bpf within the JVM introduces specific architectural risks. This document outlines high-level security properties and implementation trade-offs.

---

## 1. Thread-Level vs. Process-Level Isolation

Seccomp filters on Linux can be applied to a single thread or the entire process. `jseccomp` supports both via `installOnCurrentThread` (Tier 2) and `installOnProcess` (Tier 1).

### The "Elasticsearch Approach" (Process-Wide)
For years, industry leaders like **Elasticsearch** have successfully used a minimal, process-wide seccomp filter to prevent Remote Code Execution (RCE). By blocking a small set of syscalls (`fork`, `vfork`, `execve`, `execveat`) globally at startup, they ensure that even if a vulnerability like Log4Shell is exploited, the attacker cannot spawn a shell.

**Recommendation:** Use `ContainedExecutors.installOnProcess(Policy.NO_EXEC)` as your foundational baseline defense.

### Thread-Level Mitigation & The "ACE Shared-Memory Pivot" Threat Model
Thread-level containment (e.g., wrapping an `ExecutorService` with restrictive policies like `PURE_COMPUTE`) is a powerful tool to minimize the blast radius of un-trusted library execution. However, **thread-scoped seccomp is not an absolute security boundary against an attacker who achieves Arbitrary Code Execution (ACE) on that thread.**

Because the JVM runs within a single Linux process, **all JVM threads share the same physical address space, virtual memory maps, and heap.** 

If an attacker achieves native code execution (e.g., via a buffer overflow in a native JNI dependency or using raw Java FFM/`Unsafe` pointer manipulation) inside a sandboxed worker thread, they cannot make blocked system calls *on that thread*. However, they can compromise the rest of the JVM process by:
1. **Memory Corruption:** Corrupting the stacks or memory blocks of unrestricted parent or sister threads running in the same process space.
2. **Dynamic Thread Injection / Task Poisoning:** Accessing the JVM's internal structures (like the `ForkJoinPool.commonPool()` queue or JVM scheduler queues) directly in memory using pointer arithmetic, and injecting malicious tasks to be executed by unrestricted threads.
3. **Internal JVM Structure Hijacking:** Overwriting JVM function tables, class metadata, or garbage collector structures to trigger code execution on unrestricted helper threads.

**The Architectural Floor:** Therefore, thread-level seccomp must **never** be treated as a strong VM boundary (like a Docker container or gVisor sandbox). It is a highly effective, low-overhead shield that prevents contained libraries from making direct system calls (e.g. initiating SSRF or spawning shells), but process-wide `NO_EXEC` (Tier 1) remains mandatory to prevent the attacker from escalating an ACE pivot.

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

## 4. The Ironic Security Shield: `PR_SET_NO_NEW_PRIVS` & Privilege Locking

To load a seccomp filter without root privileges (`CAP_SYS_ADMIN`), the Linux kernel enforces a strict requirement: the process must first enable the **`PR_SET_NO_NEW_PRIVS`** flag via a `prctl` call:

```kotlin
// Enforced by Linux before loading unprivileged seccomp filters:
LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)
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

1.  **You CAN start the JVM as root:** If you run your application as `root` (e.g. `sudo java -jar app.jar`), it starts at the highest privilege level. When `jseccomp` sets `no_new_privs`, it locks you at root. The app will run fine as root (subject to your seccomp filters), but it cannot go "above" root.
2.  **You CAN execute standard child processes:** Spawning standard helper scripts or binaries (e.g. calling `ls` or executing a python utility via `ProcessBuilder`) works perfectly. They inherit the exact unprivileged context and seccomp filters of the parent JVM.
3.  **You CANNOT escalate using sudo/su inside Java code:** If your JVM runs as a standard unprivileged user (e.g. `leanid`), calling `Runtime.getRuntime().exec("sudo systemctl restart nginx")` will **fail immediately**, even if the user is fully authorized in the host's `/etc/sudoers` file. The `sudo` binary will execute but will be denied root transition by the kernel.

### Security Analysis of Nested Seccomp in OCI Runtimes

OCI runtimes (such as `runc`, `containerd`, and Docker) restrict the `seccomp(2)` system call and specific `prctl(2)` options within their default profiles. This design decision is part of a defense-in-depth strategy aimed at reducing the host kernel's attack surface, preventing untrusted processes within containers from interacting with the kernel's BPF verifier or constructing arbitrary syscall filters.

However, the necessity of this OCI-level block can be evaluated against kernel-level invariants:
1.  **Enforced State Monotonicity:** The Linux kernel strictly requires the `PR_SET_NO_NEW_PRIVS` flag to be set before an unprivileged process can load a seccomp filter. Once active, the process and all descendants are permanently barred from privilege transitions (such as setuid, setgid, or file capability elevations).
2.  **Filter Monotonicity:** Seccomp filters can only restrict the current syscall capabilities; they cannot be removed, bypassed, or relaxed by subsequent nested filters.
3.  **Kernel Limits:** Modern kernels cap seccomp filter depth and BPF program complexity, preventing simple kernel memory exhaustion vectors.

Given these kernel-level invariants, blocking unprivileged seccomp filter installation inside containers does not prevent privilege escalation, since the kernel already enforces an immutable boundary. The primary risk re-introduced by whitelisting `seccomp` and `prctl(PR_SET_SECCOMP)` is a minor increase in BPF verifier exposure. 

A potential architectural alternative for OCI specifications would be to permit nested filter installation by default whenever the container is configured with `allowPrivilegeEscalation: false` (which pre-emptively enforces `PR_SET_NO_NEW_PRIVS`). This would allow secure, application-level sandboxing (such as thread-scoped containment) to be deployed natively within standardized container environments without requiring custom profiles.

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

`jseccomp` uses BPF argument inspection to provide fine-grained control over critical syscalls, allowing the JVM to function while blocking malicious actions.

### Executable Memory Protection (`mmap` & `mprotect`)
We inspect the `prot` argument (the 3rd argument, `args[2]` in `seccomp_data`) of both `mmap` and `mprotect`. Standard mappings are allowed, but the library triggers an immediate `EPERM` if the `PROT_EXEC` (0x04) bit is set. This blocks binary shellcode execution while allowing the JIT and GC to function normally on other threads.
> **Note on 32-bit Truncation:** BPF jump/load instructions natively operate on 32-bit words. The filter loads the lower 32 bits of the `prot` argument to check for `PROT_EXEC`. Since the Linux kernel internally casts the `prot` flag to an `unsigned long` but only honors the standard lower bits defined in POSIX, this 32-bit truncation is secure and matches kernel behavior.

### JVM Stability Protection (`clone`)
We inspect the `flags` argument of `clone`. We allow `clone` only if it includes **both** `CLONE_THREAD` and `CLONE_VM` (indicating a new thread). Standard process forking (`fork`) and memory-sharing processes (`CLONE_VM` without `CLONE_THREAD`) are blocked. `clone3` is blocked with `ENOSYS` to force runtimes to fallback to the inspectable legacy `clone`.

---

## 8. HotSpot JVM Whitelist Risks (Safepoints & GC Deadlocks)

A critical technical risk of thread-scoped seccomp sandboxing in the JVM is **Safepoint and GC deadlock**. 

JVM application threads are not fully isolated; they must periodically synchronize during safepoints (e.g. for dynamic compilation, deoptimization, thread dumps, or garbage collection). During these periods, application threads execute JVM runtime paths which invoke systems-level synchronization and scheduling operations:
* `futex`: Used extensively by the JVM for thread park/unpark and monitor synchronization.
* `sched_yield`: Called by threads during spin-lock contention.
* `rt_sigreturn`: Executed to return from signal handlers (HotSpot uses `SIGSEGV` for safepoint polling and `SIGUSR1` for thread suspension).
* `madvise` / `mprotect`: Invoked by garbage collection threads (e.g. ZGC or G1) to manage page tables and memory barriers.
* `gettid`: Used to identify native threads.

If a custom `jseccomp` policy aggressively blocks any of these coordination syscalls, the next safepoint or GC sweep will cause a **catastrophic, permanent deadlock of the entire JVM**.

### JVM Platform Comparison: JIT vs. AOT
* **HotSpot JVM (JIT):** Requires a highly permissive system call floor. Because of dynamic compilation, runtime stack walking, and lazy classloading, application threads must leave synchronization, timing, and memory management syscalls unblocked to avoid deadlocks.
* **GraalVM Native Image (AOT):** Enables a much stricter security floor. With no JIT thread, no dynamic classloading, and a highly streamlined runtime footprint, a native executable can run safely under policies that block timing, scheduling, and signal return syscalls that standard HotSpot would require.

---

## 9. The Trapping Architecture: Native `SIGSYS` Signal Interception

The default mode of `jseccomp` is to return `SECCOMP_RET_ERRNO` with `EPERM` (1) upon a policy violation. While robust and secure, detecting these violations in Java relies on parsing exception String messages (e.g. "Operation not permitted"), which is fragile and locale-sensitive.

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
 └── Java raises IOException → jseccomp reads thread-local flag → Throws deterministic exception
```

### Technical implementation requirements for `SIGSYS`:
1. **Async-Signal-Safe Interception:** The handler must run in a signal context. Calling Java code directly from the handler is unsafe and will crash the VM. The handler must be a small native C helper that records the violation details in a lock-free thread-local buffer or write to a pipe.
2. **Instruction Pointer Manipulation:** To prevent the thread from spinning in an infinite syscall-retry loop, the C handler must modify the CPU register state in `ucontext_t`: setting the return register (`rax` on x86_64, `x0` on aarch64) to `-EPERM` and incrementing the instruction pointer (`rip` / `pc`) past the 2-byte `syscall` instruction (`0x0f 0x05`).
3. **Graceful Failures:** This trapping architecture enables perfect stack traces, dynamic threat intelligence logging, and locale-independent exception mapping, but it must be written in a static native library companion to be 100% stable.

---

## 10. Known Limitations & Caveats

### Inherited File Descriptors
Seccomp filtering applies to *syscalls*, not *data structures*. If a thread inherits an open socket file descriptor (or receives one via `SCM_RIGHTS`) before the `NO_NETWORK` policy is applied, it can still call `recvmsg`, `recvfrom`, `write`, or `writev` on that existing descriptor. `NO_NETWORK` prevents the creation of *new* sockets (`socket`, `connect`, `bind`, `accept`), but does not block generic read/write syscalls which are essential for standard JVM I/O.

### Non-English Locales and Violation Exceptions
Java's core `IOException` classes do not expose the raw OS `errno` values. Under the current experimental `SECCOMP_RET_ERRNO` approach, `jseccomp` detects containment violations by matching localized exception messages (e.g., "Operation not permitted" or "Permission denied") combined with specific JVM error codes (`error=1` or `error=13`).
On non-English locales, if the JVM translates these messages entirely, a blocked syscall will still be successfully intercepted by the kernel, but the application may throw a generic `IOException` rather than the specific `ContainmentViolationException`. The security guarantee remains intact; only the exception wrapping is affected.

### Platform Support
Seccomp-BPF and Landlock are Linux-only features. The library safely performs an OS-level check (`Platform.isSupported()`) before initializing native FFM bindings. On macOS or Windows, the library degrades gracefully based on the `IO_CONTAINED_FALLBACK` policy (failing fast or logging a warning and running uncontained) without throwing `UnsatisfiedLinkError` or `WrongMethodTypeException`.

---

## 11. Information Leaks (Side Channels)

Seccomp restricts **actions** (syscalls), but it does not provide **data isolation**. 
*   A contained thread can still read any static variable or heap object it can reference.
*   It can use side channels (CPU timing, cache contention) to leak data to another thread.

---

## Summary: Security vs. Stability

| Policy | Security Level | Stability Risk | Best Use Case |
| :--- | :--- | :--- | :--- |
| `NO_EXEC` | High | Low | Global process-wide lockdown (Elasticsearch model). |
| `NO_NETWORK` | High | Medium | Data parsing, report generation. |
| `PURE_COMPUTE`| Critical | High (HotSpot) / Medium (GraalVM) | Pure algorithmic tasks (image processing, crypto). |

---

## 12. Kubernetes (K8s) Production Deployment Pattern

To run a containerized JVM using `jseccomp` securely inside a Kubernetes cluster, you must avoid running pods with privileged security contexts (e.g. `privileged: true` or running unconfined). 

Instead, configure Kubernetes to use the **Localhost custom seccomp profile** pattern.

### Step 1: Place the Custom Seccomp Profile on Kubernetes Nodes
Kubelet looks for custom seccomp profiles in its local filesystem at:
`/var/lib/kubelet/seccomp/`

You must place a copy of `docker-seccomp.json` into a subdirectory on each host node (for example, as `/var/lib/kubelet/seccomp/profiles/jseccomp.json`).

*   **Automation tip:** Use a lightweight Kubernetes **DaemonSet** with a `hostPath` mount to distribute and keep this profile file synchronized across all nodes automatically:
    ```yaml
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      name: jseccomp-profile-initializer
      namespace: kube-system
    spec:
      selector:
        matchLabels:
          name: jseccomp-profile-initializer
      template:
        metadata:
          labels:
            name: jseccomp-profile-initializer
        spec:
          containers:
          - name: initializer
            image: busybox:1.36
            command: ["sh", "-c", "mkdir -p /var/lib/kubelet/seccomp/profiles && cp /config/jseccomp.json /var/lib/kubelet/seccomp/profiles/jseccomp.json && sleep 3600"]
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
              name: jseccomp-profile-configmap
    ```

### Step 2: Apply the Seccomp Profile in the Pod Manifest
In your application’s Pod or Deployment manifest, specify the custom profile within the container or pod `securityContext`. 

Additionally, you **must** configure `allowPrivilegeEscalation: false`. This ensures the container sets `PR_SET_NO_NEW_PRIVS`, which is a kernel requirement for unprivileged threads to load/stack their own nested seccomp filters.

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
          localhostProfile: profiles/jseccomp.json
      containers:
      - name: jseccomp-service
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
