# Securing the JVM at the Kernel Level: Thread-Scoped Syscall Containment
 
In [Part 1](#), we explored the concept of the **Bill of Behavior (BoB)**—a shift from broad container boundaries to granular behavioral contracts. We discussed how eBPF provides the visibility to build these contracts and how modern evasion techniques like fileless malware necessitate surgical enforcement.
 
Now, we are going to get practical. We’re going to look at one of the most dynamic, complex, and "over-privileged" runtimes in the modern data center: the **Java Virtual Machine (JVM)**.
 
## The Global Sandbox Fallacy
 
Most JVM security today relies on a global sandbox. We apply a Seccomp profile or an AppArmor policy to the entire Linux process (the Pod). 
 
The problem? A typical Spring Boot application is a monolith of behavior. The main process needs to open network sockets for the API, read configuration files from the disk, and map memory for the JIT compiler. Because the *process* needs these capabilities, the *entire process* is granted them.
 
If an attacker triggers a Remote Code Execution (RCE) vulnerability (like Log4Shell) inside a worker thread, they inherit the full privileges of the JVM. They don’t need to break out of the container; they can simply "live off the land" using the network and file access the JVM is already allowed to have.
 
## The Solution: Tiered Enforcement
 
The Linux kernel provides a powerful but underutilized capability: **Seccomp filters can be applied per-thread.**
 
This is the core philosophy behind `jseccomp`. We advocate for a tiered "Defense-in-Depth" model that combines process-wide safety with surgical thread-level containment:
 
1.  **Tier 1: Global Process Lockdown:** At application startup, we apply a minimal `Policy.NO_EXEC` filter to the entire JVM process. This permanently disables the ability to spawn a shell (`execve`), providing a massive security baseline with almost zero stability risk.
2.  **Tier 2: Surgical Thread Containment:** For specific worker pools handling untrusted data (like a JSON parser or an image processor), we apply much stricter policies—blocking network access (`Policy.NO_NETWORK`) or even all file operations (`Policy.PURE_COMPUTE`).
 
By isolating these high-risk tasks into "Contained Executors," the worker thread enters a restricted state that it can never leave, while the main JVM threads (GC, JIT, API listeners) remain unconstrained.
 
### Stopping the "Shellcode" without Breaking the JIT
 
The biggest challenge with kernel-level JVM security is the JIT (Just-In-Time) compiler. The JVM must frequently call `mmap` or `mprotect` to mark memory as executable (`PROT_EXEC`) so it can run optimized code. 
 
A blunt Seccomp filter that blocks `PROT_EXEC` will crash the JVM instantly.
 
`jseccomp` solves this using **BPF argument inspection**. When a thread calls `mmap`, the kernel-level BPF filter doesn't just look at the syscall name; it inspects the memory protection flags. 
 
*   **Standard Mapping:** Allowed. The worker thread can allocate memory for data.
*   **Executable Mapping (`PROT_EXEC`):** Blocked. If an attacker tries to inject binary shellcode and mark it as executable, the kernel returns `EPERM`.
 
Because this filter is applied only to the worker thread, the background JIT threads on the same JVM continue to function perfectly. We have surgically neutralized shellcode execution without affecting application performance.

## Neutralizing Fileless Malware
 
In Part 1, we mentioned **fileless malware** using `memfd_create`. By creating an anonymous file in RAM and executing it via `execveat`, attackers bypass all disk-based security.
 
In a `jseccomp` environment, these syscalls are blocked by default in restricted policies. Even if an attacker gains code execution, the kernel physically prevents them from creating these memory descriptors or spawning new processes. They are trapped inside a purely computational sandbox.

## Seccomp vs. BPF-LSM: The Privilege Trade-off

If you are following the bleeding edge of Linux kernel security, you might be asking: *Why use Seccomp instead of the newer BPF-LSM (Linux Security Modules)?* 

BPF-LSM is undeniably more powerful. While Seccomp only sees raw memory addresses and is vulnerable to Time-of-Check to Time-of-Use (TOCTOU) attacks when inspecting file paths or IP addresses, BPF-LSM hooks deep into the kernel *after* these objects are safely resolved. A BPF-LSM program can inspect the exact canonical file path (`/etc/passwd`) or destination IP and enforce surgical policies.

However, there is a massive architectural trade-off: **Privilege**.

To load a BPF-LSM program into the kernel, the process requires high privileges (like `CAP_BPF` or `CAP_MAC_ADMIN`). A standard, secure JVM should never run with these capabilities. Therefore, to use BPF-LSM, you must deploy a highly privileged node agent (like a Kubernetes DaemonSet) to manage the policies on behalf of the application.

Seccomp, on the other hand, allows an entirely unprivileged application to *self-restrict*. As long as the `NoNewPrivileges` flag is set, a worker thread can unilaterally strip away its own capabilities. `jseccomp` requires zero external agents, daemonsets, or cluster-level privileges—it is pure, developer-driven "shift left" security.

## Internal Micro-segmentation: The Scalpel vs. The Shield

A common question is: *If I use a cluster-wide tool like Kubescape with eBPF, do I still need thread-level containment?*

The answer is **Defense-in-Depth**. Think of cluster-wide security as the "shield" protecting the perimeter of your building. It’s essential, but it’s blunt. `jseccomp` is the "scalpel" used for internal micro-segmentation. 

External tools see your container as a black box; they don't know when a specific high-risk worker thread is processing untrusted data. `jseccomp` allows you to lock the individual safes inside the rooms of your building, applying restrictions based on internal application logic that an external orchestrator simply cannot see.

## Beyond Java: The Portability Trade-off
While the principles of syscall containment are universal, the implementation strategy—process-level vs. thread-level—depends heavily on your language's runtime.

### Process-Level: Universally Portable
Process-level enforcement (`installOnProcess`) works in virtually any language—Go, Rust, Python, Node.js, or C++. Because the filter applies to the entire OS process, it doesn't matter how the language manages its internal concurrency. If you block `execve` for the process, no part of that application can ever spawn a shell. This remains the strongest baseline for any backend service.

### Thread-Level: The Scheduler Challenge
Surgical, thread-scoped containment is much more selective. It relies on a stable 1:1 mapping between your application's concurrency primitive and the underlying OS thread.

*   **Logical Choices (Rust, C++, Python, Node.js):** These environments use native OS threads or explicit worker processes. You can "poison" a specific worker thread with a restrictive seccomp filter and be confident that only the untrusted task will be affected.
*   **The Go Problem (M:N Scheduling):** Go is a notable example where thread-scoped enforcement is currently impractical. Because Go uses an M:N scheduler, thousands of **goroutines** are multiplexed onto a small pool of OS threads. If you apply a seccomp filter to an OS thread to secure one specific goroutine, the Go runtime might context-switch a completely different, trusted goroutine onto that "poisoned" thread. The trusted goroutine would then instantly crash the moment it tries to perform a valid syscall that the previous goroutine was forbidden from using. 

Without major refactoring to the Go runtime (or using performance-killing workarounds like `runtime.LockOSThread()`), surgical thread-level containment remains a specialized tool for runtimes with predictable thread affinity, like the JVM or Rust.

## See It in Action
 
The `jseccomp` library provides a simple, idiomatic wrapper around standard Java `Executors`. 
 
```kotlin
// Wrap a standard thread pool with a "No Execution" policy
val safeExecutor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    Policy.NO_EXEC
)

// This task can perform computation, but if it tries to spawn 
// a shell or a reverse shell, the kernel will kill the action.
safeExecutor.submit {
    // Malicious payload here...
    Runtime.getRuntime().exec("/bin/sh") // Throws ContainmentViolationException
}
```

### Try It Locally
 
You can reproduce this containment yourself. The repository includes a demonstration of a Log4Shell exploit being neutralized by `jseccomp` at the kernel level.
 
1.  **Clone & Run:**
    ```bash
    git clone https://github.com/leanid/jseccomp.git
    cd jseccomp
    docker compose up -d
    docker compose exec jseccomp ./gradlew test
    ```
*(Note: The container runs with `seccomp=unconfined` so our nested Java filters can be applied).*

When you explore the `demo` module, you'll see the kernel physically rejecting the attack. The JVM doesn't just fail to spawn the shell; the OS throws a hard `EPERM` (Operation not permitted), surfaced cleanly in Java:
```text
java.util.concurrent.ExecutionException: io.contained.ContainmentViolationException: 
Thread attempted a prohibited system call (EPERM).
```

## Conclusion
 
The "Bill of Behavior" isn't just a conceptual ideal; it is a technically feasible engineering strategy. By moving from process-level boundaries to thread-scoped kernel enforcement, we can build dynamic applications that are secure by design.
 
Syscalls are the ultimate source of truth. By controlling them at the thread level, we ensure that even when our code is compromised, our system remains intact.
