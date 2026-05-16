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

## The Concept of Scopes: When is a Behavior Expected?

A Bill of Behavior (BoB) isn't just a flat list of syscalls; to be effective, it must be context-aware. This is where the concept of **Scopes** becomes critical. We can categorize these into two main groups: those that are practically achievable today, and those that remain aspirational.

### 1. Lifecycle Scopes (The Pragmatic Path)
The most realistic way to implement Scopes is by aligning with the application's natural lifecycle. This approach is currently being implemented in **Kubescape**:

*   **Startup Scope:** Broad permissions needed to load configurations, establish connection pools, and initialize the JIT. This scope ends once the application passes its first health check.
*   **Runtime Scope:** A much narrower "steady-state" set of permissions. This is where the majority of an application's life is spent.
*   **Shutdown Scope:** Permissions required for graceful termination, such as flushing logs or closing connections.

By using Kubernetes health checks as a trigger, the runtime engine can automatically "rotate" the active security contract. This provides a clear, automated enforcement boundary that matches how developers already think about their apps.

### 2. Granular Scopes (The Experimental Frontier)
Beyond lifecycle phases, we can theoretically define scopes at a much deeper level. While these make for powerful Proofs of Concept (PoC), turning them into stable, production-ready technology faces significant architectural challenges:

*   **Process/Thread Scopes:** Restricting behavior based on which specific OS thread is executing (the core of the `jseccomp` experiment).
*   **Module/Library Scopes:** Restricting behavior based on which JAR or package is currently on the stack.
*   **Stacktrace Scopes:** Using the calling context to decide if a syscall is valid (e.g., "Allow `socket()` only if called via the AWS SDK").

While these granular scopes represent the "dream" of behavioral security, they often introduce high performance overhead or require deep integration with the language runtime. For now, Lifecycle Scopes remain the most viable path for widespread adoption.

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
 
**Prerequisites:**
*   Linux (x86_64 or aarch64)
*   JDK 22+ (Uses the new Foreign Function & Memory API)
*   Docker or Podman
 
**Steps:**
1.  **Clone the Repo:**
    ```bash
    git clone https://github.com/leanid/jseccomp.git
    cd jseccomp
    ```
2.  **Run the Tests:**
    The project uses a custom Seccomp filter, so the container must run with `unconfined` security options to allow the nested filters to be installed.
    ```bash
    docker compose up -d
    docker compose exec jseccomp ./gradlew test
    ```
3.  **Explore the Demo:**
    Look at the `demo` module to see how a vulnerable logging setup is protected. The tests in `ExploitDemonstrationTest` and `ProtectionDemonstrationTest` show exactly how the kernel intervenes.

## Conclusion
 
The "Bill of Behavior" isn't just a conceptual ideal; it is a technically feasible engineering strategy. By moving from process-level boundaries to thread-scoped kernel enforcement, we can build dynamic applications that are secure by design.
 
Syscalls are the ultimate source of truth. By controlling them at the thread level, we ensure that even when our code is compromised, our system remains intact.
