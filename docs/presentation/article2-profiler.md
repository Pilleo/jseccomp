# Dynamic Policy Profiling in Mazewall

> **Series overview:** This is Part 2 of a 5-part series on behavioral security for cloud-native applications. **What this part adds:** the introduction of **mazewall**—a newly developed, experimental Proof-of-Concept JVM sandboxing library written in preparation of articles to make them more practical—and a developer-focused guide to profile your code.

---

In Part 1, we established that traditional container-level boundaries leave an open field for attackers once they achieve Arbitrary Code Execution (ACE) inside an application. We argued that the future of cloud-native security belongs to **contracts**—specifically, the **Software Bill of Behavior (SBoB)**—where the kernel restricts threads to a narrow, pre-declared set of capabilities.

But this raises an immediate, practical engineering challenge: **how do you build the contract?**

Manually cataloging every system call and filesystem path an application uses introduces significant engineering friction. Furthermore, predicting required system calls in a complex runtime like the JVM is highly error-prone; under-specifying a policy by blocking a critical runtime operation can result in fatal JVM deadlocks.

**mazewall** is a JVM library designed to enforce thread-scoped Seccomp-BPF and Landlock boundaries. To mitigate the misconfiguration risks inherent in manual rule declaration, mazewall relies on a **Discovery before Enforcement** model: instead of speculating on required capabilities, the library profiles the active code block under test to capture its exact system requirements.

---

## The Landscape: Local Tracing vs. Cluster-Wide Observation

Before we look at how mazewall discovers a policy, it is worth comparing this approach to existing behavioral security tools.

In the cloud-native ecosystem, tools like **Kubescape** have pioneered dynamic runtime profiling. Using eBPF (Extended Berkeley Packet Filters) at the host kernel level, Kubescape observes a running container in a staging cluster, builds a baseline of its system calls, and detects anomalies. This provides a strong platform-level security control.

However, cluster-wide dynamic profiling has a few critical limitations for application developers:
1. **Lack of Application Context:** A cluster-level eBPF tracer sees the JVM process as a single black box. It cannot easily distinguish between a high-privilege administrative thread, a low-privilege JSON parser thread, or the JIT compiler thread. It profiles the *average process*, not individual logical tasks.
2. **Slow Developer Feedback Loop:** Running a container in a staging cluster, generating traffic, compiling eBPF logs, and generating a security policy is a heavy, slow process. It cannot easily be integrated into a developer's local inner loop or CI pipeline.

**mazewall** takes a different approach: **developer-scoped, thread-level profiling**. It offers three architectural tiers based on the required transparency and available environment privileges:

1.  **Tier P (Privileged):** Uses root access to attach eBPF probes directly to the kernel. This is the only way to achieve **100% transparent profiling**, capturing even asynchronous `io_uring` operations without any application impact.
2.  **Tier S (Standard):** Uses unprivileged `USER_NOTIF`. Transparent for synchronous syscalls, but has a "blind spot" for `io_uring`.
3.  **Tier A (Iterative):** Fully in-process and unprivileged. It "learns" the policy through trial-and-error by catching and resolving `AccessDeniedException`s.

---

## Dynamic Profiling: The Developer Workflow

The dynamic profiling workflow in mazewall involves wrapping the target workload in a `Profiler.profile` block, executing integration tests, and capturing the resulting contract.

Let's look at a realistic workload. This task reads a local JSON configuration file, connects to a local loopback server to read a greeting, and attempts to initialize a high-performance `io_uring` queue (a modern Linux I/O engine used by frameworks like Netty):

```kotlin
val workload = {
    // 1. Read configuration from disk
    val config = File("/tmp/mazewall_app_config.json").readText()
    
    // 2. Connect to local server and read a greeting
    val clientSocket = Socket("localhost", serverPort)
    val greeting = clientSocket.getInputStream().bufferedReader().readText()
    clientSocket.close()

    // 3. Initialize high-performance async io_uring
    val setupNr = Syscall.IO_URING_SETUP.numberFor(Arch.current()).toLong()
    val setupResult = LinuxNative.syscall(setupNr, 32L, 0L)
    
    if (setupResult.returnValue >= 0) {
        val ringFd = setupResult.returnValue.toInt()
        LinuxNative.close(ringFd)
    }
    
    "Workload successfully completed!"
}
```

To profile this workload and generate its SBoB, we wrap it in mazewall's built-in profiler:

```kotlin
import io.mazewall.profiler.Profiler

fun main() {
    // Run the workload under the Profiler to audit exact syscalls & path accesses
    val profilingResult = Profiler.profile {
        workload()
    }

    // Inspect the return value
    println(profilingResult.value)
}
```

Behind the scenes, the profiler intercepts every system call and filesystem access occurring *only* on the active executing thread. Because the profiler is scoped to this specific thread block, it ignores process-wide background activity like the JIT compiler's compilation threads, garbage collection sweeps, and unrelated JVM thread pools.

However, system call profiling on a live thread is never completely sterile. Developers must account for **transient runtime noise** executed directly by the JVM on the profiled thread:

*   **Dynamic Classloading:** If a class (within the workload or a third-party dependency) is loaded for the first time during the profiling run, the profiled thread executes the classloader. This triggers filesystem reads on JARs/classes and memory management calls (`mmap`, `mprotect`).
*   **DNS Resolution & Network Bookkeeping:** Connecting to a hostname (even `"localhost"`) forces the thread to invoke name resolution stubs, reading host configurations (like `/etc/resolv.conf` or `/etc/nsswitch.conf`) and querying network sockets.
*   **Thread Synchronization:** Lock contention or thread parking triggers coordination calls (`futex`, `sched_yield`) directly on the executing thread.
*   **vDSO Fallbacks:** Calls to retrieve system time (`System.currentTimeMillis()`) normally run in userspace via vDSO, but can fall back to direct `clock_gettime` system calls under certain container virtualizations or older architectures.

This transient noise presents a operational challenge: if a class is warmed up *before* profiling but loaded lazily in production, the production thread will crash due to a missing rule (under-specification). Conversely, whitelisting classloader paths that are only loaded once during test setup violates the principle of least privilege (over-specification). Mitigating this requires warming up the JVM before running the profiler, or relying on AOT compilation (as discussed in Part 5).

## Policy Compilation & DSL Representation

Once the profiling run completes, the profiler compiles its observations into an immutable record called a `BillOfBehavior` (BoB). 

The `BillOfBehavior` compiles directly to a Kotlin Policy DSL representation via `bob.toDsl()`. This output is a type-safe definition ready for inclusion in the application configuration:

```kotlin
val bob = profilingResult.behavior
val dsl = bob.toDsl("MyWorkerPolicy", Policy.PURE_COMPUTE)
println(dsl)
```

The output is a structured Kotlin policy definition:

```kotlin
val MyWorkerPolicy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .unblock(Syscall.IO_URING_SETUP)
    .allowFsRead("/tmp/mazewall_app_config.json")
    .build()
```

### The Anatomy of the Policy
This generated policy contains three elements:
1. **`Policy.PURE_COMPUTE`:** This is a default-deny base policy. It blocks high-risk actions like process execution (`execve`), network socket creation (`socket`), and executable memory allocation.
2. **`unblock(Syscall.IO_URING_SETUP)`:** The profiler detected that the thread requires setting up an `io_uring` queue, and whitelists only this specific system call.
3. **`allowFsRead("/tmp/mazewall_app_config.json")`:** The profiler observed a file read. Instead of granting broad filesystem access, it whitelists only the specific configuration file path that was touched.

---

## Dynamic Filesystem Learning: The Iterative Profiler

System call profiling is straightforward, but file paths are highly dynamic. In a complex web application, a task might lazily read class files, local resources, or temporary data that isn't easily captured in a single linear execution.

To solve this unprivileged, mazewall provides the **Iterative Profiler** (`IterativeProfiler.profile`).

It is important to understand a fundamental kernel constraint here: **Landlock does not have a "permissive" or "log-only" mode.** Unlike AppArmor or SELinux, which can "complain" (log but allow), Landlock only logs when it **denies** access. This creates a "Catch-22" for transparent profiling: to see what an app is doing via Landlock logs, you must block its access; but if you block its access, the app crashes and you can't see the rest of the workload.

To profile file paths without root, mazewall uses a pragmatic, loop-based learning algorithm:

1. **Deploy in Staging/Test:** The workload is executed under a restricted base policy with filesystem access denied by default.
2. **Catch Violations:** When the JVM attempts to read an unauthorized path (e.g., loading a lazy class or reading a config), the kernel blocks the access, throwing a filesystem `AccessDeniedException`.
3. **Learn and Whitelist:** The Iterative Profiler catches the exception, extracts the denied path, whitelists it in the active ruleset, and immediately retries the execution.
4. **Converge:** The loop runs progressively until the entire code block executes from start to finish without triggering a single filesystem violation.

```kotlin
// Base policy allows standard file/open syscalls, but denies all paths by default
val basePolicy = Policy.builder()
    .unblock(Syscall.OPEN, Syscall.OPENAT, Syscall.OPENAT2)
    .build()

val compiledPolicy = IterativeProfiler.profile(basePolicy) {
    // Runs the workload, dynamically learning and whitelisting every required file path
    targetWorkload()
}
```

Upon convergence, the iterative execution yields the minimal set of verified paths (`compiledPolicy.allowedFsReadPaths`) required for successful classloading and execution.

---

## The Dynamic Profiling Risk: The Environment Drift

While dynamic profiling automates rule generation, it introduces a systems-level operational risk: **Environment Drift**.

Because the Profiler records the *exact* physical execution of the thread, the accuracy of your generated Bill of Behavior (BoB) relies on a perfect match between your profiling sandbox and your production execution environment. If any of the following variables differ, the actual system calls or filesystem paths required by your application may shift, resulting in immediate production crashes when your policy is enforced:

*   **CPU Architecture:** System call tables differ physically between hardware platforms (e.g., `x86_64` vs. `aarch64`/ARM64). While `mazewall` handles CPU architecture translation for syscall names under the hood, the underlying code paths generated by the JVM or native libraries (like Netty) can vary, executing completely different syscalls on different CPUs.
*   **Operating System & Kernel Version:** System calls change, evolve, or are introduced across Linux kernel versions. Furthermore, Landlock features (like ABI levels) depend directly on the running host kernel. A policy profiled on a cutting-edge local kernel might crash on an older enterprise production kernel.
*   **Java Virtual Machine (JVM) Version & Vendor:** Different JDK releases (e.g., JDK 22 vs. JDK 25) or vendors (e.g., Eclipse Temurin vs. GraalVM) utilize completely different internal systems-level mechanisms for Garbage Collection, JIT compilation stubs, and thread park synchronization. A profile generated under Temurin will likely crash when run under GraalVM due to diverging GC stubs.
*   **System Libraries & Host Configuration:** The local C standard library (e.g., standard `glibc` vs. Alpine's `musl`), JVM flags (like `-XX:+UseG1GC` vs. `-XX:+UseZGC`), and even local hostname configurations can alter which low-level system calls are invoked for basic memory allocation or network lookup operations.

> [!WARNING]
> **The golden rule of dynamic profiling:** Always profile in a container that replicates your **production environment alignment matrix** (identical CPU architecture, host kernel capabilities, base image OS libraries, and JVM flags). Profiling locally on a different architecture/JVM than your target environment is a recipe for production instability.

---

## The Next Step: Enforcement

Once you have generated your `Policy` using the Profiler, enforcing it in production requires wrapping your thread pool with mazewall's decorator:

```kotlin
import io.mazewall.enforcer.ContainedExecutors

// Create a standard Java thread pool
val baseExecutor = Executors.newFixedThreadPool(4)

// Wrap it with mazewall using your compiled policy
val containedExecutor = ContainedExecutors.wrap(baseExecutor, MyWorkerPolicy)

// Submit tasks — execution is constrained by the registered filter
containedExecutor.submit {
    workload()
}
```

Tasks submitted to `containedExecutor` execute on OS threads where the Seccomp/Landlock restrictions are applied. Any attempt to invoke unapproved system calls or access unapproved paths triggers kernel-level rejection.

Enforcing these restrictions raises several systems-level questions: How does a JVM-managed runtime safely apply Seccomp and Landlock filters to individual OS threads? And how do we prevent resource conflicts, deadlocks with the garbage collector, or interference with the JIT compiler?

In **Part 3**, we will look under the hood of mazewall to examine the mechanics of JVM thread containment.

---

*Next Up: [Part 3: Thread-Scoped JVM Containment: The Mechanics](article3-enforcement.md)*
