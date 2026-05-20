# The Global Sandbox Fallacy: Thread-Scoped Seccomp in the JVM

> **Series overview:** This is Part 2 of a 4-part series on behavioral security for cloud-native applications.


In Part 1, we established that the Linux kernel gives us three unprivileged enforcement primitives — Seccomp, Landlock, and (for platform agents) BPF-LSM — and that a Software Bill of Behavior describes what software is *expected* to do so these primitives have something authoritative to enforce.

Now we get practical. The JVM is one of the most capability-rich processes in the modern data center. Let's examine why the standard approach to securing it leaves significant attack surface, and how thread-scoped enforcement closes the gap.

---

## Why Not BPF-LSM?

Before anything else: if you've been following kernel security, your first question is probably *"why Seccomp and not BPF-LSM?"*

BPF-LSM is unambiguously more powerful. While Seccomp sees raw memory addresses and is TOCTOU-vulnerable for path-based decisions (Part 1), BPF-LSM hooks *after* kernel objects are fully resolved — it inspects the canonical path `/etc/passwd`, the resolved destination IP, the resolved inode. It enables complex, context-aware enforcement that Seccomp cannot match.

**The architectural blocker is privilege.** Loading a BPF-LSM program requires `CAP_BPF` or `CAP_MAC_ADMIN`. A production JVM running as a non-root user in a container should never hold these capabilities. Using BPF-LSM for application-level self-restriction means deploying a highly privileged node agent (a Kubernetes DaemonSet) to manage policies on the JVM's behalf — a significant operational dependency.

Seccomp and Landlock are **self-restriction primitives**. With `NoNewPrivileges` set, any thread can unilaterally strip its own capabilities — no agents, no cluster-level permissions. `jseccomp` requires zero external infrastructure. That architectural purity has a cost (TOCTOU on path inspection), but it's the right trade-off for developer-driven "shift left" security.

---

## The Global Sandbox Fallacy

The standard approach to JVM security is a global seccomp profile applied to the entire Linux process — the Docker default profile, an AppArmor policy on the pod, or a custom seccomp JSON in the `securityContext`.

This is not worthless. Docker's default profile already blocks ~40 dangerous syscalls: `keyctl`, `add_key`, `request_key`, `ptrace` in certain modes, and others. That baseline matters.

**But the remaining allowed syscalls are the problem.** A typical Spring Boot application — even after Docker's default restrictions — still requires:
- `socket` + `connect` + `sendmsg` for its API and database connections
- `openat` + `read` for reading config files and loading classes
- `mmap` with `PROT_EXEC` for the JIT compiler to generate native code

Because the *process* needs these capabilities, *every thread* in the process has them — including threads processing untrusted data.

When an attacker triggers an RCE vulnerability (Log4Shell, a deserialization gadget chain, an XXE payload that reaches JNDI), they inherit the full capability set of the worker thread. They don't need to escape the container. They can use the network socket the JVM already has open to exfiltrate data, the filesystem access it already has to read `/etc/passwd`, the process execution it already has to... wait, that's where it gets interesting.

---

## The Solution: Tiered Enforcement

The Linux kernel provides a capability that is underutilized: **Seccomp filters can be applied per-thread.**

`jseccomp` is built around a two-tier model:

**Tier 1 — Global Process Lockdown:** At application startup, apply `Policy.NO_EXEC` to the entire JVM process via `ContainedExecutors.installOnProcess()`. This permanently disables shell spawning (`execve`, `execveat`, `fork`, `vfork`, `memfd_create`) for every thread, present and future.

This mimics the approach Elasticsearch has used in production for years — a minimal, process-wide filter that renders Log4Shell-style RCE toothless. The attacker can reach your vulnerable code; they simply cannot spawn a shell. The filter is permanent and cannot be undone.

> [!WARNING]
> **Experimental and Untested Code.** The entire `jseccomp` library — including both the process-wide (`installOnProcess()`) and thread-scoped (`wrap()`) mechanisms — is an **experimental proof-of-concept**. None of this code has been tested or validated for production environments. Do not use any part of this library in production.



**Tier 2 — Surgical Thread Containment:** For specific worker pools handling untrusted data — JSON parsers, image processors, XML deserializers, report generators — apply stricter policies. `ContainedExecutors.wrap()` creates an `ExecutorService` decorator that installs the chosen policy on each worker thread before it runs its first task. These restrictions are permanent for the lifetime of that thread.

```kotlin
// Global lockdown at startup — all threads, forever
ContainedExecutors.installOnProcess(Policy.NO_EXEC)

// Per-pool surgical restriction for untrusted-data workers
val imageProcessor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    Policy.PURE_COMPUTE  // no network, no file open, no exec, no mmap(PROT_EXEC)
)
```

---

## Stopping Shellcode Without Breaking the JIT

The JVM's JIT compiler is the most obvious obstacle to strict memory protection. The JIT must call `mmap` with `PROT_EXEC` to allocate executable memory for optimized native code. A naive Seccomp filter blocking all `PROT_EXEC` will crash the JVM immediately.

`jseccomp` solves this with **BPF argument inspection**. The BPF filter doesn't just check the syscall number — it checks the `prot` argument to `mmap` (and `mprotect`). Specifically, it loads the lower 32 bits of `prot` (located at `args[2]` in `struct seccomp_data`) and tests whether the `PROT_EXEC` bit (0x4) is set. 

Here is the exact logical flow of the BPF bytecode instruction sequence generated by the library:

```assembly
; 1. Load the system call number into the accumulator
ld [0]                 ; ACC = seccomp_data.nr

; 2. Check if this is mmap (e.g. syscall 9 on x86_64)
jeq #9, jt_mmap, jf_next ; If ACC == 9, proceed to mmap check; else next check

jt_mmap:
; 3. Load the 3rd argument (prot) which is at args[2] (offset 32 in seccomp_data)
ld [32]                ; ACC = seccomp_data.args[2] (lower 32-bits of prot)

; 4. Check if the PROT_EXEC (0x04) bit is set
jset #0x04, deny, allow ; If (ACC & 0x04) is true, jump to deny; else allow mapping

deny:
ret #0x00050001        ; SECCOMP_RET_ERRNO with EPERM (1)

allow:
ld [0]                 ; Restore ACC = seccomp_data.nr for subsequent filters
```

Because this filter is applied only to the contained worker threads, the JIT threads running on the same JVM continue operating without restriction. We've surgically neutralized shellcode execution — thread-scoped, zero JVM stability impact.

> **32-bit truncation note:** BPF operates on 32-bit words. The filter loads the lower 32 bits of `prot`. Since the Linux kernel casts the `prot` argument to `unsigned long` but only honors the standard lower bits defined in POSIX, this truncation is architecturally correct and matches kernel behavior.

---

## The GC and Safepoint Deadlock Risk

Applying extreme restrictions like `Policy.PURE_COMPUTE` inside a HotSpot JVM comes with a massive, implicit runtime risk: **Safepoints and GC cycles.**

A JVM thread is never a completely isolated island. Periodically, the JVM pauses application threads to perform Garbage Collection, generate thread dumps, or execute runtime optimizations (safepoints). To coordinate these operations, application threads must run JVM runtime code, which frequently invokes system calls for synchronization and resource management:
* `futex` for native lock acquisition and thread waking.
* `sched_yield` to relinquish CPU slices during contention.
* `rt_sigreturn` to exit from signals triggered by safepoint interrupts.

If a custom `jseccomp` policy aggressively blocks these utility system calls in a worker thread, the thread will fail to coordinate during the next JVM safepoint. The result is a **catastrophic, VM-wide deadlock or immediate JVM crash**.

> [!CAUTION]
> **Extensive Testing Mandatory.** When creating custom policies, you must never block core JVM synchronization and scheduling primitives. Your policies must be tested under heavy thread contention, high-throughput garbage collection, and active thread dumps in staging environments before any consideration of non-production deployment.

---

## Native vs. JIT Strictness: GraalVM's Advantage

This safepoint deadlock risk exposes a fundamental difference in sandboxing strictness between **JIT-compiled HotSpot JVMs** and **AOT-compiled GraalVM Native Images**:

1. **HotSpot JVM (JIT):** Requires a highly permissive system call floor. Because HotSpot dynamically compiles native code, manages dynamic classloading, and performs complex runtime optimizations, application threads running in HotSpot require access to dynamic memory allocation, thread signaling, and logging.
2. **GraalVM Native Image (AOT):** Can run under an extremely restrictive system call floor. A native binary compiles directly to an ahead-of-time machine executable. It has no JIT compiler thread, no dynamic classloader, and a highly streamlined runtime garbage collector. 

This means that for pure mathematical computation or isolated data parsing tasks, a **GraalVM native binary can safely block system calls that a standard HotSpot JVM would require to avoid crashing**. If you need absolute syscall minimization, compiling to a Native Image is your most resilient path.

---

## The Limits: ROP and JOP

Blocking `mmap(PROT_EXEC)` prevents the *introduction of new malicious code* (shellcode). It does not stop an attacker who reuses *existing* code already mapped in the JVM's address space.

**Return-Oriented Programming (ROP)** and **Jump-Oriented Programming (JOP)** chain together short existing code sequences ("gadgets") from the JVM binary, loaded libraries, and the JDK itself. These chains can implement arbitrary computation without ever calling `mmap` or `mprotect`. Seccomp cannot see CPU instruction flow — only syscalls.

This is not a flaw in `jseccomp`; it is the honest limit of the syscall interception model. The complementary defenses are:
- **ASLR** — randomizes the base addresses of loaded code, making gadget chain addresses unpredictable
- **Stack Canaries** — detect stack corruption before a ROP chain can pivot
- **CFI (Control Flow Integrity)** — hardware enforcement of valid branch targets (Intel CET Shadow Stacks, ARM BTI)

Seccomp is the lock on the door for *new* code. ASLR + CFI are the internal sensors for gadget chain attacks.

---

## Seccomp + Landlock: The Complete Picture

Seccomp's TOCTOU vulnerability for path inspection (it sees raw pointers, not resolved paths) means it cannot safely enforce "this thread may only read from `/app/data`."

**Landlock** fills that gap. It provides path-aware filesystem access control at the inode level, with the same zero-privilege profile as Seccomp. `jseccomp` combines both:

```kotlin
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .allowJvmClasspath()          // allow lazy classloading (critical — see below)
    .allowFsRead("/data/incoming")
    .allowFsWrite("/data/processed")
    .build()

val executor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    policy
)
```

**Critical JVM gotcha:** Landlock is applied at the OS thread level, permanently. If a restricted worker thread is the first to trigger the JVM's lazy classloading for a new class, the JVM will attempt to open the `.jar` or `.class` file from the classpath. If Landlock blocks that read, the JVM throws `NoClassDefFoundError`. `allowJvmClasspath()` pre-authorizes `java.home` and all classpath entries to prevent this. Calling it is not optional when using Landlock.

Unlike Seccomp's `TSYNC` flag, Landlock's `landlock_restrict_self` only affects the calling thread — not existing JVM threads. True process-wide Landlock requires applying the ruleset *before* `execve`-ing the JVM (from a launcher), so all threads inherit it from birth.

---

## Internal Micro-segmentation: Scalpel vs. Shield

A common question: *"If I already run Kubescape or Falco cluster-wide, why do I need thread-level containment?"*

The answer is Defense-in-Depth, and the distinction is *visibility*.

Cluster-wide tools see your container as a black box. They observe the process boundary — what syscalls the JVM process makes, what network connections it opens. They cannot see *which thread inside the JVM* is making those calls, *which library* is on the call stack, or *what data* triggered the behavior. A worker thread processing a malicious JSON payload looks identical to a thread processing a legitimate request from the outside.

`jseccomp` applies restrictions based on internal application logic that no external orchestrator can see. The cluster-wide tool is the building's perimeter security; `jseccomp` is the lock on each individual safe inside.

---

## Beyond Java: The Scheduler Constraint

The principles here are universal, but thread-level enforcement is only meaningful if there is a stable 1:1 mapping between your application's concurrency primitive and an OS thread.

**Go goroutines:** Go's M:N scheduler multiplexes thousands of goroutines onto a small pool of OS threads. If you apply a Seccomp filter to an OS thread to sandbox one goroutine, the Go runtime may schedule a different, completely unrelated goroutine onto that "poisoned" thread — which then crashes the moment it attempts a syscall the previous goroutine was forbidden from using. `runtime.LockOSThread()` prevents scheduling but cripples Go's concurrency model. `GOMAXPROCS=1` doesn't help — the scheduler is still non-deterministic with respect to thread assignment. Thread-level containment is currently impractical for Go.

**Java virtual threads (Project Loom, Java 21+):** Loom's virtual threads have exactly the same M:N scheduler problem as Go goroutines. Virtual threads are scheduled onto a carrier thread pool (by default, a `ForkJoinPool`). 
If a task running on a virtual thread installs a seccomp filter on its current thread, it sandboxes the underlying **OS carrier thread**. When that task completes or yields, the carrier thread remains permanently restricted. Any subsequent virtual thread scheduled onto that carrier—even one running a completely unrelated, high-privilege administrative task—will inherit those restrictions and crash or fail.

To prevent this critical "carrier contamination," `jseccomp` detects virtual threads at runtime and immediately throws `IllegalStateException` with a clear diagnostic message:

```
java.lang.IllegalStateException: Attempted to apply seccomp containment inside a virtual thread.
Use a dedicated platform thread pool and install containment on its carrier threads instead.
```

**Rust and C++ with native OS threads:** These use predictable 1:1 thread models and are excellent candidates for thread-level containment. Process-level enforcement (`prctl(PR_SET_SECCOMP, ...)`) is universally portable regardless of thread model.

---

## Configuring Docker: Custom Seccomp Profiles vs. Unconfined

The hands-on examples in Part 3 require running Docker containers with `--security-opt seccomp=unconfined`. This instruction is often misunderstood by developers and system administrators as a security hazard. Let's look at what is actually happening.

A common misconception is that the kernel prevents the installation of new seccomp filters because it cannot verify "monotonicity compatibility." This is technically incorrect: **the Linux kernel supports filter stacking natively**. You can stack as many filters as you want (up to a depth limit of 32, or a BPF instruction count limit), and the kernel will run all of them in reverse order, applying the most restrictive action returned.

**The actual blocker is Docker's default Seccomp profile.** By default, Docker blocks the `seccomp(2)` system call and restricts the `prctl(2)` system call arguments to prevent containers from modifying their own security filters. When the JVM inside a standard container attempts to call `prctl(PR_SET_SECCOMP)` or `seccomp(SECCOMP_SET_MODE_FILTER)`, the host kernel blocks the call at the outer Docker container boundary, causing an immediate `EPERM`.

Running with `seccomp=unconfined` disables the host-side seccomp sandbox entirely to let our demo install filters. However, **this is highly discouraged for production environments**.

### The Production Solution: Custom Docker JSON Profile

Instead of running unconfined, you should run your container with a **custom Docker seccomp JSON profile** that is identical to the standard Docker profile but explicitly whitelists the installation syscalls:

1. **`seccomp`**: Allowed with zero restrictions.
2. **`prctl`**: Allowed, specifically whitelisting `PR_SET_SECCOMP` (22) and `PR_SET_NO_NEW_PRIVS` (38) in the arguments list.

This maintains Docker's robust container-level security floor (blocking access to dangerous host-level calls like `keyctl` or kernel namespace mutations) while empowering the JVM inside the container to dynamically apply its own unprivileged thread-level sandboxes.

### Security Analysis of Nested Seccomp in OCI Runtimes

OCI runtimes (such as `runc`, `containerd`, and Docker) restrict the `seccomp(2)` system call and specific `prctl(2)` options within their default profiles. This design decision is part of a defense-in-depth strategy aimed at reducing the host kernel's attack surface, preventing untrusted processes within containers from interacting with the kernel's BPF verifier or constructing arbitrary syscall filters.

However, the necessity of this OCI-level block can be evaluated against kernel-level invariants:
1.  **Enforced State Monotonicity:** The Linux kernel strictly requires the `PR_SET_NO_NEW_PRIVS` flag to be set before an unprivileged process can load a seccomp filter. Once active, the process and all descendants are permanently barred from privilege transitions (such as setuid, setgid, or file capability elevations).
2.  **Filter Monotonicity:** Seccomp filters can only restrict the current syscall capabilities; they cannot be removed, bypassed, or relaxed by subsequent nested filters.
3.  **Kernel Limits:** Modern kernels cap seccomp filter depth and BPF program complexity, preventing simple kernel memory exhaustion vectors.

Given these kernel-level invariants, blocking unprivileged seccomp filter installation inside containers does not prevent privilege escalation, since the kernel already enforces an immutable boundary. The primary risk re-introduced by whitelisting `seccomp` and `prctl(PR_SET_SECCOMP)` is a minor increase in BPF verifier exposure. 

A potential architectural alternative for OCI specifications would be to permit nested filter installation by default whenever the container is configured with `allowPrivilegeEscalation: false` (which pre-emptively enforces `PR_SET_NO_NEW_PRIVS`). This would allow secure, application-level sandboxing (such as thread-scoped containment) to be deployed natively within standardized container environments without requiring custom profiles.

---

While process-wide lockdown (Tier 1) is a proven conceptual model (demonstrated by Elasticsearch's native lockdown mechanisms), its implementation in `jseccomp` is entirely experimental. 

Similarly, thread-scoped surgical containment (Tier 2) provides a targeted proof-of-concept isolation boundary. However, the entire library — including both process-wide and thread-scoped modes — remains an **untested research experiment** that should not be used in any production environments.

*Next up: Part 3: The Attacks jseccomp Stops*


