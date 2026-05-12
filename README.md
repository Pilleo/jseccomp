# contained-executors

**Kernel-enforced containment for Java threads. No agents. No SecurityManager. Just seccomp.**

---

## The Problem

In December 2021, Log4Shell (CVE-2021-44228) allowed attackers to achieve Remote Code Execution on millions of Java servers by crafting a single malicious string. The exploit worked by tricking Log4j into calling `Runtime.exec()` to spawn a reverse shell.

Mitigations came in two flavors, and both fell short:

- **Input validation** — Attackers quickly found bypasses. You cannot enumerate every way a string might be dangerous.
- **Java's SecurityManager** — Deprecated in JDK 17 and removed in JDK 24. It was never truly reliable.

The real question is: **What happens when a library you trust does something it should never be allowed to do?**

---

## The Solution

Wrap the executor that runs untrusted code. The kernel enforces the policy — no JVM bytecode can circumvent it.

```kotlin
val safe = ContainedExecutors.wrap(
    Executors.newSingleThreadExecutor(),
    Policy.NO_EXEC
)

// The exploit payload reaches the vulnerable logger...
val future = safe.submit { vulnerableLogger.log(maliciousInput) }

// ...but the kernel intercepts execve() and returns EPERM.
// The reverse shell never spawns. Attack neutralized.
future.get() // throws ExecutionException { cause: ContainmentViolationException }
```

No changes to `vulnerableLogger`. No patch required. Five lines of wrapping code.

---

## How It Works

`contained-executors` uses **Linux seccomp-bpf** — the same mechanism used by Chrome, Docker, and Elasticsearch — to install a system call filter on each worker thread before it runs any user code.

The filter is a small BPF program that intercepts every syscall made by the thread and returns `EPERM` for prohibited ones. Once installed, the filter cannot be removed or bypassed by any JVM code: it is enforced by the kernel at the hardware boundary.

When a blocked syscall is attempted, the kernel returns `EPERM`. This surfaces as an `IOException("Operation not permitted")` inside the JVM, which `ContainedExecutors` catches and translates into a `ContainmentViolationException` carrying the original cause.

---

## Quick Start

### Try It Live (No Setup Required)

Want to see it in action without configuring a Linux VM and JDK 22?
- **[Interactive Playground on Killercoda](https://killercoda.com/YOUR_USERNAME/scenario/jsecomp)** – A free, browser-based Linux environment where you can run the tests, tweak `Policy.kt`, and experiment with the containment yourself.
- **[Watch the Demo](#)** *(Recording coming soon)* – A 30-second terminal recording of the exploit succeeding, then being blocked by the kernel.

### Requirements

- **Linux** (x86_64 or aarch64) — seccomp is a Linux kernel feature
- **JDK 22+** — requires the Foreign Function & Memory (FFM) API
- Gradle 9+ or Maven with `--enable-native-access=ALL-UNNAMED`

### Running the Demo

```bash
./gradlew :demo:test
```

This runs two tests back-to-back:

1. **`ExploitDemonstrationTest`** — Without containment, the exploit succeeds: `touch /tmp/pwned_unsafe` executes.
2. **`ProtectionDemonstrationTest`** — With containment, `ContainmentViolationException` is thrown and the file is never created.

### Usage

**Wrap a standard `ExecutorService`:**

```kotlin
val executor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    Policy.NO_EXEC,
    Policy.NO_NETWORK
)
```

**Built-in policies:**

| Policy | Blocked syscalls |
|---|---|
| `Policy.NO_EXEC` | `execve`, `execveat`, `fork`, `vfork` |
| `Policy.NO_NETWORK` | `connect`, `sendto`, `sendmsg`, `socket` |
| `Policy.PURE_COMPUTE` | All of the above + `open`, `openat` |

**Custom policy:**

```kotlin
val myPolicy = Policy.builder()
    .block(Syscall.PTRACE)
    .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
    .block(Syscall.MEMFD_CREATE) // Close the memfd_create bypass (see below)
    .build()
```

**Combine policies:**

```kotlin
val combined = Policy.combine(Policy.NO_NETWORK, myPolicy)
```

**Install on the current thread directly** (e.g., on virtual thread carriers):

```kotlin
ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
```

**Graceful degradation** — On macOS or Windows, the library **fails by default** to prevent accidental insecure deployments. To override this behavior (e.g., for local development), configure via:

```bash
-Dio.contained.fallback=FAIL            # throw UnsupportedOperationException (default)
-Dio.contained.fallback=WARN_AND_BYPASS # log warning, run uncontained
-Dio.contained.fallback=SILENT_BYPASS   # run uncontained silently
```

---

## Important: Shared Thread Pools & "Poisoning"

Seccomp filters are **immutable and permanent** for the lifetime of a thread. 

If you wrap an `ExecutorService` (like `Executors.newFixedThreadPool`), the worker threads in that pool will be permanently restricted after their first contained task. **Do not share the same pool between contained and uncontained tasks.** If an uncontained task is later scheduled on a "poisoned" worker thread, it will unexpectedly fail with `EPERM` when attempting restricted operations.

For best results, always use a dedicated `ExecutorService` for restricted tasks.

---

## Virtual Threads

Seccomp filters are **per-thread**. Virtual threads multiplex onto carrier threads from a shared pool — which means you cannot contain a virtual thread by wrapping its executor, and you **must not** install a filter from within a virtual thread (as it would poison the carrier for other unrelated tasks).

**Important:** Calling `installOnCurrentThread()` from inside a virtual thread will throw `IllegalStateException`.

### The Current Limitation

Standard JDK 22 does not currently support per-executor custom schedulers for virtual threads. This means you cannot easily isolate a subset of virtual threads onto a restricted set of carrier threads using public APIs.

### The Recommended Workaround

If you must use virtual threads with seccomp, the only safe way is to:

1. Use a **Platform Thread Executor** wrapped with `ContainedExecutors.wrap()`.
2. Inside your task, perform your sensitive operations.
3. If you need parallelism *within* that task, you can spawn virtual threads, but be aware that they will only be restricted if they happen to run on a carrier thread that has been restricted — which is not guaranteed unless you restrict the **entire** JVM carrier pool (via `jdk.virtualThreadScheduler.parallelism` and global installation), which is generally discouraged.

For security-critical tasks requiring containment, **prefer using Platform Threads** via `ContainedExecutors.wrap(Executors.newFixedThreadPool(...))`.

---

## What This Is Not

- **Not a complete sandbox.** A contained thread cannot make blocked syscalls, but it can still consume CPU and memory. For resource isolation, use cgroups.

- **Not a guarantee against in-process attacks.** Code in the same JVM can read your thread's heap, modify static state, and poison shared caches. This library protects against I/O side effects, not memory corruption.

- **Not bypass-proof against privileged attackers.** A process with `CAP_SYS_ADMIN` can disable seccomp filters. This library assumes you trust the kernel and the initial process setup.

- **Not a replacement for input validation.** Blocking exec after the fact is defense in depth. Validate your inputs first.

- **Not compatible with virtual thread executors using the default shared scheduler** without the dedicated carrier pattern described above. Calling `installOnCurrentThread()` inside a virtual thread throws `IllegalStateException`.

- **Blocking `clone` can cause JVM crashes.** The `clone` and `clone3` syscalls are available in the API but are **not** blocked by the default `NO_EXEC` or `PURE_COMPUTE` policies. 
  - **Why it is safe:** This is not an escape hatch. In Linux, seccomp filters are strictly inherited by all child processes and threads created via `clone` or `fork`. If an attacker compromises a thread and spawns a new thread, that new thread is born inside the exact same sandbox and cannot escalate privileges.
  - **Why blocking it is dangerous:** The JVM uses `clone` internally for lazy initialization of subsystems (like GC or Logger threads). If you manually block `clone`, a contained task triggering lazy initialization will cause `pthread_create` to fail (`EPERM`), leading to silent internal JVM thread failures or crashes.

- **Not available on macOS or Windows.** The library degrades gracefully on non-Linux platforms, with a clear warning. Production deployments should always be Linux.

- **Some syscalls require argument inspection.** `mmap` is a prime example: the JVM uses it constantly for JIT and GC, so blocking it outright would crash the process. However, an attacker can use `mmap` with `PROT_EXEC` to allocate executable memory for shellcode. 
  - **The Solution:** `contained-executors` uses BPF's argument inspection capabilities. Every filter we install includes a special check that allows standard `mmap` calls but triggers a trap if the `PROT_EXEC` bit is set in the protection flags. This blocks in-memory shellcode execution without affecting the JVM's internal operations.

- **`NO_EXEC` does not block `memfd_create`.** An attacker can use `memfd_create` + `mmap(PROT_EXEC)` to execute shellcode in memory without calling `execve`. To close this bypass, add `Syscall.MEMFD_CREATE` to your policy:
  ```kotlin
  val policy = Policy.combine(Policy.NO_EXEC, Policy.builder().block(Syscall.MEMFD_CREATE).build())
  ```

---

## Credits

The seccomp approach used here is inspired by and would not exist without the prior art in [Elasticsearch's `SystemCallFilter`](https://github.com/elastic/elasticsearch/blob/main/server/src/main/java/org/elasticsearch/bootstrap/SystemCallFilter.java). That code is internal to Elasticsearch and not reusable as a library. This project makes the same pattern available to any Java application.

---

## Building

```bash
# Run all tests (including the live exploit/protection demo)
./gradlew check

# Build all modules
./gradlew build
```

Module structure:

| Module | Purpose |
|---|---|
| `utils` | The `io.contained` library (Arch, BpfFilter, SeccompInstaller, ContainedExecutors, Policy, etc.) |
| `demo` | The Log4Shell-style exploit/protection demonstration |
| `app` | Placeholder application module |