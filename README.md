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

`contained-executors` uses **Linux seccomp-bpf** to install system call filters on worker threads. The implementation uses the Java Foreign Function & Memory (FFM) API to interact with the kernel.

Prohibited syscalls trigger a `SECCOMP_RET_TRAP`, which the kernel delivers as a `SIGSYS` signal. The library registers a native signal handler to capture these events and record violation details in a shared memory segment. The executor wrapper checks this state after each task to ensure violations are detected even if the resulting system call failure is suppressed by user logic.

This mechanism is enforced by the kernel at the hardware boundary and cannot be removed or bypassed by any JVM bytecode.

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
| `Policy.PURE_COMPUTE` | All of the above + `open`, `openat`, `ioctl`, `prctl` |

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

Seccomp filters are **per-thread**. Virtual threads multiplex onto carrier threads from a shared pool. Installing a filter from within a virtual thread will sandbox the carrier, affecting all other virtual threads that land on it.

**Important:** Calling `installOnCurrentThread()` from inside a virtual thread throws `IllegalStateException` to prevent accidental carrier contamination.

### The Dedicated Carrier Pattern

To safely contain virtual threads, you must isolate them onto a dedicated set of carrier threads and install the policy on those carriers manually.

```kotlin
// Step 1: Create dedicated carrier threads and install the policy on each
val carriers = Executors.newFixedThreadPool(4)
val ready = CountDownLatch(4)
repeat(4) {
    carriers.submit {
        ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
        ready.countDown()
    }
}
ready.await()

// Step 2: Build a virtual thread executor that uses these restricted carriers
// Note: Requires a way to provide 'carriers' as the scheduler to the virtual thread factory.
// For security-critical tasks, Platform Threads are the recommended stable alternative.
```

---

## What This Is Not

- **Not a complete sandbox.** A contained thread cannot make blocked syscalls, but it can still consume CPU and memory. For resource isolation, use cgroups.

- **Not a guarantee against in-process attacks.** Code in the same JVM can read your thread's heap, modify static state, and poison shared caches. This library protects against I/O side effects, not memory corruption.

- **Not bypass-proof against privileged attackers.** A process with `CAP_SYS_ADMIN` can disable seccomp filters. This library assumes you trust the kernel and the initial process setup.

- **Not a replacement for input validation.** Blocking exec after the fact is defense in depth. Validate your inputs first.

- **`clone` and `mmap` are selectively restricted.** Previously, blocking these syscalls caused JVM instability.
  - **`clone`:** We now use argument inspection to allow thread creation (`CLONE_THREAD`, `CLONE_VM`) while blocking process forking. Modern `clone3` calls are forced to fallback to inspectable legacy `clone` via `ENOSYS`.
  - **`mmap`:** We allow standard mappings but block requests with `PROT_EXEC` to prevent in-memory shellcode execution.

- **Not available on macOS or Windows.** The library degrades gracefully on non-Linux platforms, with a clear warning. Production deployments should always be Linux.

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
