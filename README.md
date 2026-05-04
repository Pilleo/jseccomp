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

**Graceful degradation** — On macOS or Windows, the library runs tasks uncontained by default. Configure via:

```bash
-Dio.contained.fallback=FAIL            # throw UnsupportedOperationException
-Dio.contained.fallback=WARN_AND_BYPASS # log warning, run uncontained (default)
-Dio.contained.fallback=SILENT_BYPASS   # run uncontained silently
```

Or equivalently via the `IO_CONTAINED_FALLBACK` environment variable.

---

## Virtual Threads

Seccomp filters are **per-thread**. Virtual threads multiplex onto carrier threads from the shared ForkJoinPool — which means you cannot contain a virtual thread by wrapping its executor. The filter must be installed on the carrier.

The correct pattern for virtual threads:

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
val vtFactory = Thread.ofVirtual().scheduler(carriers).factory()
val virtualPool = Executors.newThreadPerTaskExecutor(vtFactory)

// Every virtual task is now guaranteed to run on a restricted carrier
virtualPool.submit { vulnerableLogger.log(input) }
```

---

## What This Is Not

- **Not a complete sandbox.** A contained thread cannot make blocked syscalls, but it can still consume CPU and memory. For resource isolation, use cgroups.

- **Not a guarantee against in-process attacks.** Code in the same JVM can read your thread's heap, modify static state, and poison shared caches. This library protects against I/O side effects, not memory corruption.

- **Not bypass-proof against privileged attackers.** A process with `CAP_SYS_ADMIN` can disable seccomp filters. This library assumes you trust the kernel and the initial process setup.

- **Not a replacement for input validation.** Blocking exec after the fact is defense in depth. Validate your inputs first.

- **Not compatible with virtual thread executors using the default shared scheduler** without the dedicated carrier pattern described above.

- **Blocking `clone` can cause JVM crashes.** The `clone` and `clone3` syscalls are available in the API but are **not** blocked by the default `NO_EXEC` or `PURE_COMPUTE` policies. 
  - **Why it is safe:** This is not an escape hatch. In Linux, seccomp filters are strictly inherited by all child processes and threads created via `clone` or `fork`. If an attacker compromises a thread and spawns a new thread, that new thread is born inside the exact same sandbox and cannot escalate privileges.
  - **Why blocking it is dangerous:** The JVM uses `clone` internally for lazy initialization of subsystems (like GC or Logger threads). If you manually block `clone`, a contained task triggering lazy initialization will cause `pthread_create` to fail (`EPERM`), leading to silent internal JVM thread failures or crashes.

- **Not available on macOS or Windows.** The library degrades gracefully on non-Linux platforms, with a clear warning. Production deployments should always be Linux.

- **Not all syscalls are blockable with simple number checks.** `mmap` with `PROT_EXEC` is dangerous only when backed by a file descriptor; blocking it outright breaks the JIT. v0.1 takes a conservative approach and does not block `mmap`. Future versions may inspect arguments.

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