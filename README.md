# jseccomp

**Kernel-enforced thread-scoped sandboxing for JVM applications. No agents. No SecurityManager. Just pure Linux Seccomp & Landlock.**

---

> [!WARNING]
> **Experimental Research Proof-of-Concept.** This library is an untested research prototype exploring thread-scoped sandboxing on modern Linux kernels. It is not production-ready, contains known stability and security limitations, and must **not** be deployed in production environments.

---

## The Solution

Modern application security layers are often too broad (process-wide containers) or highly brittle (application-level parsing checks). `jseccomp` provides surgical, unprivileged self-restriction at the OS thread boundary. By wrapping the executor that runs untrusted data-parsing tasks, the kernel enforces the security policy — no JVM bytecode or dynamic vulnerability can circumvent it.

```kotlin
val safe = ContainedExecutors.wrap(
    Executors.newSingleThreadExecutor(),
    Policy.NO_EXEC
)

// The exploit payload reaches a vulnerable library...
val future = safe.submit { vulnerableLogger.log(maliciousInput) }

// ...but the kernel intercepts execve() and returns EPERM.
// The reverse shell never spawns. The attack is completely neutralized.
future.get() // Throws ExecutionException { cause: ContainmentViolationException }
```

## How It Works

`jseccomp` uses **Linux Seccomp-BPF** and **Landlock LSM** to install unprivileged security filters. The implementation is 100% pure Java, utilizing the **Foreign Function & Memory (FFM) API** (JDK 22+) to interface directly with the kernel without the need for native C dependencies.

Prohibited syscalls trigger a `SECCOMP_RET_ERRNO` with `EPERM` (or Landlock file permissions return `EACCES`), causing standard Java I/O or JNI calls to fail. The executor wrapper catches these failures, matches them, and throws a `ContainmentViolationException`.

---

## Features & Roadmap

### Existing Capabilities
* **Tier 1 - Process-Wide Lockdown:** Apply `Policy.NO_EXEC` to the entire JVM at startup, rendering shell spawning completely impossible.
* **Tier 2 - Thread-Scoped Surgical Containment:** Wrap dedicated platform thread pools to strip capabilities (such as network access or dynamic memory execution) from worker threads.
* **Dual-Syscall JIT Memory Protection:** Generates linear BPF bytecode that inspects both `mmap` and `mprotect` arguments, blocking `PROT_EXEC` modifications to stop shellcode injection without interfering with the JVM's JIT compiler.
* **Path-Aware Filesystem Sandboxing:** Seamlessly integrates **Landlock** to restrict directories (e.g. allowing reads in `/data/incoming` while blocking `/etc` and the host filesystem).
* **Automatic Classpath Authorization:** Auto-whitelists the JVM classpath and `java.home` to avoid lazy classloading crashes inside Landlock.

### Roadmap: Native `SIGSYS` Trapping (SECCOMP_RET_TRAP)
The current implementation relies on `SECCOMP_RET_ERRNO` and parsing localized JVM exception strings. We are actively planning a roadmap to transition to a native `SIGSYS` trapping architecture:
1. **`SECCOMP_RET_TRAP` Execution:** Instruct the kernel BPF filter to trigger a `SIGSYS` signal upon a violation.
2. **Native Signal Handler Integration:** Register a native C signal handler using `sigaction` via FFM.
3. **Instruction Pointer Advancement:** Intercept the signal, asynchronously record registers and violation metadata, modify `rax` to `-EPERM`, and increment the instruction pointer (`rip` / `pc`) past the 2-byte `syscall` instruction to resume Java execution safely.
4. **Deterministic Java Exception Mapping:** Map violations deterministically to Java exceptions without relying on brittle exception message parsing.

---

## Quick Start

### 1. Run the Tests Locally

To run the integration suite in a contained environment with nested seccomp support:

```bash
git clone https://github.com/leanid/jseccomp.git
cd jseccomp

# Start the container under the custom seccomp profile
docker compose up -d
docker compose exec jseccomp ./gradlew test
```

> **Note on Container Security:** Rather than running completely unconfined (which is insecure), `jseccomp` includes a custom [docker-seccomp.json](docker-seccomp.json) profile that is automatically configured in [docker-compose.yml](docker-compose.yml). This profile whitelists `seccomp(2)` filter stacking, enabling the JVM inside the container to apply nested thread-level policies while keeping the container fully isolated from the host.

### 2. Configure a Path-Restricted Thread Pool (Landlock)

```kotlin
// Restrict filesystem access, block process execution, and disable network
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .allowJvmClasspath()             // Crucial: allow lazy loading of JVM classes
    .allowFsRead("/data/incoming")   // Allow read-only access here
    .allowFsWrite("/data/processed") // Allow write-only access here
    .build()

val executor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    policy
)

executor.submit {
    // This will succeed:
    val data = File("/data/incoming/task1.json").readText()
    File("/data/processed/result.json").writeText(data)
    
    // This will throw AccessDeniedException:
    File("/etc/passwd").readText()
}
```

---

## Built-In Policies

| Policy | Blocked Syscalls / Primitives | Best Use Case |
|---|---|---|
| `Policy.NO_EXEC` | `execve`, `execveat`, `fork`, `vfork`, `memfd_create`, `io_uring_setup` | Process-wide startup lockdown baseline. |
| `Policy.NO_NETWORK` | All execution blocks + `connect`, `socket`, `bind`, `accept` | Data parsers that require local filesystem access but no internet. |
| `Policy.PURE_COMPUTE` | All network and execution blocks + `open`, `ioctl`, `prctl` | Algorithmic worker pools (image decoding, cryptographic operations). |

## System Call Reference

When designing custom security policies, you should consult the authoritative Linux documentation for each system call.

*   **Linux Man Pages:** Use `man 2 <syscall_name>` in your terminal (e.g., `man 2 prctl`, `man 2 seccomp`) to read the exact signature, argument descriptions, and potential error codes (`errno`).
*   **Online Reference:** The [man7.org Section 2](https://man7.org/linux/man-pages/dir_section_2.html) portal provides the most up-to-date web-based version of the Linux manual pages.
*   **Architecture Tables:** For architecture-specific syscall numbers (ID mapping), refer to [syscalls.me](https://syscalls.me/) or [filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/).

---

## Critical JVM Constraints

* **Loom Virtual Thread Contamination:** Thread-scoped seccomp sandboxes the underlying OS thread. Since virtual threads share OS carrier threads via a ForkJoinPool, applying a filter inside a virtual thread will permanently "poison" that carrier thread. `jseccomp` explicitly detects virtual threads at runtime and throws `IllegalStateException` to prevent this bypass.
* **GC & Safepoint Deadlock Risk:** Custom policies must never block JVM coordination syscalls (`futex`, `sched_yield`, `rt_sigreturn`, `madvise`, `gettid`). Blocking synchronization primitives will lead to VM-wide deadlocks during the next GC cycle.
* **Shared-Memory ACE Bypass:** Thread-scoped seccomp is not an absolute sandbox. If an attacker achieves native Arbitrary Code Execution (ACE) on a thread, they can manipulate the shared JVM heap/stack to corrupt unrestricted carrier or parent threads. Combine with process-wide `NO_EXEC` (Tier 1) for strong defense-in-depth.

---

## License

This project is licensed under the Apache License 2.0.
