# mazewall

**Kernel-enforced thread-scoped sandboxing for JVM applications. No agents. No SecurityManager. Just pure Linux Seccomp & Landlock.**

---

> [!WARNING]
> **Experimental Research Proof-of-Concept.** This library is an untested research prototype exploring thread-scoped sandboxing on modern Linux kernels. It is not production-ready, contains known stability and security limitations, and must **not** be deployed in production environments.

---

## The Problem

The JVM process security model is binary: every thread in the process shares the same OS-level permissions. A vulnerability in one library exploited on one thread has access to everything the entire process holds — open network sockets, file descriptors, exec permissions. Container-level seccomp profiles (like the OCI default) are applied to the entire process; they cannot distinguish between the trusted framework thread and the worker thread parsing a malicious payload.

When Log4Shell hit, the attacker's code ran on the same thread as the vulnerable logger — a thread that already had `execve` permission because the rest of the JVM needed it.

---

## The Solution

Modern application security layers are often too broad (process-wide containers) or highly brittle (application-level parsing checks). `mazewall` provides surgical, unprivileged self-restriction at the OS thread boundary. By wrapping the executor that runs untrusted data-parsing tasks, the kernel enforces the security policy — no JVM bytecode or dynamic vulnerability can circumvent it.

Here is what that looks like in practice:

```kotlin
val safe = ContainedExecutors.wrap(
    Executors.newSingleThreadExecutor(),
    Policy.NO_EXEC
)

// The exploit payload reaches a vulnerable library...
val future = safe.submit { vulnerableLogger.log(maliciousInput) }

// ...but the kernel intercepts execve() and returns EPERM.
// The shell process is never spawned. The attack's execution vector is blocked.
future.get() // Throws ExecutionException { cause: ContainmentViolationException }
```

## How It Works

`mazewall` uses **Linux Seccomp-BPF** and **Landlock LSM** to install unprivileged security filters. The implementation is 100% pure Kotlin for the JVM, utilizing the **Foreign Function & Memory (FFM) API** (JDK 22+) to interface directly with the kernel without the need for native C dependencies.

Prohibited syscalls trigger a `SECCOMP_RET_ERRNO` with `EPERM` (or Landlock file permissions return `EACCES`), causing standard Java I/O or JNI calls to fail. The executor wrapper catches these failures, matches them, and throws a `ContainmentViolationException`.

---

## Use Cases

### 1. Runtime Attack Prevention
The canonical use case: wrap thread pools that process untrusted input (user uploads, API payloads, deserialized objects) with a policy that blocks process spawning, shellcode injection, and network exfiltration. A compromised library inside the sandbox hits `EPERM` and cannot escape.

### 2. Behavioral Attestation for Regulated Data

This is a less obvious but equally important use case. `mazewall` can be used to **prove** — at the kernel level, not by software assertion — that sensitive data was handled with strict behavioral constraints.

Consider a thread pool that decrypts and processes PII, payment card data, or legally privileged documents. By wrapping it with `Policy.PURE_COMPUTE` and a Landlock path restriction:

- **No network call was made.** `connect`, `socket`, `sendmsg` are blocked by the kernel. The data could not have been exfiltrated, regardless of what application code claims.
- **No file was written outside the declared path.** The data was not persisted anywhere outside the explicitly whitelisted Landlock paths — not even by a misbehaving logger.
- **No subprocess was spawned.** `execve`, `fork`, `memfd_create` are blocked. The data could not have been passed to an external process or a fileless in-memory executor.

Any violation of these guarantees causes an immediate, observable `ContainmentViolationException`. Violations are not silent — they are detectable events.

This is relevant to:
- **Fintech / PCI DSS:** Proving that card numbers or cryptographic keys were used only for the declared computation.
- **Healthcare / HIPAA:** Proving that PHI passed through a transformation step without being replicated, transmitted, or logged externally.
- **Legal / Confidentiality:** Proving that a privileged document was analyzed but never copied, exfiltrated, or written to an unexpected path.
- **Confidential Computing pipelines:** Providing an in-process behavioral attestation layer complementary to hardware trusted execution environments (TEEs).

> [!IMPORTANT]
> This attestation is **kernel-enforced, not software-asserted**. The guarantee comes from the Linux Seccomp and Landlock subsystems — not from application-level checks that an attacker could bypass. Subverting it requires compromising the kernel itself.

> [!WARNING]
> The attestation covers **syscall-level behavior only**. It cannot prevent in-process memory reads by other threads sharing the same JVM heap (see *Shared-Memory ACE Bypass* below). For absolute isolation, combine with process-wide `NO_EXEC` (Tier 1) and, where the strongest guarantees are required, a hardware TEE.

## Project Module Architecture

`mazewall` is split into specialized subprojects to keep production deployments clean, lightweight and secure:

*   **`:enforcer`**: The core runtime enforcement engine. It performs the Foreign Function & Memory (FFM) system call bindings, compiles `Policy` records into raw Seccomp BPF programs, handles Landlock path containment, and manages thread coordination safety. It has **zero runtime dependencies** beyond Kotlin and standard JVM libraries.
*   **`:profiler`**: The diagnostic and trace profiling module. It implements active monitoring techniques like out-of-process BPF `USER_NOTIF` listener daemons, iterative progressive path testing, and `strace`-based descendant process log analysis. This module compiles trace data into structured Bills of Behavior (SBoBs) and is designed **strictly for testing and developer environments**.
*   **`:demo`**: The interactive core showcase demonstrating how `mazewall` blocks Arbitrary Code Execution (ACE) exploits at the kernel level and how Seccomp and Landlock form complementary protection layers to prevent modern asynchronous seccomp bypasses (`io_uring`).
*   **`:demo:vulnerable-app`**: A comprehensive Spring Boot 3.x integration showing real-world CVE exploitation prevention (Log4Shell, SSRF, XXE, etc.) in a production-like environment.

---

## Features & Roadmap

### Existing Capabilities
* **Tier 1 - Process-Wide Lockdown:** Apply `Policy.NO_EXEC` to the entire JVM at startup, rendering shell spawning completely impossible.
* **Tier 2 - Thread-Scoped Surgical Containment:** Wrap dedicated platform thread pools to strip capabilities (such as network access or dynamic memory execution) from worker threads.
* **Dual-Syscall JIT Memory Protection:** Generates linear BPF bytecode that inspects both `mmap` and `mprotect` arguments, blocking `PROT_EXEC` modifications to stop shellcode injection without interfering with the JVM's JIT compiler.
* **Path-Aware Filesystem Sandboxing:** Seamlessly integrates **Landlock** to restrict directories (e.g. allowing reads in `/data/incoming` while blocking `/etc` and the host filesystem).
* **Automatic Classpath Authorization:** Auto-whitelists the JVM classpath and `java.home` to avoid lazy classloading crashes inside Landlock.

### Roadmap: Native `SIGSYS` Trapping (SECCOMP_RET_TRAP)
The current implementation relies on `SECCOMP_RET_ERRNO` and parsing localized JVM exception strings. The primary detection path (`error=1` / `error=13` JVM-encoded errno matching) is locale-independent and already well-optimized; the fundamental limit is that Java's `IOException` does not expose raw errno values. The planned path forward is a native `SIGSYS` trapping architecture:
1. **`SECCOMP_RET_TRAP` Execution:** Instruct the kernel BPF filter to trigger a `SIGSYS` signal upon a violation.
2. **Native Signal Handler Integration:** Register a native C signal handler using `sigaction` via FFM.
3. **Instruction Pointer Advancement:** Intercept the signal, record registers and violation metadata, modify `rax` to `-EPERM`, and advance `rip`/`pc` past the 2-byte `syscall` instruction to resume Java execution. **Caveat:** this technique is only architecturally safe for syscalls that return a scalar error code. Syscalls where the caller dereferences a pointer argument based on the return value (e.g., `mmap` returning a memory address, `stat` writing into a buffer) will crash or corrupt the JVM if their return is faked. The `SECCOMP_RET_ERRNO` approach remains the stable production default for all such syscalls.
4. **Deterministic Java Exception Mapping:** Map violations deterministically to Java exceptions without relying on brittle exception message parsing.

---

## Quick Start

### 1. Run the Tests Locally

To run the integration suite in a contained environment with nested seccomp support:

```bash
# Start the container under the custom seccomp profile
podman compose up -d
podman compose exec mazewall ./gradlew test
```

> [!IMPORTANT]
> **Podman Native Integration:** This project is optimized for **rootless Podman**.
>
> Standard `security_opt: seccomp=...` triggers a bug in some orchestrators where the full JSON profile is passed as a string over the socket, causing a "file name too long" (`ENAMETOOLONG`) error. We bypass this using the Podman-native annotation `io.podman.annotations.seccomp` in `compose.yml`.

> **Note on Container Security:** Rather than running completely unconfined (which is insecure), `mazewall` includes a custom [podman-seccomp.json](podman-seccomp.json) profile that is automatically configured in [compose.yml](compose.yml). This profile whitelists `seccomp(2)` filter stacking, enabling the JVM inside the container to apply nested thread-level policies while keeping the container fully isolated from the host.

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

## Demos

### 🛡️ [Real-World CVE Exploitation Demo](demo/vulnerable-app/README.md)
A comprehensive Spring Boot 3.x integration showing how `mazewall` blocks real-world exploits (Log4Shell, SSRF, XXE, etc.). The demo includes a fully-automated orchestration script [run_vulnerable_app_demo.sh](run_vulnerable_app_demo.sh) that executes all 11 exploit vectors and compiles a comparative report.

### 🧩 [Interactive Core Showcase](demo/README.md)
The interactive showcase demonstrating:
- **`unsafe` vs `safe`:** Direct comparison of an exploit's impact with and without `mazewall` containment.
- **`profile` & Enforce:** Automated `USER_NOTIF` profiling of a complex workload.
- **Async Seccomp Bypass Mitigation:** How `mazewall` uses **Landlock LSM** to cage asynchronous `io_uring` file operations that typically bypass thread-scoped Seccomp filters.

---

## Built-In Policies

| Policy                | Blocked Syscalls / Primitives                                                                                                                                                                                                                                                                                                                              | Best Use Case                                                        |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `Policy.NO_EXEC`      | `execve`, `execveat`, `fork`, `vfork`, `memfd_create`, `io_uring_setup`, `io_uring_enter`, `ptrace`, `init_module`, `finit_module`                                                                                                                                                                                                                         | Process-wide startup lockdown baseline.                              |
| `Policy.NO_NETWORK`   | `connect`, `sendto`, `sendmsg`, `socket`, `bind`, `listen`, `accept`, `accept4`, `io_uring_setup`, `io_uring_enter`                                                                                                                                                                                                                                       | Data parsers that require local filesystem access but no internet.   |
| `Policy.PURE_COMPUTE` | All network and execution blocks + `open`, `openat`, `openat2`, `rename`, `mkdir`, `chmod`, `chown`, `umask`, `truncate`, `process_vm_writev`, `userfaultfd`, `unshare`, `setns`, `mount`, `pivot_root`, `chroot`, `bpf`, `io_uring_enter`; `mmap`/`mprotect` with `PROT_EXEC` and non-thread `clone` via BPF; `prctl` restricted to safe options via BPF | Algorithmic worker pools (image decoding, cryptographic operations). |
| `Policy.STRICT_SANDBOX` | Base: `PURE_COMPUTE` + allows JVM classpath read.                                                                                                                                                                                                                                                                                                         | High-security workers preventing lazy classloading deadlocks.        |

## System Call Reference

When designing custom security policies, you should consult the authoritative Linux documentation for each system call.

*   **Linux Man Pages:** Use `man 2 <syscall_name>` in your terminal (e.g., `man 2 prctl`, `man 2 seccomp`) to read the exact signature, argument descriptions, and potential error codes (`errno`).
*   **Online Reference:** The [man7.org Section 2](https://man7.org/linux/man-pages/dir_section_2.html) portal provides the most up-to-date web-based version of the Linux manual pages.
*   **Architecture Tables:** For architecture-specific syscall numbers (ID mapping), refer to [syscalls.me](https://syscalls.me/) or [filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/).

---

## Critical JVM Constraints

* **Loom Virtual Thread Contamination:** Thread-scoped seccomp sandboxes the underlying OS thread. Since virtual threads share OS carrier threads via a ForkJoinPool, applying a filter inside a virtual thread will permanently "poison" that carrier thread. `mazewall` explicitly detects virtual threads at runtime and throws `IllegalStateException` to prevent this bypass.
* **GC & Safepoint Deadlock Risk:** Custom policies must never block JVM coordination syscalls (`futex`, `sched_yield`, `rt_sigreturn`, `madvise`, `gettid`). Blocking synchronization primitives will lead to VM-wide deadlocks during the next GC cycle.
* **Shared-Memory ACE Bypass:** Thread-scoped seccomp is not an absolute sandbox. If an attacker achieves native Arbitrary Code Execution (ACE) on a thread, they can manipulate the shared JVM heap/stack to corrupt unrestricted carrier or parent threads. Combine with process-wide `NO_EXEC` (Tier 1) for strong defense-in-depth.

---

## License

This project is licensed under the Apache License 2.0.
