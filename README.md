# mazewall

[![CI](https://github.com/Pilleo/jseccomp/actions/workflows/ci.yml/badge.svg)](https://github.com/Pilleo/jseccomp/actions/workflows/ci.yml)
[![JitPack](https://jitpack.io/v/Pilleo/jseccomp.svg)](https://jitpack.io/#Pilleo/jseccomp)

**Kernel-enforced thread-scoped sandboxing for JVM applications.**

---

> [!WARNING]
> **Experimental Research Proof-of-Concept.** This library is an untested research prototype exploring thread-scoped sandboxing on modern Linux kernels. It is not production-ready, contains known stability and security limitations, and must **not** be deployed in production environments.

---

## Start Here

| I want to… | Go to |
|------------|-------|
| Understand what mazewall is and why it exists | Keep reading ↓ |
| Run the live exploit demo | [Demo README](demo/README.md) |
| Integrate mazewall into my Spring/Quarkus app | [enforcer README](enforcer/README.md) → Quick Start |
| Understand the kernel internals and threat model | [Article Series](#technical-articles) |
| Contribute or modify the codebase | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## Technical Articles


To read the core research and threat model analysis behind `mazewall`, start with our deep-dive article series:

| Part | Title | Core Focus |
| :--- | :--- | :--- |
| **Part 1** | [Do You Really Know What Your App Is Doing at Runtime?](docs/presentation/article.md) | SBoB concepts, eBPF, Linux sandboxing primitives (`Seccomp`, `Landlock`, LSM). |
| **Part 2** | [Let Your Code Build Its Own Sandbox](docs/presentation/article2-profiler.md) | Dynamic profiling, `USER_NOTIF` daemon, Iterative Landlock Path Discovery. |
| **Part 3** | [Thread-Scoped JVM Containment: The Mechanics](docs/presentation/article3-enforcement.md) | FFM native bridge, errno races, GC safepoint deadlocks, Loom VT carrier issues. |
| **Part 4** | [Mazewall: The Attacks We Actually Stop](docs/presentation/article4-attacks.md) | Exploitation defense (Log4Shell, fileless malware, JIT exec memory, `io_uring` evasion). |
| **Part 5** | [Generating an SBoB for Java: What's Missing](docs/presentation/article5-graalvm.md) | The Merge Fallacy, dynamic classloading noise, GraalVM AOT Closed-World compilation. |
| **Part 6** | [Beyond the Thread: Isolates, WebAssembly, and Tooling](docs/presentation/article6-isolates.md) | Thread-hopping bypass, GraalVM Isolates, WASI Component Model (Endive), sidecar portals. |

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

## Motivation: Developer-Centric Security & The "Friction Budget"

`mazewall` was created to explore how to build usable, automated sandboxing directly into the JVM codebase. Security only succeeds when it integrates cleanly with developer workflows. As highlighted by Matthew Green and Matthew Smith in [*"Developers are Not the Enemy!: The Need for Usable Security APIs"*](https://ieeexplore.ieee.org/document/7676144) and supported by Google's yearly [**DORA Reports**](https://dora.dev/publications/), reducing developer friction and shifting security left is critical for both safety and velocity.

For a complete analysis of the "Friction Budget" theory and behavioral contracts, see [Part 1: Do You Really Know What Your App Is Doing?](docs/presentation/article.md).

## How It Works

`mazewall` uses **Linux Seccomp-BPF** and **Landlock LSM** to install unprivileged security filters. The implementation is 100% pure Kotlin for the JVM, utilizing the **Foreign Function & Memory (FFM) API** (JDK 22+) to interface directly with the kernel without the need for native C dependencies.

Prohibited syscalls trigger a `SECCOMP_RET_ERRNO` with `EPERM` (or Landlock file permissions return `EACCES`), causing standard Java I/O or JNI calls to fail. The executor wrapper catches these failures, matches them, and throws a `ContainmentViolationException`.

---

## Use Cases

### 1. Runtime Attack Prevention
The canonical use case: wrap thread pools that process untrusted input (user uploads, API payloads, deserialized objects) with a policy that blocks process spawning, shellcode injection, and network exfiltration. A compromised library inside the sandbox hits `EPERM` and cannot escape.

### 2. Behavioral Attestation for Regulated Data

This is a less obvious but equally important use case. `mazewall` can be used to **prove** — at the kernel level, not by software assertion — that sensitive data was handled with strict behavioral constraints.

Consider a thread pool that decrypts and processes PII, payment card data, or legally privileged documents. By wrapping it with `Policy.PURE_COMPUTE_UNSAFE` and a Landlock path restriction:

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

### Roadmap: Native `SIGSYS` Trapping (`SECCOMP_RET_TRAP`)
To avoid parsing JVM exception message strings (since Java `IOException` does not expose raw errno values), the roadmap includes implementing a native `SIGSYS` signal trap handler via the FFM API. This will register a native C signal handler to capture violation metadata, advance the instruction pointer past the blocked `syscall` instruction, and map violations deterministically to Java exceptions. Refer to [containment_design.md](docs/internals/containment_design.md) for detailed architecture and the scalar return value memory-safety caveats.

---

## Kernel Compatibility

`mazewall` utilizes modern Linux kernel features. While the library can be **compiled** on older kernels (like JitPack's Kernel 4.4), the **runtime features** available depend on your host's kernel version:

| Feature | Min Kernel | Status on 4.4 (JitPack) |
| :--- | :--- | :--- |
| **Seccomp-BPF** (Basic) | 3.5 | ✅ Available |
| **Seccomp Syscall** | 3.17 | ✅ Available |
| **io_uring** | 5.1 | ❌ Unavailable |
| **Seccomp USER_NOTIF** | 5.0 | ❌ Unavailable (Profiler disabled) |
| **Landlock LSM** (Filesystem) | 5.13 | ❌ Unavailable |
| **Landlock Network Control** | 6.7 | ❌ Unavailable |

> [!NOTE]
> **Seccomp-BPF vs. Seccomp Syscall:** 
> * **Seccomp-BPF** is the kernel feature (since 3.5) that allows filtering syscalls via BPF programs.
> * **Seccomp(2) Syscall** is the modern API (since 3.17) that enables advanced features like **`TSYNC`** (synchronizing filters across all JVM threads), which is the primary mechanism `mazewall` uses for process-wide lockdowns.

> [!IMPORTANT]
> **Recommended Kernel:** For the full security suite (including Landlock filesystem isolation and `io_uring` bypass mitigation), we recommend **Linux Kernel 6.2+**.

---

## Installation

`mazewall` is available via **JitPack** (Community) and **GitHub Packages** (Official).

### 📦 Option 1: JitPack (Easiest)

Add the JitPack repository and the dependency to your build:

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    // Core enforcement engine
    implementation("com.github.Pilleo.jseccomp:enforcer:main-SNAPSHOT")
}
```

### 🛡️ Option 2: GitHub Packages (Production-Grade)

For higher reliability and verified builds, use GitHub Packages.

1. **Authenticate:** Add your GitHub credentials to `settings.gradle.kts` (requires a Personal Access Token with `read:packages` scope):

```kotlin
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/Pilleo/jseccomp")
            credentials {
                username = "YOUR_GITHUB_USERNAME"
                password = "YOUR_GITHUB_TOKEN"
            }
        }
    }
}
```

2. **Add Dependency:**
```kotlin
dependencies {
    implementation("io.mazewall:enforcer:0.1.0-SNAPSHOT")
}
```

---

## Quick Start


### 1. Run the Tests

To run the integration suite directly on a Linux host with a compatible kernel (6.2+):

```bash
./gradlew test
```

Alternatively, you can run the tests in an isolated environment using **Podman** (which includes a custom seccomp profile for nested sandboxing):

```bash
# Start the container under the custom seccomp profile
podman compose -f infra/dev/compose.yml up -d
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew test
```

> [!IMPORTANT]
> **Podman Native Integration:** This project is optimized for **rootless Podman**.
>
> Standard `security_opt: seccomp=...` triggers a bug in some orchestrators where the full JSON profile is passed as a string over the socket, causing a "file name too long" (`ENAMETOOLONG`) error. We bypass this using the Podman-native annotation `io.podman.annotations.seccomp` in `infra/dev/compose.yml`.

> **Note on Container Security:** Rather than running completely unconfined (which is insecure), `mazewall` includes a custom [podman-seccomp.json](infra/dev/podman-seccomp.json) profile that is automatically configured in [infra/dev/compose.yml](infra/dev/compose.yml). This profile whitelists `seccomp(2)` filter stacking, enabling the JVM inside the container to apply nested thread-level policies while keeping the container fully isolated from the host.
>
> > [!NOTE]
> > **Container Profiles:** This command uses the development profile (`infra/dev/compose.yml`) which runs the test environment. Do not confuse it with the CVE demo profile (`demo/vulnerable-app/compose.yml`) used to run the vulnerable Spring Boot app.

### 2. Configure a Path-Restricted Thread Pool (Landlock)

```kotlin
// Restrict filesystem access, block process execution, and disable network
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE_UNSAFE)
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
A comprehensive Spring Boot 3.x integration showing how `mazewall` blocks real-world exploits (Log4Shell, SSRF, XXE, etc.). The demo includes a fully-automated orchestration script [scripts/run_vulnerable_app_demo.sh](scripts/run_vulnerable_app_demo.sh) that executes all 11 exploit vectors and compiles a comparative report.

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
| `Policy.PURE_COMPUTE_UNSAFE` | All network and execution blocks + `open`, `openat`, `openat2`, `rename`, `mkdir`, `chmod`, `chown`, `umask`, `truncate`, `process_vm_writev`, `userfaultfd`, `unshare`, `setns`, `mount`, `pivot_root`, `chroot`, `bpf`, `io_uring_enter`; `mmap`/`mprotect` with `PROT_EXEC` and non-thread `clone` via BPF; `prctl` restricted to safe options via BPF | Algorithmic worker pools (image decoding, cryptographic operations). |
| `Policy.PURE_COMPUTE` | Base: `PURE_COMPUTE_UNSAFE` + allows JVM classpath read.                                                                                                                                                                                                                                                                                                         | High-security workers preventing lazy classloading deadlocks.        |

## System Call Reference

When designing custom security policies, you should consult the authoritative Linux documentation for each system call.

*   **Linux Man Pages:** Use `man 2 <syscall_name>` in your terminal (e.g., `man 2 prctl`, `man 2 seccomp`) to read the exact signature, argument descriptions, and potential error codes (`errno`).
*   **Online Reference:** The [man7.org Section 2](https://man7.org/linux/man-pages/dir_section_2.html) portal provides the most up-to-date web-based version of the Linux manual pages.
*   **Architecture Tables:** For architecture-specific syscall numbers (ID mapping), refer to [filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/).

---

## Critical JVM Constraints

* **Loom Virtual Thread Contamination:** Thread-scoped seccomp sandboxes the underlying OS thread. Since virtual threads share OS carrier threads via a ForkJoinPool, applying a filter inside a virtual thread will permanently "poison" that carrier thread. `mazewall` explicitly detects virtual threads at runtime and throws `IllegalStateException` to prevent this bypass.
* **GC & Safepoint Deadlock Risk:** Custom policies must never block JVM coordination syscalls (`futex`, `sched_yield`, `rt_sigreturn`, `madvise`, `gettid`). Blocking synchronization primitives will lead to VM-wide deadlocks during the next GC cycle.
* **Shared-Memory ACE Bypass:** Thread-scoped seccomp is not an absolute sandbox. If an attacker achieves native Arbitrary Code Execution (ACE) on a thread, they can manipulate the shared JVM heap/stack to corrupt unrestricted carrier or parent threads. Combine with process-wide `NO_EXEC` (Tier 1) for strong defense-in-depth.

---

## License

This project is licensed under the Apache License 2.0.
