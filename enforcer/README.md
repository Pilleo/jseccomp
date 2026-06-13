# mazewall-enforcer

**Core runtime engine for thread-scoped and process-wide syscall sandboxing.**

This subproject implements unprivileged sandboxing using Linux **Seccomp-BPF** and **Landlock LSM** through the JDK **Foreign Function & Memory (FFM) API** (JDK 22+). It is designed to be a zero-dependency security layer for production JVM services.

> [!WARNING]
> **Security boundary: read this before deploying.**
> `ContainedExecutors.wrap()` (Tier 2) restricts syscalls on the *calling* thread. It stops data-plane attacks (SSRF, XXE, path traversal, fileless malware) on that thread. It does **not** isolate arbitrary Java code — an attacker who can execute Java logic (e.g., via deserialization RCE) can hop to an unrestricted thread pool using `CompletableFuture.runAsync(...)` or virtual threads.
>
> **Always install the Tier 1 process-wide baseline first:**
> ```kotlin
> ContainedExecutors.installOnProcess(Policy.NO_EXEC) // call once in main()
> ```
> See [SECURITY_CONSIDERATIONS.md](../docs/internals/SECURITY_CONSIDERATIONS.md) for the complete threat model.

---

## Technical Architecture

- **FFM Native Bindings:** Uses the JDK Foreign Function & Memory API to map native Linux system calls directly from Kotlin, eliminating the need for JNI or dynamic C library dependencies.
- **BPF Program Compilation:** Generates deterministic BPF instruction arrays. The compiler uses an inverted linear scan to handle complex syscall policies within the 8-bit seccomp relative jump limitation.
- **Thread-Scoped Enforcement:** Applies filters to individual OS threads via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`. Filters are inherited by child threads created after installation.
- **Filesystem & Network Isolation:** Integrates Landlock LSM to restrict filesystem paths and TCP ports. It automatically handles Landlock ABI negotiation and authorizes the JVM classpath for lazy classloading.
- **Atomic Synchronization (`TSYNC`):** Leverages the `SECCOMP_FILTER_FLAG_TSYNC` flag to synchronize filters across all existing threads in the process during initialization.

---

## Installation

Add `mazewall-enforcer` to your project via **JitPack** or **GitHub Packages**.

### Gradle (Kotlin)

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.Pilleo.jseccomp:enforcer:main-SNAPSHOT")
}
```

---

## Core API Usage

The primary entry point is `ContainedExecutors`, which provides wrappers for standard `ExecutorService` instances.

### 1. Wrapping an Executor

```kotlin
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.Policy

val policy = Policy.builder()
    .base(Policy.NO_EXEC)
    .allowFsRead("/var/tmp/incoming")
    .allowJvmClasspath()
    .build()

val sandboxed = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    policy
)
```

### 2. Process-Wide Baseline

```kotlin
// Apply a NO_EXEC baseline to the entire JVM process early in main()
ContainedExecutors.installOnProcess(Policy.NO_EXEC)
```

---

## Critical Safety Invariants

To prevent JVM deadlocks and stability issues, `:enforcer` implements several internal safeguards:

- **Loom Carrier Protection:** Seccomp filters bind to OS threads. `:enforcer` detects if installation is attempted within a Virtual Thread (Loom) and throws `IllegalStateException` to prevent poisoning shared carrier threads.
- **Coordination Whitelisting:** JVM coordination syscalls (`futex`, `sched_yield`, `rt_sigreturn`, `madvise`, `gettid`, etc.) are always whitelisted. Blocking these syscalls would deadlock the JVM during GC safepoints.
- **Initialization Ordering:** Landlock rulesets are always initialized before Seccomp filters, as active Seccomp rules would otherwise block the Landlock configuration syscalls.

---

## Testing

Tests require a Linux host (6.2+) or the provided dev container environment.

```bash
# Unit tests (no kernel interaction)
./gradlew :enforcer:test

# Full check including integration tests (requires Podman)
./scripts/run_tests.sh :enforcer:integrationTest
```
