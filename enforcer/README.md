# mazewall-enforcer

**The core, production-grade security containment and enforcement engine of mazewall.**

This subproject implements unprivileged, thread-scoped and process-wide sandboxing using Linux **Seccomp-BPF** and **Landlock LSM** through the JDK **Foreign Function & Memory (FFM) API** (JDK 22+). It contains zero diagnostic or profiling overhead, ensuring high performance and minimal classpath footprints for production services.

---

## Technical Highlights

- **FFM Native Bindings:** 100% pure Java/Kotlin FFM integration mapping native Linux system calls without dynamic C library dependencies.
- **Inverted Linear BPF Compiler:** Compiles security rules into deterministic BPF instruction arrays. Leverages an inverted linear scan algorithm to bypass the 8-bit seccomp relative jump limitation when parsing long syscall policies.
- **Microsecond Thread Scoping:** Restricts thread execution capabilities dynamically by setting process-wide or thread-scoped filters during runtime execution.
- **Landlock Path Restriction:** Automatically negotiates the highest supported Landlock ABI, authorizes necessary classpaths for lazy classloading, and cages directory operations.
- **Synchronized Multithreading (`TSYNC`):** Installs filters process-wide safely across all existing threads by using the kernel's `SECCOMP_FILTER_FLAG_TSYNC`.

---

## Architectural Layout

The codebase inside `:enforcer` is structured into three clear enforcement layers:

1. **System Call Binder (`LinuxNative`, `Arch`, `Syscall`)**: Translates Kotlin enums and FFM layouts into kernel syscall identifiers for `x86_64` and `aarch64`. Captures thread-local `errno` safely into confined memory segments immediately following a native execution block.
2. **BPF Instruction Compiler (`BpfFilter`, `PureJavaBpfEngine`)**: Compiles high-level policies into BPF assembly instructions, including nuanced argument-inspection arrays for `mmap`/`mprotect` (PROT_EXEC restrictions), `clone` (restricting non-thread thread spawning), and `prctl` (whitelisting safe operation flags).
3. **Public API & Runtime Caging (`ContainedExecutors`, `Policy`)**: Provides thread pool wrappers (`ExecutorService`) and composable policy builders that enforce sandboxing rules transparently.

---

## Installation

Add `mazewall-enforcer` to your project via **JitPack**.

### Gradle (Kotlin)

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.mazewall:mazewall:enforcer-SNAPSHOT")
}
```

---

## Quick Start Example

Wrap your untrusted, data-parsing executor service with process or thread-scoped limitations:

```kotlin
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.Policy

// Build a restrictive, path-aware policy
val securePolicy = Policy.builder()
    .base(Policy.PURE_COMPUTE_UNSAFE)
    .allowJvmClasspath()              // Permits JVM lazy class loading
    .allowFsRead("/var/tmp/incoming") // Read permission only
    .build()

// Wrap your thread pool with the policy
val sandboxedExecutor = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    securePolicy
)

// Any execution inside the wrapped executor is now contained at the kernel level
sandboxedExecutor.submit {
    // This runs successfully:
    val contents = File("/var/tmp/incoming/data.json").readText()
    
    // This will trigger a ContainmentViolationException (EACCES / EPERM):
    File("/etc/passwd").readText()
}
```

---

## Key Safety Invariants

- **Loom Carrier Poisoning Prevention:** Because seccomp filters bind permanently to the host OS thread, calling seccomp filters inside virtual threads will permanently "poison" the shared carrier thread. `:enforcer` intercepts all installation calls made from virtual threads and immediately throws `IllegalStateException` to prevent container escape.
- **Safepoint Deadlock Safeguards:** Core JVM thread coordination calls (such as `futex`, `sched_yield`, `rt_sigreturn`, `madvise`, `gettid`, and `clone` with `CLONE_THREAD`) are strictly whitelisted and prohibited from being blocked. Restricting these calls will deadlock the JVM permanently during the next safepoint / Garbage Collection cycle.
- **Landlock Precedence:** When combining Landlock and Seccomp sandboxes, **Landlock must always be initialized first**. Seccomp rules block the landlock configuration calls once loaded.

---

## Setup & Testing

Compile the module or run tests. Tests require a Linux host (6.2+) or the provided Podman environment.

```bash
# Compile core module
./gradlew :enforcer:build

# Run tests directly
./gradlew :enforcer:test

# Run tests in Podman
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew :enforcer:test
```
