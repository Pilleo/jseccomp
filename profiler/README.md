# mazewall-profiler

**Automatically discover the exact syscall policy your workload needs — no guesswork, no deadlocks.**

Figuring out which system calls and filesystem paths your code uses by hand is error-prone and dangerous. Block the wrong coordination syscall (`futex`, `rt_sigreturn`) and the entire JVM deadlocks at the next GC cycle. The profiler eliminates this problem by observing your workload during a test run and generating the exact `Policy` DSL you need.

> **Dev/test only.** Do not include the `:profiler` module as a production runtime dependency.

---

## Quick Start

```kotlin
import io.mazewall.profiler.Profiler

// 1. Wrap your workload in a profile block during a test
val result = Profiler.profile {
    myXmlParser.parse(untrustedInput)
}

// 2. Print the generated policy DSL
println(result.behavior.toDsl())
```

**Output:**
```kotlin
Policy.builder()
    .base(Policy.NO_NETWORK)
    .allowFsRead("/app/schemas")
    .allowFsRead("/app/config.xml")
    .allowJvmClasspath()
    .build()
```

**3. Paste it into your application:**
```kotlin
val safePool = ContainedExecutors.wrap(
    Executors.newFixedThreadPool(4),
    result.behavior.toPolicy()   // or paste the DSL above
)
```

That's it. The kernel now enforces exactly what the profiler observed — nothing more.

---

## The Problem It Solves

A `Policy` is a BPF program loaded into the Linux kernel. Writing one by hand means:
- Knowing the exact syscall numbers for your CPU architecture
- Anticipating every path your library touches during lazy classloading
- Knowing which JVM coordination calls (`futex`, `sched_yield`, `madvise`) must never be blocked
- Getting it wrong → JVM deadlock, no stack trace, no recovery

The profiler handles all of this by observing the actual execution.

---

## Profiling Tiers

Three profiling strategies are available depending on your environment and what you need to discover:

| Tier | API | Best For | Privilege |
|------|-----|----------|-----------|
| **S (Recommended)** | `Profiler.profile { }` | Standard synchronous workloads, accurate syscall + path capture | Unprivileged |
| **A (Iterative)** | `IterativeProfiler.profile(basePolicy) { }` | `io_uring`-based workloads, Landlock path discovery without a daemon | Unprivileged |
| **P (strace)** | `StraceProfiler` | Legacy environments, descendant subprocess tracing | `ptrace_scope ≤ 1` |

### Tier S — `USER_NOTIF` Daemon (Recommended)

The default. An out-of-process daemon intercepts every syscall on the profiled thread via the kernel's `SECCOMP_USER_NOTIF` interface. It captures both the syscall number and the resolved filesystem path (via `/proc/<pid>/fd/`), then releases the thread and lets it continue.

**Limitations:**
- `io_uring` operations bypass syscall interception (see Tier A / Tier H workaround in [article2-profiler.md](../docs/presentation/article2-profiler.md))
- Requires `ptrace_scope ≤ 1` or a container with `SYS_PTRACE` if cross-process path resolution is needed

### Tier A — Iterative Landlock Profiler

Runs the workload under a progressively tightening Landlock policy. When a path access is denied, the path is whitelisted and the workload retries. Converges to the minimal filesystem ruleset.

> [!CAUTION]
> Because the workload restarts on each violation, any side effects (DB writes, outbound messages) will execute multiple times. Use idempotent workloads or mock external systems.

```kotlin
val compiledPolicy = IterativeProfiler.profile(Policy.builder().build()) {
    targetWorkload()
}
println(compiledPolicy.allowedFsReadPaths)
```

### Tier P — Descendant `strace` Profiler

Wraps a subprocess under `strace -f` and parses the syscall log stream asynchronously. Useful for tracing legacy workloads or child JVM processes without modifying their code.

---

## SBoB Output

The profiler's final output is a `BillOfBehavior` — a structured behavioral contract that lists observed syscalls, filesystem paths, and network endpoints. This is the JVM-native contribution to the [SBoB (Software Bill of Behavior)](../docs/presentation/article.md) concept.

```kotlin
val behavior: BillOfBehavior = result.behavior

behavior.syscalls        // Set<Syscall>  — every syscall observed on the profiled thread
behavior.opens           // Set<String>   — every filesystem path opened
behavior.fsWritePaths    // Set<String>   — every path written to
behavior.networkEndpoints // Set<String>  — every socket destination

behavior.toPolicy()      // → Policy (ready to pass to ContainedExecutors.wrap)
behavior.toDsl()         // → String (Kotlin DSL to paste into your codebase)
behavior.toJson()        // → String (machine-readable SBoB JSON)
```

---

## Technical Architecture

*(Internal details for contributors — skip if you just want to use the profiler.)*

- **`Profiler` / `ProfilerDaemon`**: Implements the out-of-process `USER_NOTIF` engine. The daemon receives the seccomp listener FD via UNIX socket `SCM_RIGHTS` passing, intercepts trapped syscalls, resolves paths via `process_vm_readv`, and sends an ACK back to release the worker thread.
- **`ProfilerTraceListener`**: Bridge between the daemon and the JVM — receives `TraceEvent`s and correlates them with JVM stack traces via `ThreadRegistry`.
- **`IterativeProfiler`**: Implements the deny-and-retry Landlock learning loop.
- **`StraceProfiler` / `StraceWorkloadRunner`**: Spawns target workloads under `strace -f` and parses the log stream.
- **`BobCompiler` / `BillOfBehavior`**: Deduplicates raw high-frequency syscall streams and compiles the structured behavioral contract.

For the critical ACK loop architecture and deadlock prevention rules, see [architectural_map.md](../docs/internals/architectural_map.md).

---

## Testing

```bash
# Unit tests (no kernel interaction)
./gradlew :profiler:test

# Full integration suite (requires Podman, Linux 5.0+)
./scripts/run_tests.sh :profiler:integrationTest
```
