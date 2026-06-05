# mazewall-profiler

**The developer diagnostic, trace capture, and security policy-generation engine of mazewall.**

This subproject implements powerful, unprivileged trace profiling engines meant **strictly for development and testing environments**. By actively monitoring JVM system calls and filesystem access, it generates accurate, optimized `Policy` configurations automatically, minimizing manual BPF ruleset compilation.

---

## Technical Highlights

`:profiler` supports three specialized profiling tiers:

### 1. Tier S: Out-of-Process `USER_NOTIF` Daemon
- Uses the kernel's modern BPF user notification interface (`SECCOMP_FILTER_FLAG_NEW_LISTENER`).
- Captures system calls on sandboxed threads, blocks the thread, and transfers the notification file descriptor to an out-of-process `ProfilerDaemon` using UNIX socket descriptor passing (`SCM_RIGHTS`).
- Resolves target filesystem paths in real-time by inspecting `/proc/<tracee-pid>/fd/` and `/proc/<tracee-pid>/mem`.
- Implements an asynchronous ACK protocol (`0x41` loop) to release tracee threads securely via `SECCOMP_IOCTL_NOTIF_SEND` without triggering JVM-wide GC safepoint deadlocks.

### 2. Tier A: Iterative Landlock Profiler
- The only unprivileged, zero-daemon way to trace Landlock directories and `io_uring` setups.
- Spawns the workload under progressively restricted Landlock filters, intercepts JVM `AccessDeniedException` violations, whitelists the path dynamically, and retries the workload until execution completes cleanly.

### 3. Tier P: Descendant Process `strace` Profiler
- Bypasses Linux kernel Yama `ptrace_scope = 1` boundaries under unprivileged, rootless containers.
- Spawns target workloads inside a child JVM executed directly under `strace -f`, allowing standard user space processes to trace their own descendants.
- Parses `strace` log streams asynchronously to extract file reads, writes, and socket destinations, while automatically filtering out noisy JVM boot/compilation activity.

---

## Architectural Layout

- **`io.mazewall.profiler`**: Contains `Profiler` and `ProfilerDaemon`, implementing the out-of-process `USER_NOTIF` tracing engine, Unix socket communication, and trace listener synchronization.
- **`io.mazewall.landlock`**: Contains `IterativeProfiler` implementing progressive directory path discovery.
- **`io.mazewall.profiler` (Strace)**: Contains `StraceProfiler` and `StraceWorkloadRunner` which manage descendant subprocess parsing.
- **Compiler & Data Models (`BillOfBehavior`, `BobCompiler`, `TraceEvent`)**: Collates raw, high-frequency, noisy syscall streams, deduplicates redundant events, and compiles a structured Bill of Behavior (SBoB) that directly generates Kotlin DSL policies.

---

## Quick Start Example

Profile a workload dynamically under the recommended `USER_NOTIF` listener to auto-generate a security policy:

```kotlin
import io.mazewall.profiler.Profiler
import java.io.File

// 1. Profile your workload inline
val result = Profiler.profile {
    val dataFile = File("/var/tmp/data.csv")
    dataFile.writeText("sample data")
    println(dataFile.readText())
}

// 2. Compile your pristine, auto-generated policy
val behavior = result.behavior
val policy = behavior.toPolicy() // Pre-built Policy ready for enforcer wrap!

// 3. Generate Kotlin DSL code for your configuration files
val dslCode = behavior.toDsl()
println(dslCode)
```

## Profiling Tiers

| Tier | API | Kernel Requirement | Best For |
|------|-----|--------------------|----------|
| **S (Recommended)** | `Profiler.profile { }` | Linux 5.0+ (`USER_NOTIF`) | In-process workloads with accurate stack traces |
| **A** | `IterativeProfiler` | Any | Landlock path discovery, no daemon required |
| **P** | `StraceProfiler` | `ptrace_scope ≤ 1` | Legacy environments, subprocess tracing |

---

## Setup & Testing

Running the tests requires a kernel $\ge 5.0$ (for `USER_NOTIF`) and nested seccomp support:

```bash
# Compile profiler module
./gradlew :profiler:build

# Run verification suite in rootless podman
podman compose exec mazewall ./gradlew :profiler:test
```
