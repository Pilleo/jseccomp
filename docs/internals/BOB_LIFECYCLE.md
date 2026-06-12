# Bill of Behavior (BoB) Determinants & Portability

A **Bill of Behavior (BoB)**—the set of system calls and filesystem paths required for a program to function—is not a static artifact. It is a snapshot of a multi-dimensional execution environment. This document outlines the factors that influence a BoB across different languages (Java, Rust, C++, Go) and why a BoB must be re-validated whenever the execution "tuple" changes.

---

## 1. The Core Determinants

Regardless of the programming language, seven primary factors dictate which system calls a binary will issue.

### A. The Language Runtime & Standard Library
The compiler itself rarely generates syscalls; the **Standard Library** (e.g., Kotlin `std`, Rust `std`, C++ `libc++`) is the primary "syscall factory."
*   **Version Shift:** Upgrading a compiler (e.g., Rust 1.70 to 1.80) often updates the standard library. A newer version may switch from `openat` to `openat2` for better security or performance, instantly breaking a restrictive BoB.
*   **Feature Detection:** Modern libraries often perform "probing" at startup (e.g., checking if `io_uring` is available). These probes generate syscalls that may only appear on certain kernels.

### B. Hardware Architecture (ISA)
Syscall numbers and availability are architecture-specific.
*   **x86_64 vs. ARM64:** ARM64 often lacks "legacy" syscalls found on x86_64 (like `stat` or `rename`), using modern equivalents (`statx`, `renameat2`) instead.
*   **ABI Nuances:** Parameters may be passed in different registers, affecting how Seccomp-BPF filters must be constructed.

### C. OS Kernel & Features
The kernel provides the "capabilities" the program consumes.
*   **Fast Paths:** On a Linux 6.x kernel, a JVM or Rust runtime may utilize `io_uring` or `epoll_pwait2`. On a Linux 5.x kernel, it will fall back to `epoll_wait`.
*   **vDSO (Virtual Dynamic Shared Object):** Calls like `gettimeofday` may be handled in userspace (0 syscalls) on one kernel but require a real syscall on an older one. This makes these calls "invisible" during profiling on modern machines.

### D. Optimization Levels (`-O0` to `-O3`)
Optimizations change the **Memory and Locking behavior** of a program.
*   **Stack Promotion:** High optimization (`-O3`) uses escape analysis to keep data on the stack, potentially eliminating `mmap`, `brk`, or `sbrk` calls seen in debug builds.
*   **Inlining & Merging:** Link-Time Optimization (LTO) can merge multiple small `write` calls into a single one or optimize away `futex` calls by reducing lock contention.

### E. Linking Strategy (Static vs. Dynamic)
*   **Dynamic (`glibc`):** The binary relies on the host's C library. If the production host has a newer `glibc` than the build machine, the app may start issuing "modern" syscalls that weren't captured during profiling.
*   **Static (`musl`):** The syscall logic is embedded in the binary. This is more portable but results in a larger BoB because the entire runtime's potential syscalls are "visible."

### F. Runtime Environment & Permissions
*   **Container Runtimes:** Podman, Docker, and K8s apply their own Seccomp profiles and namespace restrictions. If a runtime masks `/proc`, the program may attempt fallback syscalls that lead to a different BoB.
*   **Privileges:** A process with `CAP_NET_ADMIN` may issue different socket-related syscalls than an unprivileged one.

### G. Execution "Laziness" & Determinism
*   **JIT Warmup:** In managed languages (Java, Node.js), some syscalls (like `mmap(PROT_EXEC)`) only occur after a code path becomes "hot" and the JIT compiler triggers.
*   **Edge Case Inputs:** The first time an app handles a specific locale, timezone, or encrypted payload, it may load a native library or configuration file for the first time.

---

## 2. Language-Specific Nuances

| Language | Primary BoB Determinant |
| :--- | :--- |
| **Java / Kotlin** | GC Selection (`G1` vs `ZGC`), JIT Tiering, and FFM usage. |
| **Rust** | `panic` strategy (`unwind` vs `abort`), Crate dependencies (e.g., `tokio`). |
| **Go** | The runtime's "M:N" scheduler and its heavy use of `futex` and `nanosleep`. |
| **C++** | The specific `libc` provider (GNU vs LLVM) and template instantiation depth. |

---

## 3. The Portability Paradox

> [!WARNING]
> **A BoB generated on Machine A is NOT guaranteed to work on Machine B.**

Because of the determinants listed above, a BoB is only as reliable as the environment it was captured in.

---

## 4. Improving BoB Reliability: JIT vs. AOT

The execution mode of the language runtime is the single greatest factor in BoB stability.

### A. The AOT Advantage (GraalVM Native Image)
A **GraalVM Native Image (AOT)** results in a significantly more reliable and predictable BoB than a standard JVM (JIT).
*   **Static Memory Floor:** All executable memory is allocated at startup. There is no `mmap(PROT_EXEC)` at runtime because there is no JIT compiler.
*   **Closed-World Assumption:** All reachable code paths and native dependencies are analyzed and linked at build time. The "Syscall Floor" is constant from the first second of execution.
*   **High Reliability:** A BoB generated in a short 5-minute test is almost identical to one needed for a months-long production run.

### B. The JIT Challenge (Standard HotSpot JVM)
In a **JIT environment**, the BoB is a "moving target" due to:
*   **Dynamic Compilation:** The JIT compiler may trigger new `mmap` or `memfd_create` calls hours into execution as it re-optimizes hot paths.
*   **Lazy Loading:** Classes and native libraries are loaded on demand, meaning rare error paths may never be captured during a standard profiling session.

---

## 5. Engineering Strategies for Stable BoBs

To maximize the reliability of your security policies, employ these four patterns:

### 1. The "Union" Strategy (Profile Merging)
Do not rely on a single profiling run. Instead, merge multiple "perspectives":
*   `Final_BoB = BoB_Unit_Tests ∪ BoB_Integration_Tests ∪ BoB_JVM_Floor`.
*   This ensures that both the specific application logic and the background JVM management tasks (GC/JIT) are fully covered.

### 2. Deterministic Warmup (For JIT Runtimes)
Force the runtime to be less "lazy" during the profiling phase:
*   **Flags:** Use `-Xbatch` (disables background compilation) and `-XX:CompileThreshold=1` (force immediate JIT) to "flush out" all compilation-related syscalls in the first few seconds.

### 3. Semantic Syscall Grouping
Avoid whitelisting only the specific syscall seen in the log. Instead, whitelist the **Logical Class**:
*   **Example:** If you see `stat`, also whitelist `fstat`, `lstat`, and `statx`. 
*   **Reason:** Glibc and the kernel may switch between these based on versioning or path length, and a "semantic" whitelist is more portable across OS updates.

### 4. Passive "Audit Mode" in Staging
Before moving to a strict "Fail-Closed" policy in production, run the profiler in an "Audit/Log-only" mode in a staging environment.
*   Monitor for "New" syscalls that weren't captured in the baseline.
*   This captures the "long tail" of lazy or rare syscalls that only appear under real-world traffic patterns.

---

## 6. Operational Recommendations

1.  **Automate Baseline Generation:** Use the `JvmFloorWorkload` and automated profiling tools to make "re-snapping" a zero-effort task.
2.  **Use Tier S for Accuracy:** Prefer binary-accurate profilers (Tier S/BPF) over text-based log parsers (Tier P/Strace) to avoid missing nuanced arguments or asynchronous paths.
3.  **Document the Tuple:** When sharing a `.sbob` or BoB file, always include the environment metadata (JDK version, Kernel version, Arch).
