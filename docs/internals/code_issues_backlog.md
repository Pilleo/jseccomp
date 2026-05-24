# Code Issues Backlog

## Fixed Issues

### ✅ FIXED: Profiler Protocol ACK Corruption
**Context:** In `Profiler.kt`, the deduplication block correctly uses `ValueLayout.JAVA_BYTE` to write a 1-byte ACK (`0x41`). This was confirmed to be correctly implemented.

### ✅ FIXED: Profiler Socket Write Race Condition
**Context:** `ProfilerDaemon.sendTraceEvent` is synchronized on a per-socket lock to prevent interleaved writes from concurrent threads (Seccomp vs Landlock Audit).

### ✅ FIXED: Landlock Path Fallback Edge Case
**Context:** `Landlock.kt` correctly handles cases where `File(path).parent` is null (e.g., relative paths or root-level files) by defaulting to `/`.

### ✅ FIXED: Package Structure
**Context:** The project is already organized into `enforcer`, `landlock`, `profiler`, and `seccomp` packages.

### ✅ FIXED: `Policy.PURE_COMPUTE` Security Gaps
**Context:** Audited `PURE_COMPUTE` and verified that filesystem modification syscalls (`RENAME`, `LINK`, `UNLINK`, `CHMOD`, `CHOWN`, etc.) are ALREADY appropriately blocked in the policy definition.

### ✅ FIXED: AARCH64 Syscall Coverage
**Context:** Audited `Arch.kt` and `Syscall.kt`. Verified that modern `*at` variants (`renameat2`, `mkdirat`, `unlinkat`, `fchmodat`, `fchownat`, etc.) are ALREADY mapped correctly for ARM64 and accounted for in the blocking lists.

### ✅ FIXED: FFM Arena Allocation Performance
**Context:** Verified that `Profiler.kt` correctly wraps the `InputStream` in a `BufferedInputStream`, heavily mitigating `Arena` allocation pressure by performing 8KB bulk reads via overridden `read(byte[], int, int)` rather than 1-byte iterative downcalls. 

### ✅ FIXED: Profiler Daemon Path Resolution (AT_FDCWD)
**Context:** Fixed `ProfilerDaemon.getPathArgs` to properly parse `fd`-based syscalls like `FCHMOD`, `FCHOWN`, and `FSTAT` using `resolveFdPath` rather than misinterpreting the `fd` as a memory address. Implemented robust `AT_FDCWD` checks (accounting for unsigned 32-bit `0xFFFFFF9C` vs `-100L`).

### ✅ FIXED: Landlock Empty Intersection Bypass
**Context:** Fixed a severe bug in `Policy.combine` where stacking two restrictive policies with disjoint filesystem paths resulted in an `emptySet()`. Previously, this bypassed Landlock. Now, `Policy` utilizes an `enforceLandlock` boolean flag to ensure Landlock is forcefully applied (blocking all non-classpath access) when path intersections become disjoint.

## Remaining Issues

### 🔴 High: Remove Deprecated Landlock Audit Logic
**Context:** The `MAZEWALL_PROFILER_AUDIT` logic in `Profiler.kt` and `Landlock.kt` is based on the false assumption that Landlock Audit is transparent. In reality, it causes `EACCES` crashes.
**Needed:** Rip out the `Landlock.applyProfilingRuleset()` and related Netlink socket code from the Tier S profiler to restore its transparency guarantee.

### 🔴 High: Implement Tier P (Privileged Profiler)
**Context:** High-performance `io_uring` profiling currently requires either the slow `IterativeProfiler` or a performance-degrading fallback to standard I/O.
**Needed:** A root-privileged profiler using eBPF tracepoints (`sys_enter_io_uring_setup`, etc.) or `strace` to achieve true transparent "Fast Path" profiling.

### 🟡 Medium: Expand `installOnProcess` Integration Coverage
**Context:** `ContainedExecutors.installOnProcess()` needs deeper validation (inheritance, JVM stability, depth accumulation).
**Needed:** Expanded test suite.
