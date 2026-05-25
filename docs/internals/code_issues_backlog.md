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

### ✅ FIXED: Profiler Connection Failure Deadlocks JVM Thread
**Context:** In `ProfilerInstaller.kt`, `connectWithRetry` was called outside the `try-finally` block that closes the listener file descriptor `fd`. If the connection failed, the seccomp listener FD leaked and was never closed, permanently deadlocking any worker thread waiting on coordination.
**Fix:** Restructured `runCoordinatorLogic` to perform `connectWithRetry` inside the `try` block, ensuring `finally` always executes and closes `fd` on failure. Verified via logic-focused unit tests.

### ✅ FIXED: Expand `installOnProcess` Integration Coverage
**Context:** `ContainedExecutors.installOnProcess()` was lacking thorough integration-level guardrail and parameter validation tests.
**Fix:** Expanded `VirtualThreadGuardrailTest` and `ProcessContainmentTest` to verify that `installOnProcess()` throws `IllegalStateException` on Loom virtual threads, and `UnsupportedOperationException` if a policy tries to stack Landlock filesystem rules.

### ✅ FIXED: Deprecated Landlock Audit Logic Removal
**Context:** The old Netlink-based `MAZEWALL_PROFILER_AUDIT` and `Landlock.applyProfilingRuleset()` were deprecated because Landlock lacks a permissive mode and throws blocking `EACCES` signals.
**Fix:** Ripped out legacy Netlink socket bindings and `applyProfilingRuleset()` logic, fully relying on `IterativeProfiler` for unprivileged path discovery and keeping `Landlock.kt` clean.
### ✅ FIXED: Hierarchical Rule Stacking Validation
**Context:** In `ContainedExecutors.kt`, the check to prevent expanding existing Landlock permissions was using exact string matching (`containsAll`). This incorrectly threw an exception if a nested task requested a valid sub-path (e.g., `/tmp/foo` when `/tmp` was already allowed).
**Fix:** Replaced exact string matching with a robust `java.nio.file.Path`-based subset path evaluation using component-level startsWith. Added extensive unit testing to cover identical stacking, sub-path nesting, component boundaries, and expansion detection.

### ✅ FIXED: Profiler Daemon Missing Null-Terminator Bounding
**Context:** In `ProfilerDaemon.kt`, `readStringFromProcess` copies memory from a target process. If a malicious or corrupted pointer lacked a null terminator within the buffer window (`maxLen = 4096`), it copied the entire buffer as a string, processing garbage data.
**Fix:** Added a bounding check in `readStringFromProcess` (`if (len == bytesRead) { return null }`) to safely reject any strings that are not null-terminated within the read boundary. Covered with comprehensive unit tests in `ProfilerDaemonTest` using self-PID FFM memory allocations.

## Remaining Issues

### 🔴 High: Landlock Path Fallback Over-Permission
**Context:** In `IterativeProfiler.kt`, reading a missing file inside a restricted directory triggers an `EACCES` denial. The profiler conservatively grants both Read and Write access. When `Landlock.kt` processes this rule, it falls back to applying the rule to the parent directory, resulting in full write access to the parent.
**Needed:** Re-evaluate the `IterativeProfiler` fallback strategy or explicitly handle missing files before passing them to Landlock.

### 🔴 High: Implement Tier P (Privileged Profiler)
**Context:** High-performance `io_uring` profiling currently requires either the slow `IterativeProfiler` or a performance-degrading fallback to standard I/O.
**Needed:** A root-privileged profiler using eBPF tracepoints (`sys_enter_io_uring_setup`, etc.) or `strace` to achieve true transparent "Fast Path" profiling.
