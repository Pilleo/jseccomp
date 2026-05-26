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

### ✅ FIXED: Landlock Path Fallback Over-Permission
**Context:** In `IterativeProfiler.kt`, reading a missing file inside a restricted directory triggers an `EACCES` denial. Previously, the profiler conservatively granted both Read and Write access, which caused Landlock to fall back to the parent directory and grant full write permissions on the parent directory for a simple missing file read.
**Fix:** Refactored `IterativeProfiler` to use an adaptive permission discovery strategy. On the first violation of a path, only `Read` access is granted. If a subsequent run still triggers a violation on that path, it is identified as a `Write` attempt and `Write` access is granted. This ensures that missing file reads never elevate to write permissions on the parent directory, while guaranteeing convergence within exactly one extra iteration.

### ✅ FIXED: Assertive Jacoco Coverage Verification
**Context:** The Jacoco coverage verification rules in `build.gradle.kts` were highly relaxed, completely excluding complex files like `IterativeProfiler`, `Profiler`, `ProfilerDaemon`, and `Arch` from any verification, and setting low (40-60%) thresholds for others.
**Fix:** Profiled actual test coverage across the whole codebase and significantly tightened the rules. Removed unnecessary exclusions so that high-coverage core components (like `IterativeProfiler` and `ProfilerDaemon`) are verified under the strict 80% instruction coverage rule. Raised specific limits for the remaining classes to match actual tight execution boundaries (e.g. Landlock to 78%, Platform and Arch to 75%, PureJavaBpfEngine to 70%, and Profiler to 60%).

### ✅ FIXED: Tier P (Privileged/Strace Profiler)
**Context:** High-performance, transparent profiling inside containers requires a solution that is robust to namespaced permissions and kernel constraints. eBPF tracepoints require host-level `CAP_BPF` and `CAP_PERFMON` which are unavailable inside rootless unprivileged container user namespaces. At the same time, attaching to a running JVM via `ptrace(2)` / `strace -p` returns `EPERM` due to the Yama `ptrace_scope = 1` default and namespace restrictions.
**Fix:** Designed and implemented the Tier P privileged profiler (`StraceProfiler`) utilizing `strace -f` under subprocess descendant execution. The target workload (which implements the `TraceableWorkload` interface) is loaded and executed inside a child JVM spawned directly under `strace` via the `StraceWorkloadRunner` entrypoint, completely bypassing Yama `ptrace_scope` constraints. The resulting log is streamed and parsed using robust system call regex patterns to build a high-fidelity `BillOfBehavior`. JVM bootstrap and classpath discovery noise is dynamically filtered out to produce pristine, minimal policy profiles.
**Verification:** Added a comprehensive OCI container integration test suite in `StraceProfilerTest` (covering file reads, file writes, network sockets, and missing files), confirming 100% test success under unprivileged container constraints. Additionally, updated `build.gradle.kts` to exclude the spawned `StraceWorkloadRunner` from the Jacoco coverage verification block to avoid sub-process coverage check errors.

### ✅ FIXED: SBoB Decoupling (Production vs Test)
**Context:** The `MazewallProfileManager` and related profiling logic were incorrectly placed in the production application classpath, introducing a heavy test-only dependency (`:profiler`) into the runtime environment.
**Fix:** 
1. Created `io.mazewall.SbobParser` in the `:enforcer` module. This is a lightweight JSON parser (no external dependencies) that allows production code to load profiling results and convert them to `Policy` objects.
2. Moved `MazewallProfileManager` and related wrapping logic to `src/test/kotlin` in the vulnerable-app demo.
3. Implemented `MazewallTestProfileConfig` using Spring's `@TestConfiguration` to transparently wrap beans with the `Profiler` during integration tests.
4. Moved `:profiler` to a `testImplementation` dependency in the demo app.

## Remaining Issues

*No remaining high-priority issues.*

## Newly Discovered Issues (Integration Demo)

### 🔴 [Severity: High]: `Policy.PURE_COMPUTE` blocks `OPENAT` syscalls
**Context:** `PURE_COMPUTE` explicitly blocks `OPEN`, `OPENAT`, and `OPENAT2` via Seccomp. This creates a hard conflict when combined with Landlock (`allowFsRead`), because Seccomp blocks the syscall entirely before Landlock can regulate it.
**Needed:** `PURE_COMPUTE` should probably not block `OPENAT` by default if it's intended to be used as a base for Landlock policies, OR we need a `Policy.NO_NETWORK_NO_EXEC` preset that allows FS syscalls for Landlock.

### 🟡 [Severity: Medium]: `Policy.STRICT_SANDBOX` inherits `PURE_COMPUTE` flaws
**Context:** `STRICT_SANDBOX` uses `PURE_COMPUTE` as a base and calls `allowJvmClasspath()`. Because `PURE_COMPUTE` blocks `OPENAT`, the "allowed" classpath is unreachable by the kernel, potentially causing `NoClassDefFoundError` or `VerifyError` during lazy classloading.
**Needed:** Refactor `STRICT_SANDBOX` to use a base that allows FS syscalls, or explicitly unblock them.

### 🟡 [Severity: Medium]: `java.lang.VerifyError` when bytecode verification happens on restricted threads
**Context:** During the vulnerable-app demo, XStream triggered a `VerifyError: Could not link verifier` on protected threads. This was resolved by adding `allowMmapExec()` to the thread-scoped policy.
**Needed:** Document that `allowMmapExec()` (allowing `PROT_EXEC` on `mmap`) is a prerequisite for some JVM native linking operations, even if the thread doesn't intend to execute its own shellcode.

### 🔴 [Severity: High]: Process-wide `Policy.NO_EXEC` causes JVM crash even after warmup
**Context:** Even after the application has fully started (e.g., after `ApplicationReadyEvent`), the JVM JIT compiler and native library loaders (like Tomcat native) continue to require `mmap` with `PROT_EXEC`. Applying the strict `NO_EXEC` preset process-wide results in a fatal JVM crash (`os::commit_memory failed; error='Operation not permitted' (errno=1)`) when the JVM attempts to optimize code or link dynamic libraries during request processing.
**Needed:** Recommend or default to a "Balanced Baseline" for Tier 1 process-wide protection that allows `mmap(PROT_EXEC)` while still blocking `execve`, `fork`, and other process-creation primitives. Update documentation to warn against strict `NO_EXEC` for process-wide lockdown.

### 🔴 [Severity: Critical]: Unsafe heuristics in SBoB generation mask underlying system behavior
**Context:** SBoB generation via strace inherently captures all JVM bootstrap and classpath resolution noise. A previous attempt to address this used hardcoded string matching (`/lib`, `/sys`, `java.home`) to silently filter these paths out of the final compiled policy.
**Needed:** Hardcoded path filtering is an unsafe heuristic that creates silent bypasses or blocks legitimate paths. The profiler must remain transparent. We must document this limitation (SBoB will include JVM bootstrap noise) and handle refinement safely—perhaps by delegating it to the operator or providing explicit, opt-in baseline path sets, rather than silently hiding it in `BobCompiler`.
