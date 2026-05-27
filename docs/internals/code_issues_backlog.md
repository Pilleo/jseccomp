# Code Issues Backlog

### 🔴 [Severity: HIGH]: Landlock Symlink Rejection Bypass via Canonicalization
**Target:** `io.mazewall.landlock.Landlock.kt` (specifically `resolveCanonicalPath`)
**Context:** The Landlock documentation states that rules explicitly use `O_NOFOLLOW` to reject symlinks and prevent attackers from redirecting path rules. However, `addRule` calls `resolveCanonicalPath(path)` (which delegates to `File(path).canonicalPath`) *before* opening the file descriptor. `File.canonicalPath` automatically resolves all symlinks to their real targets. Therefore, `O_NOFOLLOW` operates on the already-resolved real path and will never trigger `ELOOP` for developer-provided symlinks, silently bypassing the rejection mechanism and applying the rule to the symlink's target.
**Needed:** Replace `File.canonicalPath` with a pure syntactic normalization function that collapses `.` and `..` without resolving symlinks (e.g., `Paths.get(path).normalize().toString()`). This ensures `O_NOFOLLOW` correctly evaluates the original symlink boundaries.

### 🔴 [Severity: LOW]: BPF Compiler Macro-Architecture Documentation Drift
**Target:** `io.mazewall.BpfFilter.kt` and `docs/internals/containment_design.md`
**Context:** `containment_design.md` documents that the BPF argument-inspection sequences for `mmap`, `clone`, and `prctl` fall through to the remaining linear scan by emitting `BPF_LD offset=0 # restore NR for subsequent checks`. The actual implementation in `BpfFilter.kt` uses `addInspectionResult(nr)`, which emits an immediate `BPF_RET` (ALLOW or DENY) and exits the BPF program early if the check passes.
**Needed:** Update `docs/internals/containment_design.md` to accurately reflect the early-return optimization used in `BpfFilter.kt`. Remove the `BPF_LD offset=0` instruction from the documentation snippet and explain the early `BPF_RET`.

### 🔴 [Severity: CRITICAL]: Race condition and Deadlock in `ProfilerInstaller.kt`
**Target:** `io/mazewall/profiler/engine/ProfilerInstaller.kt`
**Context:** The `installProfilingFilterForThread` method uses a `proceedLatch` to synchronize the main thread with the `coordinatorThread` (which connects to the daemon and passes the seccomp listener FD). However, the main thread unconditionally calls `proceedLatch.countDown()` inside its own `finally` block immediately after installing the BPF filter. This entirely defeats the purpose of the latch. The main thread will return immediately and proceed to execute the profiled workload.
If the `coordinatorThread` subsequently encounters an error (e.g., `connectWithRetry` fails, or the daemon is unavailable), it will catch the error, set `installError`, and call `proceedLatch.countDown()` from its `UncaughtExceptionHandler`. But the main thread is already gone and executing. As soon as the main thread issues a syscall restricted by the profiling policy, the kernel will trap it and queue a `USER_NOTIF`. Because the listener FD was never passed to the daemon, no process will ever read the notification or send an ACK. The main thread (and thus the JVM workload) will deadlock permanently in the kernel.
**Needed:** Remove `proceedLatch.countDown()` from the main thread's `finally` block. The main thread should only call it if it catches an exception *before* waiting. The `coordinatorThread` must be the one to call `proceedLatch.countDown()` upon successful listener FD transmission, so the main thread accurately waits for the profiling loop to be fully established before running the workload.

### 🔴 [Severity: HIGH]: STRICT_SANDBOX crashes on Linux kernels < 6.10 (Landlock ABI < 5) due to unblocked `ioctl`
**Target:** `io/mazewall/landlock/Landlock.kt` and `io/mazewall/Policy.kt`
**Context:** The `Policy.STRICT_SANDBOX` preset uses `PURE_COMPUTE` as its base and calls `allowJvmClasspath()`. Calling `allowJvmClasspath()` populates `allowedFsReadPaths`, which implicitly sets `enforceLandlock = true`. 
When `Landlock.applyRuleset()` is invoked, it checks `getAccessMask()`. If the system's Landlock ABI is < 5 (Linux < 6.10), Landlock cannot restrict `ioctl` operations. The code correctly verifies that if Landlock cannot restrict `ioctl`, the seccomp policy *must* block it: `else if (policy.isSyscallAllowed(Syscall.IOCTL)) { unsupportedErrors.add(...) }`.
However, `PURE_COMPUTE` does **not** block `Syscall.IOCTL` (likely because standard out `isatty` requires it). Therefore, running `STRICT_SANDBOX` on any kernel older than Linux 6.10 (e.g., Ubuntu 24.04 uses 6.8) results in a fatal `UnsupportedOperationException` on startup. 
**Needed:** Either `PURE_COMPUTE` / `STRICT_SANDBOX` must explicitly block `ioctl` (and accept that `isatty` fails, perhaps redirecting it), OR the Landlock ABI < 5 check for `ioctl` should only be a warning if the policy is an out-of-the-box preset. Alternatively, `STRICT_SANDBOX` should be adjusted to block `ioctl` explicitly.

### 🔴 [Severity: MEDIUM]: Architectural drift regarding `BobCompiler` JVM noise filtering
**Target:** `io/mazewall/profiler/compiler/BobCompiler.kt` & `AGENTS.md`
**Context:** The `profiler/AGENTS.md` document states a strict boundary: *"When modifying path parsers, ensure the noisy background JVM classloader operations (reading `.class` files, reading standard system dependencies in `/lib64` or `/etc`) are systematically filtered out via BobCompiler regular expression exclusions."* 
However, there is absolutely zero filtering logic (regex or otherwise) inside `BobCompiler.compile()` or `StraceProfiler.parseLine()`. Instead, the system relies on post-compilation filtering via `BillOfBehavior.filterPaths(JvmBaselineProfiles.jvmBootstrapNoise())`. 
**Needed:** While the functional goal of filtering out JVM noise is achieved, the mechanism has drifted from the architectural guidelines. To prevent uncontrolled memory growth during long tracing sessions and adhere to the architectural boundary, the regex exclusion logic should either be pushed down into `BobCompiler.kt`/`StraceProfiler.kt` as mandated, or the `AGENTS.md` should be updated to reflect the post-compilation `BaselinePathProfile` model.

### 🔴 [Severity: HIGH]: Landlock.applyRestrictiveBarrier() silent fail-open
**Target:** /enforcer/src/main/kotlin/io/mazewall/landlock/Landlock.kt
**Context:** In applyRestrictiveBarrier(), the calls to LinuxNative.prctl(PR_SET_NO_NEW_PRIVS) and LinuxNative.syscall(LANDLOCK_RESTRICT_SELF_NR) return a SyscallResult. The method ignores the returnValue (and errno) of these calls. If the restrictive barrier fails to apply (e.g., due to Landlock configuration limits or permission errors), the profiler will proceed with no restrictions, bypassing the intended restrictive barrier entirely.
**Needed:** Add checks for returnValue < 0 for both prctl and syscall, throwing an IllegalStateException on failure to adhere to the fail-closed doctrine, matching the logic in enforceRuleset().

### 🔴 [Severity: CRITICAL]: Whitelist policies bypass deduplication, exhausting 32-filter limit on thread pools
**Target:** /enforcer/src/main/kotlin/io/mazewall/enforcer/FilterInstallationPlanner.kt
**Context:** calculateNewFilter hardcodes needsNewFilter = true if policy.defaultAction != SeccompAction.ACT_ALLOW. It only calculates newBlocks for ACT_ALLOW (blacklist) policies. If a thread pool is wrapped with a strict whitelist policy (e.g., PURE_COMPUTE), every single task execution will install a redundant copy of the exact same filter. After 32 tasks on the same worker thread, the kernel's MAX_SECCOMP_FILTERS limit is hit and the JVM throws an IllegalStateException, crashing the worker.
**Needed:** ContainerState must track whitelist state (e.g. currentlyAllowedSyscalls and currentDefaultAction). When stacking, calculate the intersection of allowed syscalls. If a new whitelist policy does not reduce the currentlyAllowedSyscalls (i.e. it is identical or a superset), needsNewFilter should be false.

### 🔴 [Severity: MEDIUM]: Excessive container privileges and deprecated Audit architecture in compose.yml files
**Target:** /infra/dev/compose.yml and /demo/vulnerable-app/compose.yml
**Context:** The SECURITY_CONSIDERATIONS.md document clearly states that Landlock Audit is deprecated for transparent profiling because it lacks a permissive mode and causes EACCES crashes. It explicitly mandates an unprivileged profiling strategy (Tier H or Tier A). However, infra/dev/compose.yml still grants AUDIT_READ, AUDIT_CONTROL, network_mode: host, and userns_mode: host citing the deprecated Audit subsystem. Even worse, demo/vulnerable-app/compose.yml grants SYS_ADMIN and SYS_PTRACE, completely invalidating the claim that the demonstration runs in a restricted, unprivileged container environment. Furthermore, the demo compose file references a broken path ${PWD}/../../podman-seccomp.json.
**Needed:** 
1. Remove AUDIT_READ, AUDIT_CONTROL, network_mode: host, and userns_mode: host from infra/dev/compose.yml.
2. Remove SYS_ADMIN, AUDIT_READ, and SYS_PTRACE from demo/vulnerable-app/compose.yml. 
3. Fix the seccomp annotation path in the demo compose file to point correctly to the infra/dev/podman-seccomp.json file.

### 🔴 [Severity: LOW]: ContainmentViolationDetector misses \b word boundaries
**Target:** /enforcer/src/main/kotlin/io/mazewall/enforcer/ContainmentViolationDetector.kt
**Context:** The AGENTS.md documentation strictly specifies using word boundary regexes (?i)\bOperation not permitted\b... for Priority 2 matching to prevent false positives. However, containsDeniedPhrase uses msg.contains(it, ignoreCase = true), which performs unbounded substring matching.
**Needed:** Update DENIED_PHRASES matching to use a compiled Regex with \b boundaries as specified in the documentation.
