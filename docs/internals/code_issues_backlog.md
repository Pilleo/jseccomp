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

### 🔴 [Severity: HIGH]: Missing `creat` and `mknod` syscalls bypass `PURE_COMPUTE` filesystem restrictions
**Target:** `io.mazewall.Syscall`, `io.mazewall.Arch`, `io.mazewall.Policy.PURE_COMPUTE`
**Failure Hypothesis:** A blacklist-based policy (`ACT_ALLOW` default) intended to block all filesystem modifications fails to account for legacy or niche syscalls that achieve the same result. Specifically, `creat` and `mknod` are omitted.
**Context & Proof:** `Policy.PURE_COMPUTE` attempts to prevent file access and creation by explicitly blocking `OPEN`, `OPENAT`, `OPENAT2`, `MKDIR`, `LINK`, etc. However, it fails to block the `creat` (syscall 85 on x86_64) and `mknod`/`mknodat` system calls. Because `PURE_COMPUTE` operates on a default-allow basis (`defaultAction = ACT_ALLOW`), an attacker with FFM access or RCE can directly invoke `syscall(85, "/target/path", 0644)`. This will successfully create a new file or truncate an existing file to 0 bytes, bypassing the intended sandbox restrictions.
**Vulnerability Chain Potential:** High. Allows arbitrary file creation and truncation (of accessible files) from a thread that is supposed to be restricted to pure compute.
**Needed:** Add `CREAT`, `MKNOD`, and `MKNODAT` to `Syscall.kt`. Map them in `Arch.kt` (e.g., `creat` is 85 on x86_64, -1 on aarch64; `mknod` is 133, `mknodat` is 259). Add these syscalls to the blocklist in `Policy.PURE_COMPUTE` and `Policy.NO_EXEC`.

### 🔴 [Severity: HIGH]: Blacklist policies trigger silent, catastrophic Landlock filesystem lockdown due to `io_uring` check
**Target:** `io.mazewall.landlock.Landlock.kt` (specifically `shouldApplyLandlock`) and `io.mazewall.enforcer.ContainedExecutors.kt`
**Failure Hypothesis:** A developer creates a custom blacklist policy to block a single syscall (e.g., `Policy.builder().block(Syscall.EXECVE).build()`). Because `io_uring_setup` is not explicitly blocked, it defaults to ALLOW. The `Landlock.shouldApplyLandlock` method detects that `io_uring_setup` is allowed and automatically applies Landlock to prevent async bypasses. However, because the user provided no explicit allowed filesystem paths, Landlock is applied with an empty ruleset (plus the JVM classpath), permanently denying all other filesystem access (reads, writes, stat, etc.) to the thread.
**Context & Proof:** In `Landlock.kt`, `shouldApplyLandlock` returns true if `policy.isSyscallAllowed(Syscall.IO_URING_SETUP)`. Any policy built with `defaultAction = ACT_ALLOW` that does not explicitly block `IO_URING_SETUP` will trigger this. `Landlock.applyRuleset` will then create a ruleset handling all FS actions, apply the classpath rules, apply zero user rules, and enforce it via `landlock_restrict_self`. This silently destroys the thread's ability to interact with the filesystem, causing unexpected `EACCES` errors that developers will struggle to debug since they didn't request filesystem containment.
**Vulnerability Chain Potential:** High severity usability and stability defect. It breaks the principle of least astonishment and causes widespread application crashes for simple blacklist policies. Additionally, if Landlock is unsupported (`abi < 1`), it fails-open, allowing `io_uring` to bypass the seccomp filter anyway.
**Needed:** 
1. Remove the automatic Landlock application based on `IO_URING_SETUP` from `shouldApplyLandlock`.
2. Instead, if `io_uring` is allowed but the policy enforces Landlock (i.e., Landlock is explicitly requested), that's fine (the kernel handles the restriction). If Landlock is NOT explicitly requested, `io_uring` should either be allowed (accepting the risk if it's a permissive blacklist) OR explicitly warn the user. The safest approach is to ensure presets like `NO_EXEC` and `PURE_COMPUTE` explicitly block `io_uring` (which they already do), but not forcefully apply Landlock to custom blacklists.

### 🔴 [Severity: CRITICAL]: Standard Java Concurrency (`Virtual Threads`, `CompletableFuture`) trivially bypasses Thread-Scoped (Tier 2) containment without ACE
**Target:** `io.mazewall.enforcer.ContainedExecutors` and `docs/internals/SECURITY_CONSIDERATIONS.md`
**Failure Hypothesis:** A developer wraps an `ExecutorService` using `ContainedExecutors.wrap(delegate, Policy.NO_NETWORK)` to safely process an untrusted document. The untrusted parsing logic calls standard Java APIs like `CompletableFuture.runAsync { ... }` or `Thread.startVirtualThread { ... }`. Because these APIs delegate execution to the JVM's pre-existing `ForkJoinPool.commonPool()` (whose OS carrier threads were spawned at JVM startup and lack the seccomp filter), the delegated task executes entirely unconstrained.
**Context & Proof:** Seccomp and Landlock filters are strictly inherited via the Linux `clone` syscall. While `mazewall` correctly notes that Arbitrary Code Execution (ACE) can poison sibling threads, it fails to account for the fact that standard, safe Java APIs bypass thread-scoped containment by design. An attacker does not need memory corruption (ACE) or native access; they only need to submit a closure to a standard thread pool. Any network request or file access within that closure will succeed, instantly neutralizing the Tier 2 containment.
**Vulnerability Chain Potential:** Critical. Completely invalidates the security boundary of Tier 2 `wrap()` for any workload that isn't strictly synchronous and single-threaded. Malicious libraries can easily initiate SSRF or read files by simply hopping threads.
**Needed:** 
1. Document this fundamental architectural bypass clearly in `SECURITY_CONSIDERATIONS.md` alongside the ACE pivot. Emphasize that Tier 2 containment only restricts synchronous execution on the current thread.
2. Consider implementing a Java `SecurityManager` (deprecated but functional in Java 22 if enabled) or a custom JVMTI agent to intercept `Thread` creation and `ForkJoinPool` submissions from contained threads, OR strongly advise running untrusted code in a custom Java `ThreadGroup` where thread creation is blocked.

### 🔴 [Severity: HIGH]: Silent failure of Profiler path resolution under Yama `ptrace_scope` > 1 leads to catastrophic Landlock enforcement failures
**Target:** `io.mazewall.profiler.engine.ProfilerDaemon`

**Failure Hypothesis:** A system administrator configures Linux with Yama `kernel.yama.ptrace_scope = 2` (admin-only attach). When the `mazewall` Profiler daemon attempts to read path arguments using `process_vm_readv` on the JVM threads, the kernel denies the read with `EPERM` (1).
**Context & Proof:** The daemon catches this `EPERM`, logs a warning to `System.err`, and gracefully returns `null` for the read string. The event is then passed to `getPathArgs()`, which receives `null` and yields an empty list of paths (`emptyList()`). The `TraceEvent` is sent to the JVM without any path context. When `BobCompiler` consumes these events, it generates an empty set for `opens` and `fsWritePaths`.
**Vulnerability Chain Potential:** High usability / stability failure. Because the profiler fails gracefully instead of crashing, it produces a "valid" `BillOfBehavior` JSON containing `[]` for paths. When this SBoB is deployed to production via `SbobParser.parseToPolicy`, it generates a `Policy` that permits zero paths. The JVM wrapper then applies Landlock with an empty ruleset, instantly revoking all filesystem access and causing a catastrophic production crash across the application.
**Needed:** 
The profiler must explicitly FAIL (or throw an exception back to the JVM) if it encounters `EPERM` during path resolution. At the very least, it should inject a specific sentinel path like `"<YAMA_ERROR_UNKNOWN_PATH>"` so `BobCompiler` knows the trace was corrupted and can refuse to compile an empty SBoB, preventing invalid policies from being shipped.

### 🔴 [Severity: MEDIUM]: `SbobParser` lacks Context-Aware Working Directory resolution for Relative Paths
**Target:** `io.mazewall.SbobParser`
**Failure Hypothesis:** The `Profiler` runs in a staging environment where the JVM's Current Working Directory (CWD) is `/var/lib/staging`. An application accesses a file using a relative path, e.g., `config/settings.json`. The Profiler `tryRead` fails to resolve `dirfd` and falls back to logging the relative path `config/settings.json` into the `BillOfBehavior`. In production, the JVM's CWD is `/opt/app`. When `SbobParser` reads the SBoB, it calls `Paths.get("config/settings.json").toAbsolutePath().normalize()`, which resolves to `/opt/app/config/settings.json`.
**Context & Proof:** Landlock requires absolute paths. `SbobParser`'s `pruneSubpaths` method silently converts relative paths using the production JVM's CWD at the time of parsing. If the application actually intends to access a global relative path, or the profiler's CWD differs from the production CWD, the generated policy will allow the wrong absolute path. 
**Vulnerability Chain Potential:** Medium usability and sandbox evasion failure. If a relative path is unintentionally permitted, and the production CWD is `/`, the policy might inadvertently allow access to `/config/settings.json`. This breaks deterministic policy portability across environments.
**Needed:** 
1. `SbobParser` should warn or throw an error when attempting to parse a relative path, or it should accept an explicit `baseCwd` parameter to resolve relative paths deterministically rather than relying on the environmental JVM CWD at load time.
2. The Profiler should ensure all paths are fully resolved to absolute canonical paths *before* writing them to the SBoB, failing the profiler session if a `dirfd` cannot be resolved to an absolute path.

### 🔴 [Severity: HIGH]: `SbobParser` fails to parse standard JSON Unicode escape sequences (`\uXXXX`)
**Target:** `io.mazewall.SbobParser`
**Failure Hypothesis:** A developer/operator profiles a workload containing non-ASCII file paths (e.g. `/opt/café` or `/usr/share/datos_personales_🔒`). The Profiler records these paths and writes them to an SBoB JSON. Because standard JSON serializers escape non-ASCII and high-unicode symbols using standard `\uXXXX` sequences (e.g. `\u00e9` for `é`), the SBoB file will contain these escapes. When `SbobParser` reads this JSON, its custom `JsonTokenizer` will fail to parse the `\uXXXX` sequence and instead treat it as a literal string `uXXXX`, leading to silently corrupted paths and catastrophic application runtime failures under Landlock.
**Context & Proof:** In `SbobParser.kt`, `JsonTokenizer.parseString()` handles basic backslash escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`) inside its `when (esc)` block. If it encounters a Unicode escape sequence starting with `\u`, the parser matches `'u'` inside `when (esc)` and falls back to the `else` block:
```kotlin
else -> sb.append(esc)
```
Consequently, it appends `'u'` to the builder and proceeds to parse the 4 hexadecimal characters as regular string characters (e.g., `\u00e9` yields `u00e9` in the parsed string). The returned path becomes `/opt/cafu00e9` instead of `/opt/café`. When this policy is passed to Landlock, the ruleset allows `/opt/cafu00e9` but blocks `/opt/café`, causing the JVM to throw a `ContainmentViolationException` in production for a completely valid, profiled path.
**Cascading Risk Potential:** High usability and stability failure. Silently misconfigures Landlock rulesets, causing production systems to crash with unexpected access-denied errors that are highly dynamic and hard to debug.
**Needed:** Add native `\uXXXX` escape sequence support inside `JsonTokenizer.parseString()`. When `esc == 'u'`, parse the next 4 hexadecimal characters as an integer and append its `Char` representation to the path string.

### 🔴 [Severity: MEDIUM]: Trace Listener misleads developers by capturing the Main Thread stack trace for unmapped child threads
**Target:** `io.mazewall.profiler.Profiler`
**Failure Hypothesis:** A profiled workload spawns unmanaged child threads (via standard libraries or thread pools) that execute I/O or other trapped syscalls. When a child thread triggers a `USER_NOTIF`, the Trace Listener fails to resolve its TID to a Java `Thread` object in the JVM thread registry. As a fallback, the listener captures the stack trace of the main worker thread, permanently logging a completely unrelated stack trace for the child thread's event.
**Context & Proof:** In `Profiler.kt`'s `startTraceListener`, the listener runs a loop reading events from the daemon socket:
```kotlin
val threadToProfile = threadRegistry[pid] ?: workerThreadProvider()
val stackTrace = threadToProfile?.stackTrace?.map { it.toString() }
```
`threadRegistry` only tracks threads that explicitly call the profiler registration hook. Child threads spawned dynamically by libraries are not registered.
When the daemon notifies the listener that a child thread with TID `pid` made a syscall, `threadRegistry[pid]` returns `null`. The listener then invokes `workerThreadProvider()`, which returns the main thread's `Thread` object. As a result, the generated `TraceEvent` contains the stack trace of the **main thread** instead of the actual child thread. During SBoB analysis, developers are shown highly confusing stack traces of the main thread supposedly performing filesystem or network actions that it never initiated.
**Cascading Risk Potential:** Medium diagnostic and maintainability defect. Misleads developers and increases debugging complexity by reporting false/uncorrect stack frames for sandboxed workload execution.
**Needed:** Remove the fallback to `workerThreadProvider()` when capturing stack traces in the listener thread. If the TID is not found in `threadRegistry`, record `null` or a sentinel string (e.g., `["<untracked_descendant_thread_stack_trace>"]`) to maintain strict data integrity.
