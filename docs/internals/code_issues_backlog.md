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

### 🔴 [Severity: HIGH]: Nested Seccomp Stacking Security Containment Bypass on already-blocked Syscalls
**Target:** `io.mazewall.enforcer.FilterInstallationPlanner`
**Failure Hypothesis:** When a user stacked policy contains a more restrictive or more severe action for a syscall that is already blocked by a previously applied policy, the planner incorrectly skips the filter installation under a false optimization path because it only checks if the syscall is "blocked".
**Context & Proof:** `FilterInstallationPlanner.calculateNewFilter` calculates `newBlocks = blockedInPolicy - state.currentlyBlocked`. Any syscall with an action priority > ACT_ALLOW is in `blockedInPolicy`. If a syscall (e.g. `EXECVE`) was blocked by Policy 1 with a lenient action (like `ACT_LOG`), `currentlyBlocked` already contains it. When Policy 2 is nestedly stacked to block `EXECVE` with a severe action (like `ACT_KILL_PROCESS`), `newBlocks` evaluates to empty because it was already blocked. As a result, the optimizer sets `needsNewFilter` to `false`, silently skipping the installation of the second filter. The thread continues executing with only the weaker `ACT_LOG` filter in place, completely bypassing the intended `ACT_KILL_PROCESS` containment.
**Cascading Risk Potential:** High security containment bypass. A stacked policy that is intended to restrict thread capabilities further is ignored, causing RCE/compromised code to execute under weaker sandbox rules than designed.
**Needed:** Modify `currentlyBlocked` to track `Map<Syscall, SeccompAction>` rather than `Set<Syscall>`. In `calculateNewFilter`, `newBlocks` should include any syscall in the new policy that maps to a *higher priority (more restrictive) action* than the currently installed action for that syscall.

### 🔴 [Severity: HIGH]: Excessive Landlock Directory Capability Leak via Parent Fallback on Non-Existent Path Rules
**Target:** `io.mazewall.landlock.Landlock.kt` (specifically `addRule`)
**Failure Hypothesis:** When a user specifies a file-specific filesystem access rule for a file path that does not yet exist, Landlock's fallback handler opens the parent directory but fails to strip directory-specific actions (`READ_DIR`, `MAKE_DIR`, `REMOVE_DIR`) from the access mask, violating the principle of least privilege.
**Context & Proof:** If a user calls `allowFsWrite("/var/lib/app/settings.json")` (non-existent file) under a custom policy, `addRule` falls back to the parent directory `/var/lib/app` with `isFallback = true`. The `calculateFinalAccess` method only strips `dirOnlyFlags` when `!isFallback && File(resolvedPath).isFile`. Because `isFallback` is `true`, the `dirOnlyFlags` (`READ_DIR | MAKE_DIR | REMOVE_DIR`) are NOT stripped from `writeFlags`. The resulting ruleset grants the thread complete authority to list files (`READ_DIR`), create directories (`MAKE_DIR`), and delete directories (`REMOVE_DIR`) inside the parent `/var/lib/app`, exposing other sensitive files or directories to manipulation or deletion.
**Cascading Risk Potential:** High boundary bypass and integrity risk. An attacker can write to, create, or delete arbitrary files/folders under the parent directory, breaching the intended scope of a single-file rule.
**Needed:** Adjust `calculateFinalAccess` to strip `dirOnlyFlags` if the *original* user-provided path represents a file target, even during a fallback scenario. Since we cannot check `File(resolvedPath).isFile` if the file doesn't exist, we can determine the type either by analyzing the path suffix (e.g. ends with `/` or not) or by passing a flag indicating if the original intent was a file or directory.

### 🔴 [Severity: HIGH]: SbobParser Production Crashes due to Syntactic Subpath Pruning of Unresolved/Symlinked Paths
**Target:** `io.mazewall.SbobParser` (specifically `pruneSubpaths`)
**Failure Hypothesis:** SbobParser's subpath pruning operates purely syntactically without resolving symlinks. If a staging environment contains a symlinked directory and a real nested directory, pruning will discard the nested path. When the parsed policy is applied, the symlink is rejected, and because the nested path was pruned, the entire tree is left blocked, causing production application crashes.
**Context & Proof:** In `SbobParser.kt`, `pruneSubpaths` syntactically normalizes and sorts path strings. If a profiled workload accessed both `/var/log` (a symlink) and `/var/log/app` (a real directory), the SBoB JSON lists both. `pruneSubpaths` prunes `/var/log/app` because it syntactically starts with `/var/log`. In production, when `Landlock.addRule` is invoked for `/var/log`, `O_NOFOLLOW` triggers a symlink rejection `ELOOP`, so the rule is skipped and no filesystem rule is added. Since `/var/log/app` was pruned, no rule is added for `/var/log/app` either. The application is completely blocked from accessing `/var/log/app` and crashes.
**Cascading Risk Potential:** High usability and stability risk. Causes deterministic, hard-to-debug runtime crashes in production environments when deploying SBoB policies across varying file systems or symlinks.
**Needed:** SbobParser's subpath pruning must be aware of symlink and directory boundaries, or `addRule` must not prune paths that could fail to resolve. A safer solution is to have SbobParser retain all paths and let `Landlock.applyRuleset` perform dynamic pruning after resolving canonical/real paths in the actual environment, or avoid pruning paths syntactically if they could be symlinks.

### 🔴 [Severity: HIGH]: `ProfilerDaemon` fails to resolve `SYMLINKAT` path parameters due to invalid argument grouping
**Target:** `io.mazewall.profiler.engine.ProfilerDaemon` (specifically `getPathArgs`)
**Failure Hypothesis:** The `ProfilerDaemon` maps `SYMLINKAT` into the same argument-parsing branch as `RENAMEAT`, `RENAMEAT2`, and `LINKAT`. However, `SYMLINKAT` uses a completely different argument layout than those double-descriptor syscalls. This mismatch causes the profiler to read invalid memory addresses, failing path resolution completely and leading to production Landlock crashes.
**Context & Proof:** In `ProfilerDaemon.kt`, `SYMLINKAT` is matched in the following branch of `getPathArgs()`:
```kotlin
            "RENAMEAT", "RENAMEAT2", "LINKAT", "SYMLINKAT" ->
                listOfNotNull(
                    tryRead(pid, args[ARG_OLD_PATH], args[ARG_OLD_DIR_FD]),
                    tryRead(pid, args[ARG_NEW_PATH], args[ARG_NEW_DIR_FD]),
                )
```
Where:
- `ARG_OLD_DIR_FD` = 0, `ARG_OLD_PATH` = 1
- `ARG_NEW_DIR_FD` = 2, `ARG_NEW_PATH` = 3

But the Linux signature for `symlinkat` is:
`int symlinkat(const char *target, int newdirfd, const char *linkpath);`
Which translates in seccomp notification args to:
- `args[0]` = `target` (string pointer)
- `args[1]` = `newdirfd` (integer FD)
- `args[2]` = `linkpath` (string pointer)
- `args[3]` = (unused / undefined register garbage)

Consequently, `ProfilerDaemon` executes:
1. `tryRead(pid, args[1], args[0])` -> Treats `newdirfd` (e.g. `3`) as a string pointer. `process_vm_readv` tries to read memory at address `3`, failing with `EFAULT`.
2. `tryRead(pid, args[3], args[2])` -> Treats register garbage (from `args[3]`) as a string pointer, failing with `EFAULT` or `EPERM`.

As a result, neither the symlink target nor the symlink creation path is resolved. SBoB output misses the rule, causing Landlock to deny `symlinkat` in production and crash the application.
**Cascading Risk Potential:** High usability, stability, and sandbox coverage defect. Completely prevents applications from creating symbolic links via `symlinkat` in production sandboxes.
**Needed:** Move `"SYMLINKAT"` out of the `RENAMEAT` branch. Create a dedicated branch in `getPathArgs()` for `"SYMLINKAT"`:
```kotlin
            "SYMLINKAT" ->
                listOfNotNull(
                    tryRead(pid, args[0]), // Target raw string (treated as absolute or relative to linkpath)
                    tryRead(pid, args[2], args[1]) // Resolves linkpath (args[2]) relative to newdirfd (args[1])
                )
```

### 🔴 [Severity: CRITICAL]: Trace Listener Socket Interruption Deadlock due to unhandled `EINTR`
**Target:** `/profiler/src/main/kotlin/io/mazewall/profiler/Profiler.kt` (inside `startTraceListener`)
**Failure Hypothesis:** The JVM multi-threaded runtime relies heavily on POSIX signals (e.g., `SIGUSR2`, `SIGJVM1`, `SIGJVM2`) for GC safepoints and thread suspension. If one of these signals is delivered to the trace listener thread while it is blocked inside a native `LinuxNative.read()` call on the Unix domain socket, the call will fail with `EINTR` (-1). If the custom `InputStream` wrapper treats all non-positive return values as EOF and terminates, it will cause a permanent deadlock of sandboxed sibling threads.
**Context & Proof:** In `Profiler.kt`, `startTraceListener` wraps the socket reading in a custom `InputStream`:
```kotlin
override fun read(): Int {
    val res = LinuxNative.read(socketFd, readBuf, 1)
    val value =
        if (res.returnValue <= 0) {
            -1
        } else {
            readBuf.get(ValueLayout.JAVA_BYTE, 0L).toInt() and BYTE_MASK
        }
    return value
}
```
If `LinuxNative.read()` is interrupted by a signal, `res.returnValue` is `-1` and `res.errno` is `4` (`EINTR`). The code does not check `errno` and instead immediately returns `-1` (EOF). When `DataInputStream.readFully()` is reading the packet (e.g., reading the PID or name length) and receives `-1`, it throws an `EOFException` and exits the listener thread's processing loop.
Once the trace listener thread terminates, the socket is closed. When any sandboxed sibling thread subsequent to this event invokes a blocked system call, the seccomp filter intercepts the call and traps the thread by queuing a `USER_NOTIF`. The supervisor daemon receives the notification, writes the `TraceEvent` to the Unix domain socket, and blocks waiting for an ACK byte from the JVM. However, because the trace listener thread is dead and the JVM socket end is closed, the daemon's write fails or blocks indefinitely. Sibling threads are left permanently frozen in the kernel, leading to a complete JVM deadlock.
**Cascading Risk Potential:** Critical. Deterministically causes JVM deadlocks during garbage collection or thread suspension events while running the profiler.
**Needed:** Add an explicit loop inside the `read()` and `read(b, off, len)` overrides of the `InputStream` in `Profiler.kt` to check if `res.returnValue < 0 && res.errno == 4` (EINTR). If so, retry the `LinuxNative.read` call. Only return `-1` if the return value is non-positive and `errno` is not `EINTR` (indicating true EOF or socket failure).

### 🔴 [Severity: HIGH]: Missing `sendmmsg` and `recvmmsg` system calls bypass `NO_NETWORK` and `PURE_COMPUTE` restrictions
**Target:** `io.mazewall.Syscall`, `io.mazewall.Policy.PURE_COMPUTE`, `io.mazewall.Policy.NO_NETWORK`, and `/profiler/src/main/kotlin/io/mazewall/profiler/compiler/BobCompiler.kt`
**Failure Hypothesis:** A blacklist-based seccomp policy that aims to prevent all outbound networking fails to block alternative or modern socket-sending system calls. An attacker with arbitrary code execution can bypass `NO_NETWORK` or `PURE_COMPUTE` by invoking these unblocked network system calls.
**Context & Proof:** `Policy.NO_NETWORK` and `Policy.PURE_COMPUTE` block standard socket operations like `CONNECT`, `SENDTO`, `SENDMSG`, and `SOCKET`. However, they fail to account for `sendmmsg` (system call 307 on x86_64, 269 on aarch64) and `recvmmsg` (system call 299 on x86_64, 268 on aarch64). Because blacklist-based policies default to allowing any system call not explicitly blocked (`defaultAction = ACT_ALLOW`), `sendmmsg` and `recvmmsg` remain unconditionally allowed.
If an attacker achieves native arbitrary code execution (ACE) or has access to a pre-existing socket file descriptor, they can directly invoke `syscall(307, fd, msgvec, vlen, flags)` to transmit network packets, completely bypassing the socket blocklists. Additionally, these system calls are omitted from `Syscall.kt` and thus are also ignored by the `BobCompiler` during trace compilation, creating a complete blind spot in both enforcement and profiling.
**Cascading Risk Potential:** High security sandbox evasion. Enables arbitrary outbound network transmission on contained threads despite active network blocklists.
**Needed:** Add `SENDMMSG` and `RECVMMSG` to `Syscall.kt` and map them in `Arch.kt` (e.g., `sendmmsg` is 307 on x86_64, 269 on aarch64; `recvmmsg` is 299, 268). Add these variants to the block lists in `Policy.PURE_COMPUTE` and `Policy.NO_NETWORK`. Finally, update `BobCompiler.kt` and `StraceProfiler.kt` to map and parse these system calls correctly.

### 🔴 [Severity: HIGH]: `IterativeProfiler` fails to resolve wrapped exception chains, breaking progressive profiling
**Target:** `/profiler/src/main/kotlin/io/mazewall/profiler/iterative/IterativeProfiler.kt` (specifically `extractViolationPath`)
**Failure Hypothesis:** Progressive profiling (Tier A) relies on catching VFS permission failures, extracting the blocked file path, adding it to the policy, and retrying the task. If a library or framework catches the underlying `AccessDeniedException` and wraps it in a custom runtime or checked exception (which is standard behavior in modern enterprise Java frameworks), the profiler will fail to extract the path because it only inspects the top-level exception.
**Context & Proof:** In `IterativeProfiler.kt`, `extractViolationPath` only checks:
```kotlin
val path = when {
    t is AccessDeniedException -> t.file
    else -> {
        val msg = t.message
        ...
```
If a framework catches `AccessDeniedException` and wraps it (e.g. in `RuntimeException`), `t is AccessDeniedException` is `false`. It falls into the `else` block to parse the exception's message string using regex/flat string matching. However, standard Java exception wrapper messages (e.g. `"java.lang.RuntimeException: java.nio.file.AccessDeniedException: /var/lib/app/file"`) do not contain any of the `ContainmentViolationDetector.DENIED_PHRASES` like `"Permission denied"` or `"Operation not permitted"`. As a result, `phraseIdx` evaluates to `-1` and the method returns `null`. The profiler aborts the auto-discovery loop prematurely and rethrows the wrapper exception, permanently breaking rule discovery.
**Cascading Risk Potential:** High usability and stability failure. Breaks progressive sandbox profiling for any workload that uses third-party libraries that wrap exceptions.
**Needed:** Modify `IterativeProfiler.extractViolationPath` to traverse the exception cause chain using a recursive or iterative helper (similar to `ContainmentViolationDetector.isContainmentViolation`). If any cause in the chain is an `AccessDeniedException`, extract the path directly from it. If the cause is a raw `IOException`, parse its message for the file path and denied phrases.

### 🔴 [Severity: MEDIUM]: Redundant BPF Argument Inspection Blocks in Stacked Filters cause performance and size bloat
**Target:** `/enforcer/src/main/kotlin/io/mazewall/enforcer/FilterInstallationPlanner.kt` (specifically `calculateNewFilter`)
**Failure Hypothesis:** Seccomp BPF filters are additive. If a previous filter already restricts `mmap(PROT_EXEC)`, non-thread `clone`, or unsafe `prctl` calls, there is no need to compile and install duplicate argument inspection blocks for these syscalls in a new stacked filter.
**Context & Proof:** `FilterInstallationPlanner.calculateNewFilter` evaluates:
```kotlin
val needsMmapProtection = !policy.allowMmapExec && state.currentlyAllowsMmapExec
```
If a previous filter already blocked `mmap` exec, `state.currentlyAllowsMmapExec` is `false`, so `needsMmapProtection` is `false`. Thus, the protection itself does not trigger `needsNewFilter = true`.
However, if `needsNewFilter` is triggered by a *different* new syscall block, we compile the new policy filter `toInstall`. Because `policy.allowMmapExec` is `false` (the new policy also blocks it), the constructed `toInstall` has `allowMmapExec = false`. When `BpfFilter.build(arch, toInstall)` compiles the filter, it unconditionally adds the complete `mmap`/`mprotect` argument-inspection BPF instruction block.
As a result, both the existing filter and the new stacked filter contain identical redundant BPF instruction sets. Each subsequent stacked filter adds yet another copy, bloating the kernel's BPF filter list, increasing runtime overhead on every `mmap`/`mprotect`/`clone`/`prctl` call, and wasting the 32-filter depth limit budget.
**Cascading Risk Potential:** Medium performance and kernel instruction memory footprint degradation on highly nested or stacked sandbox setups.
**Needed:** In `FilterInstallationPlanner.calculateNewFilter`, when constructing `toInstall` in the `else` branch of `policy.defaultAction == ACT_ALLOW`:
If `state.currentlyAllowsMmapExec` is `false`, call `builder.allowMmapExec()` so that the new filter skips compilation of the redundant inspection block. Apply the same optimization for `allowNonThreadClone` and `allowUnsafePrctl`.

### 🔴 [Severity: NITPICK]: Design Documentation Drift in Landlock thread-local variable and restrictive method names
**Target:** `/docs/internals/containment_design.md`
**Failure Hypothesis:** The design documentation has drifted from the actual source code implementation regarding thread-local tracking variables and velocity/restricting method names, which causes confusion for developers.
**Context & Proof:** In `containment_design.md §5`:
1. The documentation states that `THREAD_LANDLOCK_APPLIED` is a `ThreadLocal<Boolean>` that ensures rulesets are applied once. In the codebase (`ContainerStateRegistry.kt`), this was refactored to `THREAD_LANDLOCK_APPLIED_READS` and `THREAD_LANDLOCK_APPLIED_WRITES` (which are `ThreadLocal<Set<String>?>`) to support dynamic subset validation during stacked nesting.
2. The documentation refers to the method `applyProfilingRuleset()` used by the Iterative Profiler. In `Landlock.kt`, this method is actually named `applyRestrictiveBarrier()`.
**Cascading Risk Potential:** Nitpick / maintainability defect. Misleads developers and increases onboarding friction.
**Needed:** Update `containment_design.md` to accurately reference `THREAD_LANDLOCK_APPLIED_READS`/`THREAD_LANDLOCK_APPLIED_WRITES` and `applyRestrictiveBarrier()`.

### 🔴 [Severity: HIGH]: Public `PureJavaBpfEngine.install` bypasses Loom Carrier Poisoning safeguards and JIT warmups
**Target:** `io.mazewall.seccomp.PureJavaBpfEngine` & `io.mazewall.enforcer.ContainedExecutors`
**Failure Hypothesis:** A client application or direct invocation of the public `PureJavaBpfEngine.install()` or `PureJavaBpfEngine.installOnProcess()` bypasses the critical virtual thread safety guards, JIT warmups, and thread-local state tracking implemented in `ContainedExecutors`.
**Context & Proof:** In `PureJavaBpfEngine.kt`, the `install` and `installOnProcess` methods are public and implement `SeccompEngine`. Unlike `ContainedExecutors.installOnCurrentThread`, `PureJavaBpfEngine` contains no `checkVirtualThread()` assertion. If a developer or library calls `PureJavaBpfEngine.install()` from within a Loom Virtual Thread, it will successfully execute `prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp(...)` on the underlying OS carrier thread. This causes carrier thread poisoning, permanently restricting all other virtual threads scheduled on it. Furthermore, it completely bypasses the `ContainerStateRegistry` thread-local state updates and `performJitWarmup()`, leading to JIT compiler deadlocks/traps and state inconsistencies during stacked filter installation.
**Cascading Risk Potential:** High security containment and stability bypass. Bypasses core safety guards, poisoning carrier threads and corrupting subsequent stacked sandboxes.
**Needed:** Declare `PureJavaBpfEngine` and `SeccompEngine` as `internal` to prevent direct external access. Additionally, add a virtual thread check `if (Thread.currentThread().isVirtual) { ... }` inside `PureJavaBpfEngine.installInternal` as a defense-in-depth safety measure.

### 🔴 [Severity: HIGH]: Excessive Landlock directory capability leak on unlinked/deleted files ending in ` (deleted)`
**Target:** `io.mazewall.profiler.engine.ProfilerDaemon` (specifically `resolveFdPath`) and `io.mazewall.landlock.Landlock.kt` (specifically `addRule`)
**Failure Hypothesis:** When a profiled application accesses a temporary file and deletes it while keeping its file descriptor open, Linux procfs `/proc/<pid>/fd/<fd>` symlinks resolve with ` (deleted)` appended to the path. The profiler logs this path, and when applied in production, Landlock's fallback mechanism opens the parent directory, exposing the entire directory to the sandbox.
**Context & Proof:** If an application opens a file (e.g. `/var/log/app/tmp_file`) and unlinks it immediately, `ProfilerDaemon.resolveFdPath` calls `readlink` on `/proc/$pid/fd/$fd`, which returns `/var/log/app/tmp_file (deleted)`. The profiler records this exact string in the SBoB JSON. In production, `Landlock.addRule()` tries to open `/var/log/app/tmp_file (deleted)`. Since that path does not exist, `handleInitialOpenFailure` catches the `ENOENT` error and falls back to the parent directory by calling `File("/var/log/app/tmp_file (deleted)").parent ?: "/"`, which resolves to `/var/log/app`. Landlock then opens `/var/log/app` and adds a rule allowing full access. This leaks access to all sibling files and folders inside that directory.
**Cascading Risk Potential:** High security privilege leak. An attacker can access, corrupt, or delete other sensitive logs and files in the parent directory, breaching the single-file isolation model.
**Needed:** In `ProfilerDaemon.kt`, strip any trailing `" (deleted)"` suffix from resolved paths before returning them. Additionally, in `Landlock.kt`'s `handleInitialOpenFailure`, ignore fallback attempts for paths ending with `" (deleted)"` or validate if the path string represents a deleted file marker before reverting to the parent.

### 🔴 [Severity: HIGH]: `ProfilerDaemon` memory-reading fails to resolve paths on page boundaries or large strings
**Target:** `io.mazewall.profiler.engine.ProfilerDaemon` (specifically `readStringFromProcess`)
**Failure Hypothesis:** If `process_vm_readv` reads a path string that does not contain a null terminator in the returned buffer (due to page boundaries or large lengths), the profiler returns `null`, breaking rule compilation.
**Context & Proof:** In `ProfilerDaemon.kt`'s `readStringFromProcess()`, a loop searches `localBuf` for `0.toByte()`. If `process_vm_readv` performs a partial read (e.g. at the end of a mapped page boundary) or if the path is longer than `maxLen` (4096 bytes) and no null terminator is present, the index loop reaches `bytesRead`. The condition `len < bytesRead` then evaluates to `false`, causing the method to return `null`. The profiler thus fails to capture the path, producing empty rulesets that crash in production.
**Cascading Risk Potential:** High usability and stability failure. Breaks path resolution on complex memory allocations, leading to broken policies and production crashes.
**Needed:** If `len == bytesRead`, copy and return the best-effort string `localBuf.copyToString(bytesRead)` rather than returning `null`. Alternatively, increase the buffer size and perform a secondary read if a null terminator is not found.

### 🔴 [Severity: HIGH]: `installOnProcess` process-wide seccomp synchronization (TSYNC) fails deterministically on standard JVMs
**Target:** `io.mazewall.seccomp.PureJavaBpfEngine`
**Failure Hypothesis:** Process-wide seccomp installation via `TSYNC` requires `no_new_privs` to be enabled on all threads in the thread group. In standard JVMs, background threads are spawned before `no_new_privs` is set, causing TSYNC to fail with `EACCES` under non-root configurations. The current exception error message is also highly misleading.
**Context & Proof:** The Linux kernel requires `no_new_privs` to be set on all sibling threads in the thread group for `SECCOMP_FILTER_FLAG_TSYNC` to succeed. When the JVM starts, GC threads, JIT threads, and VM helper threads are spawned at startup. In `PureJavaBpfEngine.installInternal`, the main thread calls `setNoNewPrivs()`, which only sets the flag on the *calling* thread. Pre-existing background threads do not get it. When `TSYNC` is attempted, the kernel returns `EACCES` (-13). The method catches this failure and throws an exception claiming "Your kernel may be too old to support SECCOMP_FILTER_FLAG_TSYNC", which is factually incorrect and misleads operators.
**Cascading Risk Potential:** High stability and deployment failure. Process-wide seccomp fails to install out-of-the-box on local developer setups or standard servers unless pre-set via an OCI container runtime or launcher wrapper.
**Needed:** Update the exception message in `PureJavaBpfEngine.kt` to clearly state that `TSYNC` failed due to missing `no_new_privs` on sibling threads, advising operators to run with OCI `allowPrivilegeEscalation: false` or pre-set `no_new_privs` using an external launcher.

### 🔴 [Severity: CRITICAL]: Permanent thread pool contamination, classloader leaks, and state pollution via un-cleared `ThreadLocal` variables
**Target:** `/enforcer/src/main/kotlin/io/mazewall/enforcer/ContainedExecutors.kt` and `ContainerStateRegistry.kt`
**Failure Hypothesis:** Standard JVM thread pools (like `ForkJoinPool` or `ThreadPoolExecutor`) reuse worker threads. Since the sandbox tracks thread-scoped seccomp and Landlock states using `ThreadLocal` registers (e.g. `THREAD_BLOCKED`, `THREAD_LANDLOCK_APPLIED_READS`, `THREAD_LANDLOCK_APPLIED_WRITES`, `FILTER_DEPTH`) but *never* clears or removes them when a wrapped task finishes, the thread-scoped security state leaks permanently into subsequent uncontained or differently contained tasks on the same thread, causing unexpected `IllegalStateException` throws or memory leaks.
**Context & Proof:** In `ContainedExecutors.kt`, `wrap` creates a `ContainedExecutorWrapper` which overrides `execute` and `submit` to wrap tasks. When the wrapped task runs, it calls `applyContainment()`, which checks the thread-local variables in `ContainerStateRegistry`. However, when the task *finishes*, the wrapper does not clean up the thread-local state!
For example, if Task A with a strict Landlock read policy is run on Thread 1, `THREAD_LANDLOCK_APPLIED_READS` is set to the allowed paths. Later, Task B is run on the *same* thread, but with a *different* policy. `appliedReads` is retrieved as Task A's paths, causing `isPathSubset` to fail or falsely reject Task B's valid paths, throwing a permanent `IllegalStateException`.
Furthermore, in standard dynamic enterprise environments (like servlet containers), keeping references to strings (the paths) in `ThreadLocal` variables of system/global threads prevents the application's classloader from being garbage collected on redeploy, resulting in severe process-wide heap memory exhaustion.
**Cascading Risk Potential:** Critical. Deterministically causes thread pool contamination, unexpected runtime crashes on recycled threads, and permanent classloader memory leaks.
**Needed:** In `ContainedExecutors.kt`, wrap task execution in a `try-finally` block. In the `finally` block, if this was the outermost sandbox application on the current thread (or if we are returning to the pool), restore or clear the thread-local states by calling `.remove()` on all thread-local registers in `ContainerStateRegistry`.

### 🔴 [Severity: HIGH]: `IterativeProfiler` crashes deterministically on relative-path filesystem violations
**Target:** `/profiler/src/main/kotlin/io/mazewall/profiler/iterative/IterativeProfiler.kt` (specifically `extractViolationPath`) and `/enforcer/src/main/kotlin/io/mazewall/Policy.kt` (specifically `validatePath`)
**Failure Hypothesis:** When a profiled workload attempts to access a file using a relative path (e.g. `Paths.get("data.txt")`), a `java.nio.file.AccessDeniedException` is thrown containing the relative path. The `IterativeProfiler` extracts this relative path and attempts to add it to the policy via `allowFsRead(path)`. However, `Policy.Builder.validatePath` strictly mandates absolute paths, throwing `IllegalArgumentException: Path must be absolute`, which crashes the profiling loop instead of resolving or canonicalizing the path.
**Context & Proof:** If a task performs `Files.readString(Paths.get("relative/file.txt"))`, Java throws `AccessDeniedException` where `t.file` is `"relative/file.txt"`. `extractViolationPath` returns `"relative/file.txt"`. `profile` calls `updatePolicyForViolation(currentPolicy, "relative/file.txt")`, which calls `builder.allowFsRead("relative/file.txt")`. Since `"relative/file.txt"` does not start with `"/"`, `validatePath` throws `IllegalArgumentException`. The retry loop in `IterativeProfiler` is immediately aborted, crashing the workload.
**Cascading Risk Potential:** High usability and stability failure. Completely prevents progressive/iterative profiling of any applications that rely on relative file paths.
**Needed:** In `IterativeProfiler.extractViolationPath`, if the extracted path is relative, resolve it to an absolute path relative to the JVM CWD (or a provided working directory) before returning it. Alternatively, canonicalize all paths in `updatePolicyForViolation` using `Paths.get(path).toAbsolutePath().normalize().toString()`.

### 🔴 [Severity: HIGH]: `IterativeProfiler` infinite retry loop and failure on disjoint prefix file paths
**Target:** `/profiler/src/main/kotlin/io/mazewall/profiler/iterative/IterativeProfiler.kt` (specifically `updatePolicyForViolation`)
**Failure Hypothesis:** The `IterativeProfiler` checks if read is already allowed using a naive string `startsWith` check. If the workload accesses a path whose prefix matches an already allowed path but is a different, longer directory name (e.g., `/var/log-extra` when `/var/log` is allowed), the check falsely returns `true`. The profiler then attempts to add a *write* rule instead of a *read* rule, causing subsequent read attempts to continue failing and forcing the profiler into an infinite discovery retry loop that aborts after 20 retries.
**Context & Proof:** If `currentPolicy` allowed read to `/var/log`, and a trapped read occurs on `/var/log-extra`, `isCurrentlyReadAllowed` evaluates to `true` (since `"/var/log-extra".startsWith("/var/log")` is true). So `updatePolicyForViolation` executes the `then` branch: `if (isCurrentlyReadAllowed) { builder.allowFsWrite(path) }`. Thus, it adds a write rule for `/var/log-extra` but NEVER adds a read rule! On the next retry, the thread tries to read `/var/log-extra` again, gets denied, and the same logic is executed. This continues until the retry count hits `maxRetries` (20), at which point the profiler crashes.
**Cascading Risk Potential:** High stability and usability bug. Blocks iterative profiling for applications with sibling directories sharing identical prefixes.
**Needed:** Use proper component-based `Path.startsWith` logic instead of raw string `startsWith`. Map the strings in `allowedFsReadPaths` to `Path` structures and normalize them, then compare using `java.nio.file.Path.startsWith`.

### 🔴 [Severity: HIGH]: Profiler connection failure on signal interruption inside `recvDescriptor`
**Target:** `/profiler/src/main/kotlin/io/mazewall/profiler/engine/ProfilerDaemon.kt` (specifically `recvDescriptor`)
**Failure Hypothesis:** The out-of-process daemon receives the seccomp listener file descriptor from the JVM via `recvmsg` on a Unix domain socket. If a POSIX signal (such as standard JVM GC safepointing signals) is delivered to the daemon's connection thread while it is blocked inside `recvmsg`, the system call returns `-1` with `errno == EINTR`. `recvDescriptor` treats this as a fatal connection failure, closes the socket, and aborts the profiling session, leaving the worker thread permanently deadlocked.
**Context & Proof:** If `LinuxNative.recvmsg` is interrupted by a signal, `returnValue` is `-1`. Since `-1 < 0`, `recvDescriptor` returns `null`. In `handleConnection`, the thread closes `socketFd` and returns, terminating the session. The tracee thread in the JVM remains frozen waiting for the daemon to ACK the listener FD, which never happens, resulting in a permanent JVM deadlock.
**Cascading Risk Potential:** High stability and reliability failure. Causes arbitrary, random JVM deadlocks during startup/GC cycles when running the profiler.
**Needed:** Wrap the `recvmsg` downcall in a loop in `recvDescriptor`. If `returnValue < 0` and `errno == 4` (EINTR), retry the `recvmsg` call. Only return `null` if the error is fatal (non-EINTR).

### 🔴 [Severity: HIGH]: `installOnProcess` process-wide seccomp synchronization (TSYNC) fails deterministically on standard JVMs
**Target:** `io.mazewall.seccomp.PureJavaBpfEngine`
**Failure Hypothesis:** Process-wide seccomp installation via `TSYNC` requires `no_new_privs` to be enabled on all threads in the thread group. In standard JVMs, background threads are spawned before `no_new_privs` is set, causing TSYNC to fail with `EACCES` under non-root configurations. The current exception error message is also highly misleading.
**Context & Proof:** The Linux kernel requires `no_new_privs` to be set on all sibling threads in the thread group for `SECCOMP_FILTER_FLAG_TSYNC` to succeed. When the JVM starts, GC threads, JIT threads, and VM helper threads are spawned at startup. In `PureJavaBpfEngine.installInternal`, the main thread calls `setNoNewPrivs()`, which only sets the flag on the *calling* thread. Pre-existing background threads do not get it. When `TSYNC` is attempted, the kernel returns `EACCES` (-13). The method catches this failure and throws an exception claiming "Your kernel may be too old to support SECCOMP_FILTER_FLAG_TSYNC", which is factually incorrect and misleads operators.
**Cascading Risk Potential:** High stability and deployment failure. Process-wide seccomp fails to install out-of-the-box on local developer setups or standard servers unless pre-set via an OCI container runtime or launcher wrapper.
**Needed:** Update the exception message in `PureJavaBpfEngine.kt` to clearly state that `TSYNC` failed due to missing `no_new_privs` on sibling threads, advising operators to run with OCI `allowPrivilegeEscalation: false` or pre-set `no_new_privs` using an external launcher.
### 🔴 [Severity: CRITICAL]: Seccomp Filter Bypass via `pkey_mprotect`
**Target:** `io.mazewall.BpfFilter`, `io.mazewall.Syscall`, `io.mazewall.seccomp.MmapProtectionTest`
**Failure Hypothesis:** The BPF filter correctly intercepts `mprotect` and `mmap` calls to prevent `PROT_EXEC` via argument inspection (checking `args[2]`). However, it misses modern Linux memory protection variants, specifically `pkey_mprotect` (`SYS_pkey_mprotect` / 329 on AMD64). Since this syscall is not explicitly hooked for argument inspection and may be allowed under loose policies or fallback behavior, an attacker who can call `pkey_mprotect` can mark memory as executable (`PROT_EXEC`), completely bypassing the Seccomp `NO_EXEC` protections designed to stop dynamic shellcode generation.
**Context & Proof:** `pkey_mprotect` takes the same `prot` parameter as `mprotect` but also takes a `pkey`. The current `BpfFilter.kt` only restricts `arch.mmap` and `arch.mprotect`. In `Syscall.kt`, there is no representation of `pkey_mprotect`. Thus, if `pkey_mprotect` is not explicitly blocked or handled via argument inspection like `mprotect`, it will fall back to the default action. Under `Policy.NO_EXEC`, `pkey_mprotect` isn't explicitly blocked, so it would fall to `ACT_ALLOW`, allowing unrestricted `PROT_EXEC` usage. This has been proven via `bypass_pkey.c` where `mprotect` with `PROT_EXEC` is blocked but `pkey_mprotect` with `PROT_EXEC` succeeds in bypassing.
**Vulnerability Chain Potential:** Very high. If an attacker achieves arbitrary code execution (or memory corruption) they can just use `pkey_mprotect` instead of `mprotect` to bypass JIT / dynamic shellcode protections in the sandbox.
**Needed:** Add `pkey_mprotect` to `Syscall`, map its number per architecture, and in `BpfFilter.buildFromActions` add it to the same argument inspection block that currently restricts `PROT_EXEC` in `mprotect` and `mmap`.
**Failure Hypothesis:** A thread pool processing multiple tasks with a whitelist policy (where `defaultAction != ACT_ALLOW`) will unconditionally attach a new, redundant Seccomp BPF filter on every task execution, eventually crashing the thread when the filter limit is reached.
```

