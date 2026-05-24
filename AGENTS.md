# Guidelines for AI Coding Agents in mazewall

Welcome, AI Agent. This repository contains **mazewall**, a kernel-enforced, thread-scoped and process-wide sandboxing library for JVM applications using Linux **Seccomp-BPF** and **Landlock LSM** via the JDK **Foreign Function & Memory (FFM) API**.

As an AI agent pair-programming on this project, you are assisting in transitioning this project from a Proof of Concept (PoC) to a production-grade library. The minimum supported JDK is **22** (FFM API finalization); the codebase targets **Java 25 idioms** where applicable. Because this is a security-critical project that directly interfaces with the Linux kernel and manipulates JVM threads, you must adhere strictly to the following rules, constraints, and engineering philosophies.

---

## 1. Core Engineering Philosophy & Tone

### Zero Hype, Absolute Certainty
*   **No Marketing or Speculative Language:** Avoid promotional, flashy, or hand-wavy descriptions. This library operates at the kernel-user space boundary where errors lead to fatal JVM deadlocks or JVM bypasses.
*   **Rigorous Decision Making:** Every choice must be double and triple checked. A single missed detail can result in catastrophic failure (JVM deadlocks, kernel instability, silent security bypasses).
*   **Honest Limitations:** Every security boundary must be documented with its exact threat model, caveats, and failure modes. If you are not 100% sure about a kernel behavior, JVM internal mechanism, or system call side-effect:
    1.  **Do not guess or assume.**
    2.  Search the codebase, `SECURITY_CONSIDERATIONS.md`, `profiler_design.md`, `containment_design.md`, and Linux manual pages — in that order. These files contain hard-won, project-specific kernel behavior discoveries that man pages do not cover.
    3.  Flag the uncertainty explicitly in comments and discuss it with the developer.
*   **Documentation Split:**
    *   **`/presentation`:** Addressed to general Backend/Software Engineers. Conceptually accessible; no BPF jump tables.
    *   **Core code, KDocs, & design docs:** Highly rigorous. Exact syscall numbers, FFM memory layouts, kernel invariants.
*   **Mandatory Documentation of Findings:** Any new architectural finding, kernel behavior discovery, or security nuance *must* be documented immediately in the appropriate Markdown file. Do not leave critical insights in conversation histories.

---

## 2. Strict Protection Against Unsafe Fallback / Bypass Scenarios

> [!WARNING]
> **CRITICAL SECURITY INSTRUCTION:** AI agents historically tend to implement "fail-safe" or "silent bypass" fallback behavior to make code "just work." **This is strictly unacceptable in a security library.**

*   **Never Implement Silent Bypasses:** Do not catch exceptions silently or downgrade a failed seccomp/Landlock installation to a warning-and-bypass unless that fallback is explicitly configured by the operator.
*   **Fail Closed by Default:** The **default `FallbackBehavior` is `FAIL`** (see `Platform.configuredFallback()` — it returns `FallbackBehavior.FAIL` unless the operator explicitly overrides via `-Dio.mazewall.fallback=WARN_AND_BYPASS` or `IO_MAZEWALL_FALLBACK=WARN_AND_BYPASS`). This is intentional and must not be changed.
*   **No Unconsulted Fallbacks:** Do not write automatic recovery loops or mock environments (like simulating a syscall return value via register manipulation) without explicit review from the developer.

---

## 3. Directory Structure & Architecture

The repository is organized as a multi-module Gradle project. The **`/utils`** module is the core library. Its source files are organized into two tiers.

### Enforcement Tier

| File                               | Responsibility                                                                                                                                                                                                                             |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Policy.kt`                        | Composable security policies. Supports `ALLOW_LIST` (default-deny) and `DENY_LIST` (default-allow) modes. Builder pattern.                                                                                                                 |
| `Syscall.kt`                       | `enum class Syscall` with `numberFor(arch)` dispatch.                                                                                                                                                                                      |
| `Arch.kt`                          | Architecture maps: CPU AUDIT identifiers, seccomp syscall numbers, per-syscall numbers for x86_64 and aarch64.                                                                                                                             |
| `BpfFilter.kt`                     | Compiles a `Policy` to a raw BPF instruction stream. Inverted linear scan for `ALLOW_LIST` mode to stay within 8-bit jump limit. Contains argument-inspection sequences for `mmap`/`mprotect`, `clone`, and `prctl`.                       |
| `SeccompEngine.kt`                 | Interface: `install(policy)`, `installOnProcess(policy)`, `isSupported`.                                                                                                                                                                   |
| `PureJavaBpfEngine.kt`             | `SeccompEngine` implementation. Sets `PR_SET_NO_NEW_PRIVS`, installs via `seccomp(2)` (falls back to `prctl(PR_SET_SECCOMP)` for old kernels), verifies with `PR_GET_SECCOMP`. If TSYNC fails, fails hard. See `containment_design.md §6`. |
| `LinuxNative.kt`                   | FFM-based syscall bindings. All calls capture `errno` via `Linker.Option.captureCallState("errno")`.                                                                                                                                       |
| `Platform.kt`                      | OS/arch support check and `FallbackBehavior` resolution. Default: `FAIL`.                                                                                                                                                                  |
| `Landlock.kt`                      | Landlock LSM integration. Negotiates highest supported ABI version. Handles JVM classpath whitelisting. See `containment_design.md §5`.                                                                                                    |
| `ContainedExecutors.kt`            | Primary public API. Wraps `ExecutorService`, provides `installOnCurrentThread()` / `installOnProcess()`. Manages incremental filter stacking with deduplication and depth enforcement. See `containment_design.md §4`.                     |
| `ContainmentViolationException.kt` | Typed exception for EPERM/EACCES violations. Always wraps the original exception as its cause.                                                                                                                                             |

### Profiling Tier

| File                   | Responsibility                                                                                                                                                                      |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Profiler.kt`          | High-level USER_NOTIF profiler API. Spawns `ProfilerDaemon`, installs BPF with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, passes fd via coordinator thread over SCM_RIGHTS.                |
| `ProfilerDaemon.kt`    | Out-of-process daemon. Receives USER_NOTIF fd, loops on `SECCOMP_IOCTL_NOTIF_RECV`, resolves paths from `/proc/<pid>/fd/`, sends `TraceEvent` structs back, issues `FLAG_CONTINUE`. |
| `BobCompiler.kt`       | Compiles raw `TraceEvent` lists into a `BillOfBehavior`.                                                                                                                            |
| `BillOfBehavior.kt`    | Immutable record of kernel-level observations. SBoB-aligned. Produces `Policy` via `toPolicy()` or Kotlin DSL via `toDsl()`.                                                        |
| `TraceEvent.kt`        | Wire-level event record: `(pid, syscallName, args, paths)`.                                                                                                                         |
| `ProfilingResult.kt`   | `(returnValue: T, behavior: BillOfBehavior)`.                                                                                                                                       |
| `IterativeProfiler.kt` | Tier A profiler (no daemon, no USER_NOTIF). Progressive Landlock restriction with `AccessDeniedException` retry. The **only** unprivileged way to profile Landlock paths and `io_uring`. |

### Additional Modules
*   **`/demo`:** Log4Shell-style RCE showcase blocked by `Policy.NO_EXEC`.
*   **`/presentation`:** Developer articles and design trade-offs.
*   **`/docs`:** Additional documentation and references.
*   **`/killercoda`:** Interactive tutorial environment configuration.

---

## 4. Critical JVM & Linux Kernel Safety Rules (The Hard Limits)

### Rule A: Never Block JVM Coordination System Calls

If your policy blocks syscalls required for thread scheduling or memory management, the next JVM safepoint will permanently freeze the entire JVM. **No recovery is possible.**

**Prohibited from blocking:**
*   `futex` — JVM thread synchronization and parking
*   `sched_yield` — spinlock contention
*   `rt_sigreturn` — return from JVM signal handlers
*   `rt_sigaction` / `sigaction` — HotSpot installs its own signal handlers during JVM init
*   `close` — JVM and FFM close fds constantly; blocking leaks fds and destabilizes the runtime
*   `gettid` — thread identification
*   `mmap` — JVM heap and code cache; `BpfFilter` blocks only `mmap(PROT_EXEC)` via argument inspection
*   `madvise` / `mprotect` — GC page allocation; `BpfFilter` blocks only `mprotect(PROT_EXEC)` via argument inspection
*   `clone` **with `CLONE_THREAD` flag** — JVM thread creation. `BpfFilter` inspects clone flags rather than blocking the syscall number. **Adding `Syscall.CLONE` to a policy block list will deadlock the JVM at the next thread creation.**
*   `prctl` — JVM calls `prctl(PR_SET_NAME, ...)` for thread naming. `BpfFilter` whitelists safe options via argument inspection. Do not block `prctl` by syscall number alone.

**When modifying `BpfFilter.kt`:** preserve the multi-instruction argument-inspection sequences for `mmap`/`mprotect`, `clone`, and `prctl`. See `containment_design.md §3` for the exact sequences. Replacing them with simple `BPF_JEQ` checks against the syscall number silently deletes the nuanced protections.

### Rule B: Prevent Loom Virtual Thread Carrier Poisoning

Seccomp filters bind permanently to the underlying Linux OS thread (LWP). If a filter is installed from within a Virtual Thread, it binds to the carrier thread and poisons all subsequent virtual threads scheduled on that carrier.

*   **The Protection:** All seccomp installation entry points detect virtual threads via `Thread.currentThread().isVirtual` and throw `IllegalStateException`. **Any new entry point that installs a seccomp filter must include this same guard.**
*   **The correct pattern for virtual threads + seccomp:** Pre-restrict carrier threads before mounting virtual threads on them:

    ```kotlin
    val carriers = Executors.newFixedThreadPool(4)
    val latch = CountDownLatch(4)
    repeat(4) {
        carriers.submit {
            ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)
            latch.countDown()
        }
    }
    latch.await()
    val vtFactory = Thread.ofVirtual().scheduler(carriers).factory()
    val pool = Executors.newThreadPerTaskExecutor(vtFactory)
    ```

### Rule C: Shared-Memory ACE Escape Caveat

Thread-scoped seccomp is **not** an absolute security boundary against an attacker with Arbitrary Code Execution (ACE) on the sandboxed thread. All JVM threads share the same address space.

**Tier 1 (process-wide `NO_EXEC`) is a hard architectural dependency for Tier 2 (thread-scoped), not an optional recommendation.** Without process-wide lockdown, a thread-level ACE pivot can elevate to the entire process through the shared heap. Never write documentation, examples, or tests that present Tier 2 thread-scoped containment *alone* as a complete security solution.

Frame thread-scoped seccomp (Tier 2) as a blast-radius mitigator against *data-driven* attacks (SSRF, XXE, SQL injection). Frame process-wide `NO_EXEC` (Tier 1) as the mandatory backstop that prevents ACE from escalating to process execution. For the full threat model with attack scenarios, see `SECURITY_CONSIDERATIONS.md §1` and `§2`.

### Rule D: Profiler ACK Deadlock Prevention

> [!CAUTION]
> If you modify `ProfilerDaemon.kt` or `Profiler.startTraceListener()`, every code path that receives a USER_NOTIF event **must** either send `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (via the `0x41` ACK byte protocol) or `SECCOMP_USER_NOTIF_FLAG_KILL_THREAD`. A missed continue permanently deadlocks the worker OS thread with no timeout and no JVM-level detection. See `profiler_design.md` for the full protocol.

### Rule E: Landlock Must Be Applied Before Seccomp

Landlock's own syscalls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) are blocked by a restrictive seccomp policy if seccomp is installed first. The `applyContainment()` method in `ContainedExecutors.ContainedExecutorWrapper` enforces the correct order: **Landlock first, then `installOnCurrentThread()`**. Do not change this order.

---

## 5. Development & Coding Conventions

### A. FFM API Patterns

*   **Minimum JDK: 22.** The FFM API was finalized in Java 22. The codebase targets **Java 25 idioms** (sealed classes, pattern matching, structured concurrency patterns) where applicable, but the library must remain runnable on JDK 22+. Do not use Java 25-only API surface without a version guard.
*   Use `Arena.ofConfined()` with `.use { }` for safe off-heap allocations (`MemorySegment`).
*   **Always capture `errno`** using `Linker.Option.captureCallState("errno")`. Read it from the captured state `MemorySegment` **immediately** after the call, before any other FFM call can overwrite it. See `containment_design.md §8` for the exact pattern.
*   Use `ValueLayout.JAVA_INT` (4 bytes) for 32-bit kernel fields like `sock_filter.k`. Using `JAVA_LONG` produces silently-corrupt BPF programs.
*   **`SECCOMP_FILTER_FLAG_NEW_LISTENER` and `SECCOMP_FILTER_FLAG_TSYNC` are mutually exclusive.** `NEW_LISTENER` is used by `Profiler`. `TSYNC` is used by `installOnProcess`. Never combine them.

### B. Containment Exception Translation

The violation detector in `ContainedExecutors.isDirectContainmentViolation()` uses a two-priority strategy:

1.  **Priority 1 (locale-independent):** `\berror[=:]\s*(1|13)\b` — matches JVM-encoded errno 1 (`EPERM`) and 13 (`EACCES`).
2.  **Priority 2 (for `IOException`/`SocketException` only):** `(?i)\bOperation not permitted\b|\bPermission denied\b|\brefusé\b|\bverweigert\b|\bnegado\b` and `"Cannot run"`.
3.  `AccessDeniedException` (`java.nio.file`) — always treated as a violation.
4.  **Prohibited:** broad fragments like `"denied"` without class restrictions (false positives on business logic exceptions).

Always call `isContainmentViolation(t)` (the full cause-chain traversal), not `isDirectContainmentViolation(t)` alone.

---

## 6. Testing and Verification Guidelines

*   **Testing is Mandatory.** Untested code in a security library is a vulnerability. Any bugfix, behavioral change, or new architectural detail **must** be accompanied by an automated test.
*   **Running Tests:** Always run using the custom OCI profile:
    ```bash
    podman compose up -d
    podman compose exec mazewall ./gradlew test
    ```
    The container is named `mazewall` (see `compose.yml`). The profile (`podman-seccomp.json`) whitelists `seccomp(2)` for unprivileged filter stacking.

*   **Test tier requirements:**

    | Test File                       | Requires Podman? | Requires Linux? | Kernel min        |
    |---------------------------------|------------------|-----------------|-------------------|
    | `BpfFilterTest.kt`              | No               | No (pure unit)  | —                 |
    | `PolicyTest.kt`                 | No               | No (pure unit)  | —                 |
    | `ContainedExecutorsTest.kt`     | **Yes**          | Yes             | 4.8+              |
    | `VirtualThreadGuardrailTest.kt` | **Yes**          | Yes             | 4.8+              |
    | `StackingIntegrationTest.kt`    | **Yes**          | Yes             | 4.8+              |
    | `MmapProtectionTest.kt`         | **Yes**          | Yes             | 4.8+              |
    | `PrctlProtectionTest.kt`        | **Yes**          | Yes             | 4.8+              |
    | `ProfilerIntegrationTest.kt`    | **Yes**          | Yes             | 5.0+ (USER_NOTIF) |
    | `LandlockTest.kt`               | No               | Yes             | 5.13+             |
    | `IterativeProfilerTest.kt`      | No               | Yes             | 5.13+             |

*   **Platform Guards:** Use `@EnabledOnOs(OS.LINUX)` on all Linux-only integration tests.
*   **Yama `ptrace_scope`:** `Profiler` calls `prctl(PR_SET_PTRACER, daemonPid)` to allow the daemon to read worker memory under Yama LSM. Do not remove this call.
*   **GraalVM roadmap:** Native AOT is planned but not yet implemented. Keep a clean separation between FFM native bindings and high-level policy logic.

---

## 7. Key Design Documents

Before modifying components in the profiling or enforcement tiers, read the relevant design document first:

| Document                     | Covers                                                                                                                                                                                        |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `containment_design.md`      | BPF linear scan rationale, argument-inspection BPF sequences, incremental filter stacking, Landlock ordering, `PureJavaBpfEngine` install sequence, FFM struct layouts, errno capture pattern |
| `profiler_design.md`         | USER_NOTIF architecture (Tier S/A/B), safepoint deadlock discovery, out-of-process daemon design, ACK protocol, `BillOfBehavior` SBoB alignment                                               |
| `SECURITY_CONSIDERATIONS.md` | Threat model, ACE escape caveat, `mmap`/`mprotect`/`clone` argument inspection rationale, `prctl` attack surface, `PR_SET_NO_NEW_PRIVS` implications, K8s deployment, Yama `ptrace_scope`     |
