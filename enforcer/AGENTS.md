# Guidelines for AI Coding Agents in mazewall-enforcer

Welcome, AI Agent. This is the **`:enforcer`** subproject of **mazewall**. It contains the core, production-grade security containment and enforcement code.

Because this library operates directly at the kernel-user space boundary and manipulates JVM OS threads, mistakes can cause fatal VM deadlocks or silent security bypasses. You MUST adhere to these strict limits, rules, and guidelines when modifying files in this subproject.

---

## 🚧 Core Invariants & Boundaries

### 1. Never Block JVM Coordination System Calls
If a seccomp policy blocks syscalls required for thread scheduling, signal routing, or memory management, the JVM will permanently freeze at the next safepoint or GC cycle.
**Prohibited from blocking:**
- `futex` — thread synchronization.
- `sched_yield` — lock contention.
- `rt_sigreturn` / `rt_sigaction` — signals and HotSpot error/exit routing.
- `close` — file descriptor management.
- `gettid` — thread identification.
- `mmap` — blocks only `mmap(PROT_EXEC)` via argument inspection.
- `mprotect` — blocks only `mprotect(PROT_EXEC)` via argument inspection.
- `clone` **with `CLONE_THREAD` flag** — JVM thread creation. **Blocking the clone syscall directly deadlocks the JVM during thread creation.**
- `prctl` — Thread naming and controls. Whitelists safe operations via argument inspection.

### 2. Protect Against Loom Carrier Poisoning
Seccomp filters bind permanently to the OS thread (LWP). Installs from virtual threads contaminate the carrier thread, poisoning all future virtual threads scheduled on it.
- **Rule:** Any new installation entrypoint must assert `!Thread.currentThread().isVirtual` and throw an `IllegalStateException` on failure.
- **Virtual Threads + Seccomp Pattern:** To safely run virtual threads on seccomp-restricted carrier threads, pre-restrict carrier threads before mounting virtual threads:
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

### 3. Landlock-Seccomp Ordering Invariant
- **Rule:** Landlock's configuration system calls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) are blocked by Seccomp policies. Therefore, **Landlock must always be initialized first before Seccomp is installed**.
- The `applyContainment()` method in `ContainedExecutors.ContainedExecutorWrapper` enforces this correct order. **Do not change this sequence.**

### 4. Fail Closed by Default
- **Rule:** Do not write "fail-safe" or "silent bypass" fallback behavior. If a seccomp filter or Landlock rule cannot be installed, and `FallbackBehavior` resolves to `FAIL` (the default), you must throw a hard exception or crash the process. Silent bypasses are strictly forbidden.

### 5. BPF Compiler & Argument Safety
- **Multi-Instruction Argument Inspection:** When modifying `BpfFilter.kt`, preserve the multi-instruction argument-inspection sequences for `mmap`/`mprotect`, `clone`, and `prctl`. Do not replace them with simple `BPF_JEQ` checks against the syscall numbers; doing so deletes crucial protection context.
- **Sock Filter Field Layouts:** Use `ValueLayout.JAVA_INT` (4 bytes) for 32-bit `sock_filter` fields (`code`, `jt`, `jf`, `k`). Specifying a `JAVA_LONG` corrupts BPF filter streams silently.
- **Mutex Flags:** `SECCOMP_FILTER_FLAG_NEW_LISTENER` (used by profiler) and `SECCOMP_FILTER_FLAG_TSYNC` (used by enforcer) are mutually exclusive. Never combine them.

### 6. FFM API Patterns
- **Minimum JDK:** 22 (FFM API finalization). Target Java 25 idioms where applicable, but the library must remain compilable/runnable on JDK 22+.
- **Off-heap Memory:** Use `Arena.ofConfined()` with `.use { }` for safe, deterministic off-heap allocations (`MemorySegment`).
- **Always Capture `errno`:** Native bindings must use `Linker.Option.captureCallState("errno")` and read it from the captured segment *immediately* after execution before another FFM call overwrites it. See `containment_design.md §8` for the exact pattern.

### 7. Containment Exception Translation
The violation detector in `ContainedExecutors.isDirectContainmentViolation()` uses a two-priority strategy:
1. **Priority 1 (locale-independent):** `\berror[=:]\s*(1|13)\b` — matches JVM-encoded errno 1 (`EPERM`) and 13 (`EACCES`).
2. **Priority 2 (for `IOException`/`SocketException` only):** `(?i)\bOperation not permitted\b|\bPermission denied\b|\brefusé\b|\bverweigert\b|\bnegado\b` and `"Cannot run"`.
3. `AccessDeniedException` (`java.nio.file`) — always treated as a violation.
4. **Prohibited:** broad fragments like `"denied"` without class restrictions (avoid false positives on standard business logic exceptions).
- **Traversing:** Always call `isContainmentViolation(t)` (performs cause-chain traversal) rather than calling `isDirectContainmentViolation(t)` directly.

---

## 🔄 Verification & Testing

Every modification inside `:enforcer` must be verified using the unprivileged OCI container:
```bash
podman compose exec mazewall ./gradlew :enforcer:check
```

- **Lints & Style:** Spotbugs and Detekt analyses must pass completely.
- **Coverage Rules:**
  - `Landlock*` instruction coverage must remain $\ge 65\%$.
  - `LinuxNative*` instruction coverage must remain $\ge 78\%$.
  - Core enforcement classes must remain $\ge 80\%$.
- **Test annotations:** Use `@EnabledIfLinuxAndSupported` to guard platform-specific tests.

---

## 📓 Code Issues & Discoveries Journal
If you discover a kernel-level behavior, FFM nuance, or bug during development, you MUST log it immediately in `docs/internals/code_issues_backlog.md`.

