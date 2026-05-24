# Technical Design: Containment Engine & Incremental Filter Stacking

This document covers the implementation details of the enforcement tier in `mazewall`:
how policies become live BPF filters, how filters stack incrementally, and how Landlock
integrates with the seccomp pipeline. Read this before modifying `ContainedExecutors.kt`,
`PureJavaBpfEngine.kt`, `BpfFilter.kt`, or `Landlock.kt`.

---

## 1. The Enforcement Pipeline

```
Policy (syscalls: Set<Syscall>, mode: Mode, allowMmapExec, ...)
    │
    ▼
BpfFilter.build(arch, policy)
    │  - architecture check prologue (AUDIT_ARCH_* constant)
    │  - clone3 ENOSYS trap (unconditional)
    │  - argument-inspection sequences for mmap/mprotect, clone, prctl
    │  - linear scan over restricted syscall numbers (sorted IntArray)
    │  - default ALLOW (DENY_LIST) or DENY (ALLOW_LIST) at the tail
    │
    ▼  Array<SockFilter>
PureJavaBpfEngine.install(policy)  /  installOnProcess(policy)
    │  1. prctl(PR_SET_NO_NEW_PRIVS, 1)
    │  2. pack sock_fprog struct via FFM Arena
    │  3. syscall(seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog)
    │  4. fallback: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)   [thread-local only]
    │  5. verify: prctl(PR_GET_SECCOMP) == 2
    │
    ▼
ContainedExecutors.installInternal(processWide, vararg policies)
    │  - deduplicates against THREAD_BLOCKED / PROCESS_BLOCKED state
    │  - enforces 32-filter depth limit
    │  - synchronized(processLock) to prevent TOCTOU race
    │  - updates thread-local or process-wide tracking state
```

---

## 2. Why a Linear BPF Scan (Not a BST)

BPF jump offsets are 8-bit unsigned integers — the maximum forward jump is 255 instructions.
A Binary Search Tree layout for even a moderately sized syscall set (e.g. `PURE_COMPUTE`'s
~40 syscalls) can require jumps that exceed this limit, requiring complex instruction
rewriting or label patching.

The linear scan emits two instructions per restricted syscall number. The logic
is inverted based on the policy mode:

**DENY_LIST mode:**
```
BPF_JEQ(nr)  → jt=0, jf=1     # if nr matches: jt=0 (no skip) → fall into RET_DENY
BPF_RET(DENY)                  # if nr does not match: jf=1 (skip this RET_DENY)
```

**ALLOW_LIST mode:**
```
BPF_JEQ(nr)  → jt=0, jf=1     # if nr matches: jt=0 (no skip) → fall into RET_ALLOW
BPF_RET(ALLOW)                 # if nr does not match: jf=1 (skip this RET_ALLOW)
```

In Classic BPF, `jt` and `jf` are **instruction skip counts** (not jump labels).
`jt=0` means "if condition is true, skip 0 instructions" (execute the next instruction immediately).
`jf=1` means "if condition is false, skip 1 instruction" (skip over the `RET_DENY`).

For 40 syscalls this produces ~80 BPF instructions — far below both the 255-offset
and the 4096-instruction kernel BPF limits. Performance: BPF is evaluated in the kernel
before the syscall; the linear scan overhead is negligible compared to the syscall itself.

---

## 3. Argument-Inspection Sequences

`BpfFilter` does **not** block these syscalls by number — it emits multi-instruction
BPF sequences that inspect arguments. **Do not replace these sequences with simple
`BPF_JEQ` checks against the syscall number.** Doing so silently removes the nuanced
protections.

### 3a. `mmap` and `mprotect` — block `PROT_EXEC`

`struct seccomp_data` byte offsets: `nr`=0, `arch`=4, `instruction_pointer`=8 (8 bytes), `args[0]`=16, `args[1]`=24, `args[2]`=32, ...
For `mmap`/`mprotect`, `prot` is the 3rd argument → `args[2]` → **byte offset 32**.

```
BPF_JEQ(syscall_nr == mmap, match, skip_5)  # if not mmap, skip 4 instructions
BPF_LD offset=32                             # load args[2] (prot) lower 32 bits
BPF_JSET 0x04, match, skip_1               # (BPF_JMP|0x40|BPF_K): if PROT_EXEC bit set, jt=0 (deny); else jf=1 (skip deny)
BPF_RET(DENY)
BPF_LD offset=0                              # restore NR for subsequent checks
# identical 5-instruction sequence for mprotect (syscall_nr == mprotect)
```

> **`JSET` semantics:** `jt=0, jf=1` — if `(ACC & 0x04) != 0` (PROT_EXEC IS set): jt=0, execute `RET_DENY` immediately; else: jf=1, skip over `RET_DENY`.

This blocks only `mmap` / `mprotect` calls where the caller requests executable memory.
The JVM's own JIT and GC `mmap`/`mprotect` calls do not use `PROT_EXEC` in the way
that shellcode injection does — they are whitelisted by this check automatically.

### 3b. `clone` — allow only `CLONE_THREAD`

`clone` flags are the 1st argument → `args[0]` → **byte offset 16**.
`CLONE_THREAD = 0x00010000`, `CLONE_VM = 0x00000100`, mask = `0x00010100`.

```
BPF_JEQ(syscall_nr == clone, match, skip_5)
BPF_LD offset=16                          # load args[0] (clone flags)
BPF_ALU|BPF_AND|BPF_K (0x54) 0x00010100  # mask to CLONE_VM | CLONE_THREAD
BPF_JEQ(0x00010100, skip_1, match)        # both bits set → JVM thread creation → skip deny
BPF_RET(DENY)
BPF_LD offset=0                           # restore NR
```

> **`BPF_AND` note:** There is no standalone `BPF_AND` opcode. This is `BPF_ALU | BPF_AND | BPF_K` = opcode `0x54`. The operand `K` is the mask value.

The JVM creates threads via `clone(CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | ...)`.
Process forking (`fork`, `vfork`, or `clone` without `CLONE_THREAD`) hits `DENY`.
An agent who naively adds `Syscall.CLONE` to a policy's block list would bypass
this inspection and deadlock the JVM at the next thread creation.

### 3c. `clone3` — always return `ENOSYS`

`clone3` is blocked unconditionally with `ENOSYS` (not `EPERM`) to force libc to
fall back to the inspectable `clone`. This is not controlled by `allowNonThreadClone`.

### 3d. `prctl` — whitelist safe options

```
BPF_JEQ(syscall_nr == prctl, match, skip_9)
BPF_LD(args[0])                    # load option
BPF_JEQ(PR_SET_NAME (15), allow, ...)
BPF_JEQ(PR_GET_NAME (16), allow, ...)
BPF_JEQ(PR_GET_SECCOMP (21), allow, ...)
BPF_JEQ(PR_SET_SECCOMP (22), allow, ...)
BPF_JEQ(PR_SET_NO_NEW_PRIVS (38), allow, ...)
BPF_JEQ(PR_GET_NO_NEW_PRIVS (39), allow, ...)
BPF_RET(DENY)
BPF_LD(syscall_nr)
```

The JVM calls `prctl(PR_SET_NAME)` constantly for thread naming. Blocking `prctl`
outright (via `Syscall.PRCTL` in the block list) is **not safe and must never be done**:
it would block the whitelisted options and prevent `PR_SET_SECCOMP` from being called
during filter-stacking. The argument-inspection path above restricts `prctl` to the
safe subset while leaving installation and naming intact.

> **`allowUnsafePrctl = true`:** Setting this flag on the policy skips the argument
> inspection entirely, leaving `prctl` unrestricted. Only use this when filter stacking
> is explicitly required beyond the whitelisted options.

### 3e. Intentionally Unrestricted JVM Syscalls

The following syscalls are **deliberately not present in any argument-inspection sequence
or block-list**. They are left completely unrestricted because blocking them causes
catastrophic JVM instability:

| Syscall        | Reason left unrestricted                                                                                                                |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `futex`        | JVM thread parking/unparking and monitor synchronization. Blocking causes deadlock at the next `synchronized` block or `Object.wait()`. |
| `sched_yield`  | Thread scheduler cooperation during spinlock contention.                                                                                |
| `rt_sigreturn` | Return from JVM signal handlers (HotSpot uses `SIGSEGV` for safepoint polling). Blocking causes instant JVM abort.                      |
| `rt_sigaction` | HotSpot installs its own signal handlers at JVM init. Blocking prevents the JVM from starting.                                          |
| `madvise`      | GC page lifecycle management (ZGC, G1).                                                                                                 |
| `gettid`       | Thread identification used by GC and diagnostic paths.                                                                                  |
| `close`        | JVM and FFM close file descriptors constantly. Blocking causes fd leaks and runtime instability.                                        |

Do not add any of these to a policy's block-list. See `SECURITY_CONSIDERATIONS.md §9`
for the full safepoint/GC deadlock analysis.

---

## 4. Incremental Filter Stacking

### Why stacking exists

Seccomp filters are monotonic: once a syscall is blocked on a thread, it cannot be
unblocked. The kernel accumulates filters in a linked list; each new filter is evaluated
in order, and the most-restrictive result wins. `ContainedExecutors` stacks filters
incrementally to allow multiple `installOnCurrentThread` calls (e.g. from nested
executor wrapping or the profiler) without wasting filter slots.

### How deduplication works

`ContainedExecutors` maintains:

| State                                  | Type                           | Purpose                                            |
|----------------------------------------|--------------------------------|----------------------------------------------------|
| `THREAD_BLOCKED`                       | `ThreadLocal<Set<Syscall>>`    | Syscalls already blocked on this OS thread         |
| `PROCESS_BLOCKED`                      | `CopyOnWriteArraySet<Syscall>` | Syscalls blocked process-wide via TSYNC            |
| `FILTER_DEPTH`                         | `ThreadLocal<Int>`             | Count of thread-local filter installations         |
| `PROCESS_FILTER_DEPTH`                 | `AtomicInteger`                | Count of process-wide filter installations         |
| `THREAD_ALLOWS_MMAP_EXEC`              | `ThreadLocal<Boolean>`         | Whether mmap PROT_EXEC inspection is still pending |
| `PROCESS_ALLOWS_MMAP_EXEC`             | `@Volatile Boolean`            | Same, process-wide                                 |
| *(identical pattern for clone, prctl)* |                                |                                                    |

Before installing, `installInternal` computes:
- `newBlocks = policy.syscalls - (THREAD_BLOCKED + PROCESS_BLOCKED)` → only truly new syscalls
- `needsMmapProtection`, `needsCloneProtection`, `needsPrctlProtection` → argument-inspection gates

If `newBlocks` is empty and no gates need updating, **no filter is installed** — the
depth counter is preserved.

### The `synchronized(processLock)` requirement

The deduplication check and the state update are inside `synchronized(processLock)`.
This prevents two threads from simultaneously calculating "this syscall is not yet
blocked" and both installing redundant filters, which would waste depth slots.
**Do not remove or weaken this lock.**

### The 32-filter depth limit

The kernel hard limit is 32 seccomp filters per thread (thread-local + process-wide combined).
- Depth ≥ 32: `IllegalStateException` is thrown before the install.
- Depth > 10: a `WARNING` log is emitted. Do not suppress this.

Exceeding 32 causes the next `seccomp()` call to return `EINVAL`, silently leaving
the policy partially unenforced. The current limit of 32 is enforced by the kernel
regardless of any library-level tracking.

### Process-wide vs. thread-local path

```
installOnProcess()  →  PureJavaBpfEngine.installOnProcess()
    - uses SECCOMP_FILTER_FLAG_TSYNC
    - TSYNC synchronises the new filter to **all threads in the same thread group,
      including those created after the call**
    - if seccomp(2) + TSYNC fails → throws `IllegalStateException` immediately;
      **never falls back to thread-local installation**
    - Kernel 5.7+ changed TSYNC semantics: pre-5.7, any mismatch returns `EINVAL`;
      5.7+ returns `EINVAL` only for true incompatibilities. In all cases,
      `mazewall` treats any TSYNC failure as a hard error.
    - updates PROCESS_BLOCKED, PROCESS_FILTER_DEPTH, PROCESS_ALLOWS_* atomics

installOnCurrentThread()  →  PureJavaBpfEngine.install()
    - uses flags=0 (thread-local only)
    - falls back to prctl(PR_SET_SECCOMP) on old kernels
    - updates THREAD_BLOCKED, FILTER_DEPTH, THREAD_ALLOWS_* ThreadLocals
```

`SECCOMP_FILTER_FLAG_TSYNC` and `SECCOMP_FILTER_FLAG_NEW_LISTENER` are mutually
exclusive. `NEW_LISTENER` is used exclusively by `Profiler`. Never combine them.

---

## 5. Landlock Integration

### Ordering requirement

Landlock installation calls `landlock_create_ruleset(2)`, `landlock_add_rule(2)`,
and `landlock_restrict_self(2)` — all standard syscalls. If seccomp is installed
first with a policy that blocks `openat` (e.g. `PURE_COMPUTE`), these Landlock
syscalls fail before Landlock can activate.

**Enforced order in `ContainedExecutors.ContainedExecutorWrapper.applyContainment()`:**
1. `Landlock.applyRuleset(policy)`    ← first
2. `installOnCurrentThread(policy)`   ← second

Do not change this order.

### Per-thread application (THREAD_LANDLOCK_APPLIED)

`THREAD_LANDLOCK_APPLIED` is a `ThreadLocal<Boolean>` that ensures the Landlock
ruleset is applied only once per OS thread. Applying it a second time on the same
thread creates a second intersective Landlock domain that **narrows** permissions
further. This can block JVM classpath reads and cause `NoClassDefFoundError` at
unpredictable points during lazy classloading.

### ABI version negotiation

Landlock `Landlock.kt` negotiates the highest ABI version the running kernel supports
via `landlock_create_ruleset(size=0, flags=LANDLOCK_CREATE_RULESET_VERSION)`. Using
a feature flag from a newer ABI than the kernel supports **silently drops those rules**
without returning an error. Always document the minimum ABI version required when
adding new Landlock access-right flags.

### JVM classpath whitelist (`allowJvmClasspath()`)

If Landlock is active and a restricted thread triggers lazy classloading of a class
whose `.jar` file is not in the allowed read paths, the kernel returns `EACCES` and
the JVM throws `NoClassDefFoundError`. `Policy.Builder.allowJvmClasspath()` reads
`java.home` and `java.class.path` at policy-build time to prevent this.

Always call `allowJvmClasspath()` when writing tests that activate Landlock on a
thread that may still lazy-load test infrastructure classes.

### Landlock TSYNC (ABI 8 / Linux 7.0+)

Historically, Landlock rulesets were strictly thread-scoped and could not be applied retroactively to sibling threads. To lock down a multi-threaded JVM process on older kernels, a wrapper launcher (e.g., C or Rust) must apply the ruleset before invoking `execve` on the JVM.

Linux 7.0 (ABI 8) introduces `LANDLOCK_RESTRICT_SELF_TSYNC` which synchronizes the ruleset to all existing threads in the process atomically. However, `mazewall` keeps this flag **disabled by default** (always passing `flags=0L` during enforcement ruleset application) due to:
1. **Sibling Thread Transparency:** The JIT compiler and GC worker threads often require system path permissions that sandboxed application threads lack. Retroactive lockdown causes process deadlocks or aborts.
2. **Test Suite Collisions:** TSYNC sandboxes the parent Gradle worker process during execution, crashing completely unrelated sibling tests with `AccessDeniedException`.

### `applyProfilingRuleset()` vs. `applyRuleset(policy)`

- `applyRuleset(policy)` — enforcement path; used by `ContainedExecutors`.
- `applyProfilingRuleset()` — applies a restrictive Landlock domain. This is used by the **Iterative Profiler (Tier A)** to trigger path denials that are then caught and resolved. In older design iterations, it was used with `MAZEWALL_PROFILER_AUDIT=true` to trigger kernel audit events, but this is now deprecated for transparent profiling as Landlock lacks a permissive mode.

---

## 6. `PureJavaBpfEngine` Installation Sequence

For reference: the exact steps performed by `PureJavaBpfEngine.installInternal()`:

```
1. prctl(PR_SET_NO_NEW_PRIVS, 1)         → required before any unprivileged seccomp call
2. Arch.current()                         → resolve arch (x86_64 / aarch64)
3. BpfFilter.build(arch, policy)          → compile BPF program
4. Arena.ofConfined().use { arena ->
     LinuxNative.newSockFProg(arena, filters)   → pack sock_fprog struct (FFM)
     syscall(seccompNr, SECCOMP_SET_MODE_FILTER, flags, &prog)
   }
5a. If syscall returns 0 → success
5b. If thread-local and syscall fails:
       prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)  ← older kernel fallback
    If process-wide (TSYNC) and syscall fails → IllegalStateException (no fallback)
6. prctl(PR_GET_SECCOMP) == 2             → verify filter is active
   (skipped if Syscall.PRCTL is in the blocked set — prctl would be blocked)
```

---

## 7. FFM Struct Layouts

All off-heap structs are allocated via `Arena.ofConfined()` to ensure automatic
deallocation at the end of the scope. Key layouts:

### `sock_filter` (8 bytes)
```
offset 0: code  (short / JAVA_SHORT, 2 bytes)
offset 2: jt    (byte  / JAVA_BYTE,  1 byte)
offset 3: jf    (byte  / JAVA_BYTE,  1 byte)
offset 4: k     (int   / JAVA_INT,   4 bytes)   ← MUST be JAVA_INT, not JAVA_LONG
```

### `sock_fprog` (16 bytes on x86_64)
```
offset 0: len     (short / JAVA_SHORT, 2 bytes)  — number of sock_filter instructions
offset 2: padding (6 bytes for alignment)
offset 8: filter  (address / ValueLayout.ADDRESS, 8 bytes)  — pointer to sock_filter array
```

Getting `k` wrong (using `JAVA_LONG` instead of `JAVA_INT`) produces a silently-corrupt
BPF program. The kernel BPF verifier may or may not catch this depending on the values
involved — it is not safe to rely on the verifier as a correctness check.

---

## 8. `errno` Capture Pattern

```kotlin
// Correct pattern (from LinuxNative.kt):
val capturedState = CAPTURED_STATE_LAYOUT.allocate(arena)
val handle = Linker.nativeLinker().downcallHandle(
    addr,
    descriptor,
    Linker.Option.captureCallState("errno")
)
val result = handle.invokeWithArguments(capturedState, ...)
val errno = capturedState.get(ValueLayout.JAVA_INT, errnoOffset)
// Read errno BEFORE any other FFM call — the captured state is not thread-safe
// across multiple calls.
```

Do not call `Native.getLastError()` — this method does not exist in the standard
JDK FFM API. Do not read errno after performing another FFM downcall, as the
captured state segment reflects only the most recent call.
