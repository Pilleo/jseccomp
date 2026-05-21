# Technical Design: Containment Engine & Incremental Filter Stacking

This document covers the implementation details of the enforcement tier in `jseccomp`:
how policies become live BPF filters, how filters stack incrementally, and how Landlock
integrates with the seccomp pipeline. Read this before modifying `ContainedExecutors.kt`,
`PureJavaBpfEngine.kt`, `BpfFilter.kt`, or `Landlock.kt`.

---

## 1. The Enforcement Pipeline

```
Policy (blocked: Set<Syscall>, allowMmapExec, allowNonThreadClone, ...)
    │
    ▼
BpfFilter.build(arch, policy)
    │  - architecture check prologue (AUDIT_ARCH_* constant)
    │  - argument-inspection sequences for mmap/mprotect, clone, clone3, prctl
    │  - linear scan over blocked syscall numbers (sorted IntArray)
    │  - default ALLOW at the tail
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

The linear scan emits two instructions per blocked syscall number:
```
BPF_JEQ(nr)  → jt=0, jf=1     # if match, fall through to RET_DENY
BPF_RET(DENY)                  # kill/EPERM/USER_NOTIF depending on mode
```

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

```
BPF_JEQ(syscall_nr == mmap, match, skip_5)
BPF_LD(args[2])                    # load prot argument (bits 0..31)
BPF_JSET(0x04, match, skip_1)      # test PROT_EXEC bit
BPF_RET(DENY)
BPF_LD(syscall_nr)                 # restore NR for subsequent checks
# same 5-instruction sequence for mprotect
```

This blocks only `mmap` / `mprotect` calls where the caller requests executable memory.
The JVM's own JIT and GC `mmap`/`mprotect` calls do not use `PROT_EXEC` in the way
that shellcode injection does — they are whitelisted by this check automatically.

### 3b. `clone` — allow only `CLONE_THREAD`

```
BPF_JEQ(syscall_nr == clone, match, skip_5)
BPF_LD(args[0])                    # load clone flags
BPF_AND(CLONE_VM | CLONE_THREAD)   # mask to relevant bits (0x00010100)
BPF_JEQ(0x00010100, skip_1, match) # both bits set → JVM thread creation → allow
BPF_RET(DENY)
BPF_LD(syscall_nr)
```

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
outright (via `Syscall.PRCTL` in the block list) is safe — the JVM handles `EPERM`
from `PR_SET_NAME` silently. But the argument-inspection path above is preferred
when filter stacking is still ongoing (e.g. when `allowUnsafePrctl = false`).

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

| State | Type | Purpose |
|---|---|---|
| `THREAD_BLOCKED` | `ThreadLocal<Set<Syscall>>` | Syscalls already blocked on this OS thread |
| `PROCESS_BLOCKED` | `CopyOnWriteArraySet<Syscall>` | Syscalls blocked process-wide via TSYNC |
| `FILTER_DEPTH` | `ThreadLocal<Int>` | Count of thread-local filter installations |
| `PROCESS_FILTER_DEPTH` | `AtomicInteger` | Count of process-wide filter installations |
| `THREAD_ALLOWS_MMAP_EXEC` | `ThreadLocal<Boolean>` | Whether mmap PROT_EXEC inspection is still pending |
| `PROCESS_ALLOWS_MMAP_EXEC` | `@Volatile Boolean` | Same, process-wide |
| *(identical pattern for clone, prctl)* | | |

Before installing, `installInternal` computes:
- `newBlocks = policy.blocked - (THREAD_BLOCKED + PROCESS_BLOCKED)` → only truly new syscalls
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
    - if seccomp(2) + TSYNC fails, fails hard (never falls back to thread-local)
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

### `applyProfilingRuleset()` vs. `applyRuleset(policy)`

- `applyRuleset(policy)` — enforcement path; used by `ContainedExecutors`.
- `applyProfilingRuleset()` — applies a "deny everything" Landlock domain used by
  the profiler to force kernel audit events for `io_uring` operations. Activated only
  via `JSECCOMP_PROFILER_AUDIT=true`. **Never call this in enforcement code paths.**

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
