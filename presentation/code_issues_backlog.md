# Code Issues Backlog

Items done in this session:
- [x] `VulnerableLogger`: `Runtime.exec` → `ProcessBuilder` + `waitFor(5, SECONDS)` 
- [x] `ExploitDemonstrationTest`: removed racy sleep polling loop
- [x] `StackingIntegrationTest`: explicit stable syscall list, `check(size > 32)` guard
- [x] `StackingIntegrationTest`: resolved all compiler warnings (non-null assertions) and removed unused `Executors` import
- [x] `ContainedExecutors.wrapCallable/wrapRunnable`: clarifying comments separating containment-install vs task-body exceptions
- [x] `ContainedExecutors.kt`: replaced all `Regex` with zero-allocation manual string scanning.

---

## Remaining Issues

### 🟡 Medium: Potential for TSYNC race in test runner


**Context:** `ContainedExecutors.installOnProcess()` is functional but has received significantly less testing than the thread-level path. The Elasticsearch technique is proven; `jseccomp`'s `installOnProcess` wrapper has not been through equivalent production hardening.

**Needed:**
- A dedicated integration test suite for `installOnProcess` covering:
  - Subsequent threads inherit the filter (verify with a Thread spawned after install)
  - JVM stability after process-wide `NO_EXEC` (GC, JIT, classloading continue normally)
  - Process-wide `NO_NETWORK` doesn't break NIO/epoll
  - Depth counter correctly accumulates process-wide + thread-local filter counts
- Document clearly in README and article that this is not yet production-validated

---

### 🟡 Medium: `DemoAppTest` Missing `@EnabledOnOs(OS.LINUX)` Guard

**File:** `demo/src/test/kotlin/demo/DemoAppTest.kt` (not yet read — verify)

If `DemoAppTest` calls `UnsafeRunner.run()` or `ExploitDemonstrationTest` logic without an OS guard, it will fail on macOS/Windows CI runners with `IOException` (no `/tmp/pwned_unsafe`, `exec` behavior differs).

**Action:** Verify and add `@EnabledOnOs(OS.LINUX)` or equivalent guard.

---

### 🟢 Low: `StackingIntegrationTest` Uses Unused `Executors` Import

After the rewrite, the `import java.util.concurrent.Executors` line is no longer used. Remove it.

---

### 🟢 Low: `Policy.combine()` Logic Inversion for Boolean Flags

**File:** `Policy.kt`, lines 76–77

```kotlin
val mmapExec = policies.any { !it.allowMmapExec }
val cloneNonThread = policies.any { !it.allowNonThreadClone }
return Policy(
    union,
    allowMmapExec = !mmapExec,      // allows exec only if NO policy blocks it
    allowNonThreadClone = !cloneNonThread,
    ...
)
```

This logic is correct — combining policies should take the most restrictive stance. But the double-negation (`any { !it.allow... }` then `!result`) is confusing. A clearer expression:

```kotlin
val allowMmapExec = policies.all { it.allowMmapExec }
val allowNonThreadClone = policies.all { it.allowNonThreadClone }
```

This reads as: "allow X only if every policy allows X" — which is the correct semantics for combining restrictive policies. Behavior is identical, readability is improved.
