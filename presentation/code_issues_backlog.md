# Code Issues Backlog

Items done in this session:
- [x] `VulnerableLogger`: `Runtime.exec` → `ProcessBuilder` + `waitFor(5, SECONDS)` 
- [x] `ExploitDemonstrationTest`: removed racy sleep polling loop
- [x] `StackingIntegrationTest`: explicit stable syscall list, `check(size > 32)` guard
- [x] `StackingIntegrationTest`: resolved all compiler warnings (non-null assertions) and removed unused `Executors` import
- [x] `ContainedExecutors.wrapCallable/wrapRunnable`: clarifying comments separating containment-install vs task-body exceptions
- [x] `ContainedExecutors.kt`: replaced all `Regex` with zero-allocation manual string scanning.
- [x] `DemoAppTest`: Verified presence of `@EnabledOnOs(OS.LINUX)` guard.
- [x] `Policy.kt`: Simplified boolean logic inversion in `Policy.combine()`.

---

## Remaining Issues

### 🟡 Medium: Expand `installOnProcess` Integration Coverage

**Context:** `ContainedExecutors.installOnProcess()` is functional and verified by `ProcessContainmentTest.kt` for basic containment. However, it requires deeper validation to be production-ready.

**Needed:**
- Expand `ProcessContainmentTest.kt` or add a new suite covering:
  - Subsequent threads inherit the filter (verify with a Thread spawned after install)
  - JVM stability after process-wide `NO_EXEC` (GC, JIT, classloading continue normally)
  - Process-wide `NO_NETWORK` doesn't break NIO/epoll
  - Depth counter correctly accumulates process-wide + thread-local filter counts
- Document clearly in README and article that this is not yet production-validated
