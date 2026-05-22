# Code Issues Backlog


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


### Packages structure does not exist. At least profiler and enforcer should be added
