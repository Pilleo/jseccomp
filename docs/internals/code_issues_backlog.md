# Code Issues Backlog


## Remaining Issues

### 🔴 High: Profiler Protocol ACK Corruption
**Context:** In `Profiler.kt`, the deduplication block incorrectly uses `ValueLayout.JAVA_SHORT` to write a 1-byte ACK (`0x41`). This causes stream corruption, as the daemon expects exactly 1 byte but receives 2. This leads to hangs or "Deduplicated" corruption logs in the daemon.
**Fix:** Change to `ValueLayout.JAVA_BYTE`.

### 🔴 High: Profiler Socket Write Race Condition
**Context:** The `ProfilerDaemon` sends binary `TraceEvent` structures to the parent JVM. If multiple threads (e.g., Seccomp vs. Landlock Audit) emit events simultaneously, the socket writes can interleave, corrupting the stream.
**Fix:** Synchronize `sendTraceEvent` in the daemon.

### 🟡 Medium: FFM Arena Allocation Performance
**Context:** The `Profiler.kt` trace listener allocates a new `Arena.ofConfined()` for every single byte read from the daemon. This creates massive GC pressure and CPU overhead during active profiling.
**Fix:** Use a single long-lived Arena for the lifetime of the trace listener.

### 🟡 Medium: Profiler Daemon Path Resolution (AT_FDCWD)
**Context:** `ProfilerDaemon.getPathArgs` fails to resolve relative paths when `dirfd` is `AT_FDCWD (-100)`. It needs to read `/proc/[pid]/cwd` to determine the tracee's context.
**Fix:** Implement CWD resolution in the daemon.

### 🔵 Low: Landlock Path Fallback Edge Case
**Context:** In `Landlock.kt`, `File(path).parent` returns `null` for paths like `/foo`. The fallback logic should handle this and default to `/`.

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
