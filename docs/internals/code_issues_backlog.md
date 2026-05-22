# Code Issues Backlog

## Fixed Issues

### ✅ FIXED: Profiler Protocol ACK Corruption
**Context:** In `Profiler.kt`, the deduplication block correctly uses `ValueLayout.JAVA_BYTE` to write a 1-byte ACK (`0x41`). This was confirmed to be correctly implemented.

### ✅ FIXED: Profiler Socket Write Race Condition
**Context:** `ProfilerDaemon.sendTraceEvent` is synchronized on a per-socket lock to prevent interleaved writes from concurrent threads (Seccomp vs Landlock Audit).

### ✅ FIXED: Landlock Path Fallback Edge Case
**Context:** `Landlock.kt` correctly handles cases where `File(path).parent` is null (e.g., relative paths or root-level files) by defaulting to `/`.

### ✅ FIXED: Package Structure
**Context:** The project is already organized into `enforcer`, `landlock`, `profiler`, and `seccomp` packages.

## Remaining Issues

### 🔴 High: `Policy.PURE_COMPUTE` Security Gaps
**Context:** `PURE_COMPUTE` is missing blocks for filesystem modification syscalls (`RENAME`, `LINK`, `UNLINK`, `CHMOD`, `CHOWN`, etc.). An attacker could manipulate files without "opening" them.
**Fix:** Add missing syscalls to `PURE_COMPUTE` definition.

### 🔴 High: Incomplete AARCH64 Syscall Coverage
**Context:** AARCH64 relies on modern `*at` variants (e.g., `renameat2`, `mkdirat`, `unlinkat`) which are not currently mapped in `Arch.kt` or `Syscall.kt`. This creates a security bypass on ARM64.
**Fix:** Map and block `*at` variants.

### 🟡 Medium: FFM Arena Allocation Performance
**Context:** The `Profiler.kt` trace listener performs a `segment = arena.allocate(1)` for every single byte read in its `InputStream` implementation. While using a shared arena, the high volume of transient segments creates massive allocation pressure.
**Fix:** Use a single re-usable buffer for socket reads.

### 🟡 Medium: Profiler Daemon Path Resolution (AT_FDCWD)
**Context:** `ProfilerDaemon.getPathArgs` fails to resolve relative paths for several syscalls and doesn't consistently handle `AT_FDCWD`.
**Fix:** Implement consistent CWD resolution for all file-related syscalls.

### 🟡 Medium: Expand `installOnProcess` Integration Coverage
**Context:** `ContainedExecutors.installOnProcess()` needs deeper validation (inheritance, JVM stability, depth accumulation).
**Needed:** Expanded test suite.
