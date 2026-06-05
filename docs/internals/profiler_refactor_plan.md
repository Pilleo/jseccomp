# Profiler.kt Refactor Design Document

## Motivation

`Profiler.kt` is currently 631 lines and conflates four distinct responsibilities into a
single file. The `@Suppress("TooManyFunctions")` annotation is a code smell — the
suppressed warning is justified by the architecture, not the design.

The public API (`profile()`, `wrap()`, `ProfilerExecutorWrapper`) should be immediately
readable without scrolling through socket setup, daemon lifecycle, and ACK protocol code.

---

## Current Structure

```
Profiler.kt (631 lines)
├── Public API
│   ├── fun profile(block)          — launches daemon, profiles workload, returns BillOfBehavior
│   ├── fun wrap(pool, policy)      — wraps ExecutorService with profiling filter
│   └── inner class ProfilerExecutorWrapper
│
├── Socket Infrastructure (~120 lines)
│   ├── connectWithRetry()
│   ├── setupSockAddrUn()
│   └── sendDescriptor()
│
├── Daemon Lifecycle (~90 lines)
│   ├── spawnDaemon()
│   ├── getOrSpawnSharedDaemon()
│   ├── cleanupDaemon()
│   └── data class DaemonContext
│
└── Trace Listener (~170 lines)
    ├── startTraceListener()        — the ACK loop; reads TraceEvents, sends ACK bytes
    └── threadRegistry mapping
```

---

## Target Structure

```
profiler/src/main/kotlin/io/mazewall/profiler/
├── Profiler.kt                     (~150 lines — public API only)
└── internal/
    ├── ProfilerSocket.kt           (~120 lines — socket plumbing)
    ├── ProfilerDaemonManager.kt    (~90 lines  — daemon lifecycle)
    └── ProfilerTraceListener.kt    (~170 lines — ACK protocol loop)
```

All three internal objects are `internal` visibility — not part of the public API.

---

## Proposed Extraction Boundaries

### `internal object ProfilerSocket`

Extracts all Unix domain socket infrastructure. No business logic.

```kotlin
internal object ProfilerSocket {
    /** Connects to the daemon socket at [socketPath] with up to [maxRetries] attempts. */
    fun connectWithRetry(socketPath: String, maxRetries: Int, retryDelayMs: Long): Int

    /** Allocates and populates a sockaddr_un structure in [arena] for the given [socketPath]. */
    fun setupSockAddrUn(arena: Arena, socketPath: String): MemorySegment

    /** Sends a file descriptor [fd] over the Unix domain socket [socketFd] via SCM_RIGHTS. */
    fun sendDescriptor(socketFd: Int, fd: Int)
}
```

**No state.** All functions are pure operations on native memory.

---

### `internal object ProfilerDaemonManager`

Extracts daemon process lifecycle. Owns the shared daemon context singleton.

```kotlin
internal data class DaemonContext(
    val process: Process,
    val socketPath: String,
    val socketFd: Int,
)

internal object ProfilerDaemonManager {
    /** Spawns a new daemon process and connects to its socket. Returns a [DaemonContext]. */
    fun spawnDaemon(policy: Policy, socketPath: String): DaemonContext

    /**
     * Returns a shared [DaemonContext], spawning one if none exists.
     * The shared daemon is reused across multiple `Profiler.wrap()` calls for the same thread.
     */
    fun getOrSpawnSharedDaemon(policy: Policy): DaemonContext

    /** Terminates the daemon process and closes the socket file descriptor. */
    fun cleanupDaemon(context: DaemonContext)
}
```

**Owns the `@Volatile sharedDaemon` field** currently at the top of `Profiler.kt`.

---

### `internal class ProfilerTraceListener`

Extracts the ACK protocol loop. This is the most complex piece — it runs on a dedicated
thread, reads `TraceEvent` packets from the daemon socket, captures stack traces,
and sends ACK bytes back.

```kotlin
internal class ProfilerTraceListener(
    private val socketFd: Int,
    private val accumulatedLogs: MutableList<TraceEvent>,
    private val stackTracesMap: MutableMap<TraceEvent, MutableList<Array<StackTraceElement>>>?,
    private val pathCache: MutableMap<String, Long>,
    private val workerThreadProvider: () -> Thread?,
) {
    /** Starts the listener thread. Returns the thread for lifecycle management. */
    fun start(): Thread

    /** Signals the listener thread to stop after the current event. */
    fun stop()
}
```

The `ackBuf`, `arena`, `readBuf`, `multiBuf`, and `inputStream` are all local to the
listener thread — they do not need to be visible in `Profiler.kt` at all.

---

## Migration Order (Keep Tests Green at Every Step)

> [!IMPORTANT]
> Each step must be followed by `./gradlew :profiler:compileKotlin :profiler:test`
> before proceeding. The profiler test suite is the primary safety net.

### Step 1 — Extract `ProfilerSocket` (lowest risk)

1. Create `internal/ProfilerSocket.kt`.
2. Move `connectWithRetry`, `setupSockAddrUn`, `sendDescriptor` verbatim.
3. Replace callsites in `Profiler.kt` with `ProfilerSocket.*` calls.
4. Delete the original private functions from `Profiler.kt`.
5. **Compile + test.**

### Step 2 — Extract `ProfilerDaemonManager` (medium risk — owns shared state)

1. Create `internal/ProfilerDaemonManager.kt`.
2. Move `DaemonContext` data class.
3. Move `spawnDaemon`, `getOrSpawnSharedDaemon`, `cleanupDaemon`.
4. Move `@Volatile sharedDaemon: DaemonContext?` to `ProfilerDaemonManager`.
5. Replace callsites in `Profiler.kt`.
6. **Compile + test.**

### Step 3 — Extract `ProfilerTraceListener` (highest risk — owns the ACK loop)

1. Create `internal/ProfilerTraceListener.kt`.
2. Move `startTraceListener` body into `ProfilerTraceListener.start()`.
3. The `Thread { ... }` block becomes the listener thread body.
4. Expose a `stop()` method that sets a `@Volatile running = false` flag.
5. Replace the `startTraceListener(...)` call in `Profiler.kt` with
   `ProfilerTraceListener(...).also { listeners += it }.start()`.
6. **Compile + test — including `ProfilerStressTest` and `ProfilerIntegrationTest`.**

### Step 4 — Slim down `Profiler.kt`

After Steps 1–3, `Profiler.kt` should contain only:
- `fun profile(block)` + KDoc
- `fun wrap(pool, policy)` + KDoc
- `inner class ProfilerExecutorWrapper`
- Module-level constants (`DEDUPLICATION_WINDOW_MS`, `PROTOCOL_ACK_BYTE`, etc.)

Remove the now-empty `@Suppress("TooManyFunctions")`.

---

## Internal Visibility Contract

These internal objects must **not** be referenced from `:enforcer`. The `internal` modifier
in Kotlin enforces this at module boundaries when modules are properly declared in
`build.gradle.kts`.

Verify with: `./gradlew :enforcer:compileKotlin` — it should not resolve any
`io.mazewall.profiler.internal.*` symbols.

---

## Risk Assessment

| Step | Risk | Primary Test | Known Gotcha |
|------|------|-------------|--------------|
| 1 — ProfilerSocket | Low | `ProfilerIntegrationTest` | Arena lifetimes must remain in caller |
| 2 — DaemonManager | Medium | `ProfilerStressTest` | `sharedDaemon` volatile field races |
| 3 — TraceListener | High | `ProfilerIntegrationTest` + stress | ACK deadlock if thread lifecycle leaks |
| 4 — Slim Profiler | None | All profiler tests | Check `@Suppress` removal doesn't add new warnings |
