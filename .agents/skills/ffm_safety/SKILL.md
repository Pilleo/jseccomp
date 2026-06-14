# Skill: FFM Safety

This skill provides a rigorous checklist for using the JDK Foreign Function & Memory (FFM) API safely and future-proofly in `mazewall`.

## Checklist

### 1. Memory Lifecycle & Modularity
- [ ] **Arena Management:** Always use `Arena.ofConfined()` within a `use { ... }` block (or `try-with-resources`) to ensure deterministic deallocation.
- [ ] **Thread Confinement:** Never share a `Confined` memory segment across threads. If cross-thread access is needed, use `Arena.ofShared()`.
- [ ] **Allocation:** Prefer `arena.allocate(layout)` over raw `MemorySegment.ofAddress` to ensure the segment is bound to a lifecycle.
- [ ] **Trait Isolation:** Native FFM logic must be encapsulated behind `NativeEngine` traits. Avoid leaking raw `MemorySegment` objects into high-level business logic.

### 2. Native Downcalls, Errno & Debuggability
- [ ] **Capture State:** All native downcalls that can set `errno` MUST use `Linker.Option.captureCallState("errno")`.
- [ ] **Timing:** Read `errno` from the captured state segment **immediately** after the `invoke` call.
- [ ] **Actionable Errors:** When a downcall fails, include the `errno` name (e.g., `EPERM`) and its numeric value in the exception message to aid debuggability.
- [ ] **No Interference:** Ensure no other FFM calls or JNI calls occur between the downcall and the `errno` read.

### 3. Layouts, Alignment & Future-Proofness
- [ ] **Correct ValueLayout:**
    - Use `JAVA_INT` for 32-bit `int` fields (e.g., `seccomp_data` fields).
    - Use `JAVA_LONG` for 64-bit `long` fields.
    - Use `ADDRESS` for pointers.
- [ ] **Valhalla Readiness:** Design layouts and wrappers with **Project Valhalla** in mind (prefer value-based classes and avoid identity-dependent operations on FFM wrappers).
- [ ] **Byte Order:** Ensure the `ByteOrder` of the layout matches the native platform (usually `ByteOrder.nativeOrder()`).
- [ ] **Padding:** Explicitly define padding in `StructLayout` to match C struct alignment rules.

### 4. Verification
- [ ] **Unit Tests:** Verify the layout size and field offsets against known constants (e.g., from `man` pages or `sizeof` in C).
- [ ] **Address Validation:** Always check if a returned `MemorySegment` is `NULL` (address 0) before dereferencing.
- [ ] **Bounds Checking:** Ensure all index-based access to `MemorySegment` is within the documented `byteSize()`.

