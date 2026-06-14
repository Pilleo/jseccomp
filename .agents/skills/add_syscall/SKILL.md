# Skill: Add Syscall

## Checklist

This skill provides a rigorous checklist for adding a new system call to the `mazewall` engine and profiler, emphasizing **compile-time safety** and **logical modularity**.

### 1. Definition Phase (Compile-Time Safety)
- [ ] **Syscall.kt:** Add the new enum value to `io.mazewall.core.Syscall`. Use uppercase naming (e.g., `IO_URING_SETUP`). 
- [ ] **Arch.kt:** Map the enum value to the correct Linux system call numbers for both `x86_64` and `aarch64`. Verify numbers against the official Linux syscall tables (e.g., `man syscalls`).
- [ ] **Strong Typing:** Ensure any new constants or flags associated with the syscall are represented as Kotlin `sealed classes` or `enums` rather than raw `Int` values wherever possible.

### 2. Policy Integration (Logical Modularity)
- [ ] **Policy Presets:** Determine if the new syscall should be blocked or allowed in standard presets (`PURE_COMPUTE`, `NO_EXEC`, `NO_NETWORK`).
- [ ] **BpfFilter.kt:** If the syscall requires argument inspection (like `mmap` or `prctl`), implement the corresponding BPF inspection block. Ensure the inspection logic is modular and does not introduce side effects to unrelated syscalls.
- [ ] **Trait Alignment:** If the syscall interacts with the filesystem or network, ensure it is represented in the corresponding `NativeEngine` trait (e.g., `NativeFileSystem`).

### 3. Profiler Integration
- [ ] **BobCompiler.kt:** Add the syscall to the SBoB (Bill of Behavior) compiler's mapping if it represents a relevant capability (File, Network, Process).
- [ ] **StraceProfiler.kt:** Ensure the syscall name matches the `strace` output format for correct parsing.
- [ ] **ProfilerDaemon.kt:** If the syscall takes path arguments (like `openat`), ensure `getPathArgs()` correctly identifies and resolves the pointers using the established FFM safety protocols.

### 4. Verification & Debuggability
- [ ] **SyscallTest.kt:** Add a unit test to verify the mapping for all supported architectures.
- [ ] **Actionable Diagnostics:** Ensure that if this syscall is blocked, the `ContainmentViolationException` provides clear, debuggable context (e.g., "Blocked syscall: OPENAT (257) with flags 0x...").
- [ ] **Integration Test:** Write a test that attempts to invoke the new syscall and verifies that the policy correctly allows or blocks it.

