# Skill: Add Syscall

## Checklist

This skill provides a rigorous checklist for adding a new system call to the `mazewall` engine and profiler.

### 1. Definition Phase
- [ ] **Syscall.kt:** Add the new enum value to `io.mazewall.core.Syscall`. Use uppercase naming (e.g., `IO_URING_SETUP`).
- [ ] **Arch.kt:** Map the enum value to the correct Linux system call numbers for both `x86_64` and `aarch64`. Verify numbers against the official Linux syscall tables (e.g., `man syscalls`).

### 2. Policy Integration
- [ ] **Policy Presets:** Determine if the new syscall should be blocked or allowed in standard presets (`PURE_COMPUTE`, `NO_EXEC`, `NO_NETWORK`). 
- [ ] **BpfFilter.kt:** If the syscall requires argument inspection (like `mmap` or `prctl`), implement the corresponding BPF inspection block.

### 3. Profiler Integration
- [ ] **BobCompiler.kt:** Add the syscall to the SBoB (Bill of Behavior) compiler's mapping if it represents a relevant capability (File, Network, Process).
- [ ] **StraceProfiler.kt:** Ensure the syscall name matches the `strace` output format for correct parsing.
- [ ] **ProfilerDaemon.kt:** If the syscall takes path arguments (like `openat`), ensure `getPathArgs()` correctly identifies and resolves the pointers.

### 4. Verification
- [ ] **SyscallTest.kt:** Add a unit test to verify the mapping for all supported architectures.
- [ ] **Integration Test:** (Optional but recommended) Write a test that attempts to invoke the new syscall and verifies that the policy correctly allows or blocks it.
