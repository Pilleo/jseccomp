# mazewall-demo

**The interactive showcase demonstrating mazewall's runtime protection and architectural complementary sandboxing.**

This subproject contains real-world scenarios demonstrating how `mazewall` blocks Arbitrary Code Execution (ACE) exploits at the kernel level without performance-degrading agents or complex wrappers, and how Seccomp and Landlock form complementary protection layers to prevent modern asynchronous seccomp bypasses.

---

## What the Demo Showcases

The demo application contains three executable execution modes:

1. **`unsafe` (Active Exploitation):** Simulates a vulnerable framework receiving a Log4Shell-style JNDI injection payload. With no behavioral protection active, the exploit successfully spawns an external process and compromises the host container filesystem.
2. **`safe` (Active Blockage):** Runs the exact same malicious JNDI payload, but wraps the thread executor in `Policy.NO_EXEC` + `Policy.NO_NETWORK`. The Linux kernel intercepts the subprocess creation (`execve`) and returns `EPERM`, throwing a typed `ContainmentViolationException` in Java.
3. **`profile` (Profile & Enforce & Complementary Sandboxing):**
   - **Step 1:** Automatically profiles a complex workload that performs file operations, opens sockets, and invokes async kernel primitives (`io_uring_setup`) using the Tier S `USER_NOTIF` profiler.
   - **Step 2:** Outputs a compiled Bill of Behavior (BoB) DSL.
   - **Step 3:** Enforces the compiled policy under `ContainedExecutors`, demonstrating that the legitimate workload executes with zero friction.
   - **Step 4:** Simulates a path breach where the attacker attempts to read `/etc/hosts` outside of the whitelisted scope, which is immediately blocked by Landlock.
   - **Step 5:** Simulates an advanced **Seccomp Bypass** where the attacker uses an allowed `io_uring` queue to submit an asynchronous read of `/etc/hosts`. The demo showcases how **Landlock LSM** intercepts the async task inside the kernel's worker thread (`io-wq`), successfully caging the attack where Seccomp alone would fail.

---

## The Complementary Seccomp-Landlock Threat Model

Modern kernel subsystems like `io_uring` allow processes to submit asynchronous read/write requests through shared ring buffers, bypassing standard thread-scoped Seccomp-BPF filters (which can only evaluate system calls initiated *directly* by the calling thread). 

`mazewall` solves this vector by enforcing a **Complementary Sandboxing Model** of Seccomp-BPF and Landlock LSM:
- **Seccomp** acts as the gatekeeper, restricting execution rights (`execve`) and socket creation (`connect`).
- **Landlock LSM** operates at the Virtual File System (VFS) hook layer. When `io_uring` executes an asynchronous file task in the kernel's helper threadpools (`io-wq`), the kernel **automatically propagates the calling thread's Landlock credentials** to the async workers. 
- Therefore, even if the thread-scoped Seccomp filter cannot inspect the async payload submitted to the ring buffer, the kernel's VFS layer intercepts the operation, caging file operations perfectly!

---

## Running the Demo

The demo must be run inside the nested seccomp OCI container:

```bash
# Start the Podman test environment
podman compose up -d

# Execute the complete demonstration suite
podman compose exec mazewall ./gradlew :demo:runScratch
```

You can run individual modes by passing arguments to the Gradle task:

```bash
# Run only the JNDI exploit showcase
podman compose exec mazewall ./gradlew :demo:runScratch --args="unsafe"

# Run only the JNDI protection showcase
podman compose exec mazewall ./gradlew :demo:runScratch --args="safe"

# Run the complete Profile & Enforce (io_uring) showcase
podman compose exec mazewall ./gradlew :demo:runScratch --args="profile"
```

---

## Class Directory

- **`demo.DemoApp`:** Main orchestration entrypoint routing arguments to the respective runners.
- **`demo.UnsafeRunner` & `demo.SafeRunner`:** Wrappers representing unprotected and protected executors.
- **`demo.VulnerableLogger`:** Simulates a framework vulnerable to string parsing exploits.
- **`demo.ProfileAndEnforceDemo`:** Implements the dynamic `USER_NOTIF` profiling trace, auto-compiles the DSL, mounts the `ContainedExecutors` sandboxing pool, and attempts both path and `io_uring` breaches.
