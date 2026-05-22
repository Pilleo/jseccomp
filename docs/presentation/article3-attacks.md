# jseccomp: The Attacks We Actually Stop

> **Series overview:** This is Part 3 of a 4-part series on behavioral security for cloud-native applications. **What this part adds:** concrete attack walkthroughs — real syscall sequences, policy definitions, and verified test outputs — showing exactly what `jseccomp` blocks and why.


Parts 1 and 2 built the conceptual and architectural case. Now we run the attacks.

This article shows — with actual syscall sequences, policy definitions, and kernel output — exactly what `jseccomp` blocks and why. All examples are runnable from the repository.

```bash
git clone https://github.com/leanid/jseccomp.git
cd jseccomp
# Linux x86_64 or aarch64, JDK 22+
# Docker needed for nested seccomp (see Part 2 for the reason)
docker compose up -d
docker compose exec jseccomp ./gradlew test
```

---

## Attack 1: Log4Shell-Style RCE (Shell Injection)

**The attack:** An attacker sends a crafted JNDI payload to a vulnerable logger. The logger deserializes the payload and calls `Runtime.exec()`, which ultimately attempts to spawn a shell or run an OS command.

<details>
<summary><b>🔍 Deep Dive: The Syscall Sequence</b></summary>

```
Thread-1 (worker, processing untrusted input)
  VulnerableLogger.log("${jndi:...cmd=touch,/tmp/pwned}")
    → ProcessBuilder.start()
      → ProcessImpl.forkAndExec()
        → execve("/bin/touch", ["touch", "/tmp/pwned"], ...)
          ← EPERM  ← seccomp filter: NO_EXEC blocks execve()
```
</details>

**The demo:** `VulnerableLogger` in the `demo` module directly simulates this gadget chain.

```kotlin
// demo/src/main/kotlin/demo/VulnerableLogger.kt
object VulnerableLogger {
    fun log(input: String): String {
        if (input.startsWith("\${jndi:")) {
            val command = extractCommand(input)
            ProcessBuilder(*command)   // execve() call site
                .inheritIO()
                .start()               // ← kernel blocks here with EPERM
                .waitFor(5, TimeUnit.SECONDS)
        }
        return "Logged: $input"
    }
}
```

**Without containment** (`ExploitDemonstrationTest`):
```
UnsafeRunner.run("${jndi:...cmd=touch,/tmp/pwned_unsafe}")
→ /tmp/pwned_unsafe exists ✓  (attack succeeded)
```

**With containment** (`ProtectionDemonstrationTest`):
```kotlin
val safeExecutor = ContainedExecutors.wrap(
    Executors.newSingleThreadExecutor(),
    Policy.NO_EXEC
)
val future = safeExecutor.submit { vulnerableLogger.log(payload) }
future.get()
// throws ExecutionException { cause: ContainmentViolationException:
//   "Task violated containment policy" }
// /tmp/pwned_safe does NOT exist
```

The kernel intercepts `execve()` in the worker thread and returns `EPERM`. The JVM surfaces this as `IOException("error=1, ...")`, which `ContainedExecutors` detects and wraps as `ContainmentViolationException`. The attacker's command never runs.

> **Simplification note:** The demo models direct command injection for clarity — `VulnerableLogger` extracts a command from the payload and calls `ProcessBuilder` directly. The real Log4Shell chain (CVE-2021-44228) works differently: the logger contacts a remote LDAP server, receives a Java class reference, deserializes and instantiates it; that class may then call `Runtime.exec()` as its payload. `jseccomp` blocks the final `execve()` regardless of how the payload was delivered — the mechanism that matters is the same.

---

## Attack 2: Fileless Malware (`memfd_create` + `execveat`)

**The attack:** A more sophisticated attacker avoids `execve` entirely. Instead:

1. Request an anonymous in-memory file descriptor (no path, no disk entry).
2. Write a full ELF binary into memory.
3. Execute the in-memory binary.

No file ever touches disk, defeating all disk-based security tooling. `jseccomp` blocks this entirely by denying the initial memory-file creation because a standard JVM worker thread has no legitimate use for it.

<details>
<summary><b>🔍 Deep Dive: The Syscall Sequence</b></summary>

```
Thread-1 (worker, attacker has RCE)
  memfd_create("payload\0", MFD_CLOEXEC)
    ← EPERM  ← seccomp filter: NO_EXEC blocks memfd_create()
```
The attack is stopped at step 1 — before any binary data is even staged.
</details>

**Verified by test** (`MemfdCreateBypassTest`):

```kotlin
@Test
fun `NO_EXEC blocks memfd_create as of recent security update`() {
    val executor = Executors.newSingleThreadExecutor()
    executor.submit {
        ContainedExecutors.installOnCurrentThread(Policy.NO_EXEC)

        val arch = Arch.current()
        val res = Arena.ofConfined().use { arena ->
            val name = arena.allocateFrom("test_memfd")
            LinuxNative.syscall(arch.memfdCreate.toLong(), name.address(), 0L, MemorySegment.NULL)
        }
        assertTrue(res.returnValue < 0, "memfd_create should be blocked by NO_EXEC")
        assertTrue(res.errno == LinuxNative.EPERM, "Expected EPERM, got ${res.errno}")
    }.get()
}
```

The test calls the kernel directly via FFM, bypassing all Java wrappers — the `EPERM` comes straight from the seccomp filter.

---

## Attack 3: Binary Shellcode Injection (`mmap` and `mprotect` with `PROT_EXEC`)

**The attack:** An attacker with arbitrary write primitives (buffer overflow, unsafe memory access, or JNI manipulation) writes raw machine code into the process address space. To execute it, they must mark the target memory region executable. 

**Why this is hard to block naively:** The JVM's JIT compiler does exactly this — it allocates heap segments and marks them executable so it can compile native code. If a naive Seccomp filter blocks all executable memory allocations, the JVM will fail to run.

**How `jseccomp` handles it:** As discussed in Part 2, `jseccomp` safely hooks the memory allocation requests and inspects their arguments bit-by-bit to ensure the JIT can work but shellcode cannot.

<details>
<summary><b>🔍 Deep Dive: Allocation and Syscall Hooking</b></summary>

Attackers typically make memory executable either directly during allocation:

```c
// Method A: Direct executable allocation
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
```

Or, more commonly, by modifying an existing readable/writable data region:

```c
// Method B: Allocating RW memory, writing payload, then converting to RX
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
memcpy(region, shellcode, size);
mprotect(region, size, PROT_READ | PROT_EXEC);  // pivot to executable
((void(*)())region)();                           // jump to shellcode
```

**Dual-Syscall BPF argument inspection:**

```
Worker Thread (contained, Policy.PURE_COMPUTE)
  mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON, -1, 0)
    → prot = 0x3, PROT_EXEC bit (0x4) not set → ALLOWED (data heap ok)

  mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANON, -1, 0)
    → prot = 0x5, PROT_EXEC bit (0x4) IS set → EPERM (blocked!)

  mprotect(region, 4096, PROT_READ|PROT_EXEC)
    → prot = 0x5, PROT_EXEC bit (0x4) IS set → EPERM (blocked!)

JIT Thread (uncontained — different OS thread)
  mmap(NULL, 65536, PROT_READ|PROT_EXEC, MAP_ANON, -1, 0)
    → no filter on this thread → ALLOWED (JIT functions normally)
```
</details>

By inspecting both system calls at the argument level, the contained worker thread is completely barred from introducing new executable machine code into the process address space. The JIT threads running on other OS threads continue compiled code optimization unimpeded.

**Verified by test** (`MmapProtectionTest`):
```kotlin
@Test
fun `PURE_COMPUTE blocks mmap with PROT_EXEC`() {
    val executor = Executors.newSingleThreadExecutor()
    executor.submit {
        ContainedExecutors.installOnCurrentThread(Policy.PURE_COMPUTE)
        // Attempt to create executable memory
        val result = LinuxNative.mmap(
            MemorySegment.NULL, 4096,
            LinuxNative.PROT_READ or LinuxNative.PROT_EXEC,
            LinuxNative.MAP_ANON or LinuxNative.MAP_PRIVATE,
            -1, 0
        )
        assertTrue(result.returnValue < 0)
        assertTrue(result.errno == LinuxNative.EPERM)
    }.get()
}
```

---

## Attack 4: io_uring Evasion

**The attack:** `io_uring` was designed for high-throughput I/O but has become a documented security evasion vector. Operations submitted to an `io_uring` ring (reads, writes, accepts, even process execution via `IORING_OP_EXECVE`, added in Linux 5.15) are dispatched by kernel-side worker threads (`io-wq`), not the submitting user-space thread. These worker threads do *not* inherit the submitting thread's Seccomp filter. From a per-thread Seccomp perspective:

- The submitting thread calls `io_uring_setup()` and `io_uring_enter()` — these are the only visible syscalls on that thread
- The actual I/O operations (`open`, `connect`, `sendmsg`, and even `execve` via `IORING_OP_EXECVE`) execute on kernel `io-wq` workers that are outside the scope of the submitting thread's Seccomp filter

**However, Landlock filesystem rules are still enforced.** Landlock is an LSM; its hooks fire at the VFS layer using the *submitting process's* credentials and active Landlock domain — not the `io-wq` thread's context. An `openat("/etc/passwd")` submitted through an `io_uring` ring still hits Landlock's inode-level check.

> **Kernel version note:** This VFS-level Landlock enforcement behaviour applies as of kernel 5.13+ (Landlock ABI 1+). Verify this on your specific target kernel; it is not guaranteed on older LTS kernels.

A sophisticated attacker who has already compromised a worker thread can set up an `io_uring` ring and submit process spawns that would be blocked by Seccomp if called directly. For filesystem reads, Landlock still provides a defense layer.

**The `jseccomp` response:** Block `io_uring_setup` entirely in `NO_EXEC` and `PURE_COMPUTE` policies. A JVM worker thread processing JSON or images has no legitimate use for `io_uring`. The standard JVM uses `epoll` + NIO, not `io_uring`, for its internal I/O.

```kotlin
// From Policy.kt — NO_EXEC definition
val NO_EXEC: Policy = builder()
    .block(Syscall.EXECVE, Syscall.EXECVEAT)
    .block(Syscall.FORK, Syscall.VFORK)
    .block(Syscall.MEMFD_CREATE, Syscall.IO_URING_SETUP, Syscall.PTRACE)
    .block(Syscall.INIT_MODULE, Syscall.FINIT_MODULE)
    .build()
```

> *The mental model from `../../../SECURITY_CONSIDERATIONS.md`:* **eBPF and Landlock see the action; Seccomp only sees the ring.** Because Seccomp cannot peer into the shared memory ring buffer, the only safe response is to prevent the ring from being created. Landlock's VFS enforcement survives the `io_uring` boundary.

---

## Attack 5: Kernel Module Injection (LPE Vector)

**The attack:** An attacker who has compromised a worker thread seeks local privilege escalation (LPE) to break out of the container. 
A naive security approach might just block direct module-loading syscalls like `init_module` or `finit_module`. However, **an attacker can bypass this via dynamic auto-loading**.

If the attacker calls `socket(AF_RDS, ...)` or invokes `mount` to attach an obscure filesystem, and the kernel does not currently have that driver loaded, the Linux kernel will **automatically trigger a dynamic modprobe helper** (`kmod`) to search for and load that module from host disk. This immediately exposes the kernel's vulnerable attack surface (e.g., legacy packet parsing bugs) to local exploitation, even if `init_module` itself was blocked.

> **Kernel configuration caveat:** This auto-loading behaviour depends on `CONFIG_MODULES` being enabled and `/proc/sys/kernel/modprobe` pointing to a valid loader (the default on most production kernels). On hardened kernels (grsecurity, minimal builds, or those with `/proc/sys/kernel/modprobe` set to `/dev/null`), module auto-loading is disabled and this attack path is already closed at the OS level. Always verify whether this is the case before relying on `jseccomp` as the sole defence against this vector. 

**The `jseccomp` response:** Blocking both direct loading and indirect auto-loading.

While `NO_EXEC` blocks the direct injection commands (`init_module`, `finit_module`), `jseccomp`'s **`PURE_COMPUTE`** policy goes much deeper: it blocks the entire `socket` and `mount` syscall families. By completely stripping the thread's ability to initialize sockets or attach mounts, `jseccomp` successfully plugs the dynamic auto-loading loophole at the thread boundary. A thread parsing JSON has **zero** legitimate reasons to create sockets or mount filesystems. Even if the underlying host kernel is highly vulnerable to legacy protocol exploits, the contained JVM thread is physically blocked from initiating the transitions that trigger module loading.

### The Host-Layer Counterpart: Defense-in-Depth with ModuleJail

This application-level sandboxing mirrors a significant trend in host-layer hardening, such as **ModuleJail** (developed by Jasper Nuyens). While `jseccomp` blocks module-loading syscalls *inside the JVM thread*, `ModuleJail` operates at the host OS layer to scan and blacklist dormant kernel modules. 

This creates a robust **Defense-in-Depth sandwich**:
1. **Host Layer:** `ModuleJail` locks down the OS kernel, ensuring vulnerable legacy modules can never be loaded system-wide.
2. **JVM Layer:** `jseccomp` blocks the specific syscall channels (`socket` families, `mount`, `init_module`) that an attacker would use to trigger dynamic kernel transitions in the first place.

---


## Filesystem Attacks and Landlock

The attacks above all operate at the syscall mechanism level. But an attacker with file-read access on a compromised thread can still read sensitive data without triggering any of the above blocks — they can call `openat("/etc/passwd", O_RDONLY)` directly, and `openat` is not blocked in `NO_EXEC` or `NO_NETWORK` policies.

Landlock addresses this at the inode level:

```kotlin
val policy = Policy.builder()
    .base(Policy.PURE_COMPUTE)
    .allowJvmClasspath()             // required — see Part 2
    .allowFsRead("/data/incoming")   // only this directory
    .allowFsWrite("/data/processed") // and this one
    .build()

val executor = ContainedExecutors.wrap(Executors.newFixedThreadPool(4), policy)

executor.submit {
    // Works:
    File("/data/incoming/task.json").readText()
    File("/data/processed/result.json").writeText(output)

    // Blocked by Landlock (EACCES):
    File("/etc/passwd").readText()
    File("/var/run/docker.sock").readText()
}.get()
```

Landlock uses `O_NOFOLLOW` when `jseccomp` opens path descriptors to build Landlock rules — this is a library implementation choice, not a Landlock kernel primitive. Because path-beneath rule descriptors are opened with `O_PATH | O_NOFOLLOW`, symlinks are rejected with `ELOOP`, preventing an attacker who controls a symlink target from redirecting a Landlock rule to an unintended path. Landlock's own kernel enforcement operates at the inode level after path resolution.

---

## The Inherited File Descriptor Caveat

Seccomp `NO_NETWORK` blocks the *creation* of new network connections: `socket()`, `connect()`, `bind()`. It does not block `read()`, `write()`, or `sendmsg()` on *already-open* file descriptors.

If a worker thread inherits an open socket from a previous task (or receives one via `SCM_RIGHTS` before containment is applied), it can still communicate over that socket after containment. `NO_NETWORK` prevents new channels from being opened — it does not isolate pre-existing ones.

The defense: always create a fresh thread pool for contained tasks, never reuse threads that previously held uncontained sockets, and apply process-wide `NO_EXEC` to ensure the base process also can't establish new privileged channels.

---

## The Policy Matrix

| Attack vector | Blocked by | Policy needed |
|---|---|---|
| Shell injection (`execve`) | Seccomp | `NO_EXEC` |
| Fileless malware (`memfd_create` + `execveat`) | Seccomp | `NO_EXEC` |
| Shellcode injection (`mmap PROT_EXEC`) | Seccomp BPF arg inspection | `PURE_COMPUTE` |
| io_uring evasion | Seccomp (`io_uring_setup`) | `NO_EXEC` |
| Kernel module injection (`init_module`, `finit_module`) | Seccomp | `NO_EXEC` |
| Network exfiltration (`connect`, `socket`) | Seccomp | `NO_NETWORK` |
| Filesystem snooping (`/etc/passwd`) | Landlock | Custom policy |
| Pivot to docker socket | Landlock | Custom policy |

> **`fork`/`clone` note:** On modern Linux (glibc 2.3.3+), the `fork(2)` libc wrapper is implemented via `clone(SIGCHLD)`, not the legacy `fork` syscall. `NO_EXEC` explicitly blocks `fork` and `vfork` syscalls. The `clone` syscall itself is handled by BPF argument inspection: `clone` with `CLONE_THREAD` (thread creation) is allowed to keep the JVM stable; `clone` without `CLONE_THREAD` (process forking) is blocked. This is transparent to the caller \u2014 `ProcessBuilder.start()` ultimately fails with `EPERM` regardless of which kernel path it takes.


---

## What jseccomp Does Not Stop

- **ROP/JOP gadget chains** — reusing existing mapped code. Seccomp cannot see CPU instruction flow; only syscalls. Complementary defences: ASLR, stack canaries, CFI (Intel CET, ARM BTI).
- **In-process heap reads** — a contained thread still shares the JVM heap with all other threads and can read any object it can reach via references. This is the Shared-Memory ACE caveat from Part 2: it is why Tier 1 (process-wide `NO_EXEC`) is mandatory as a backstop against escalation.
- **Pre-established network channels** — inherited open file descriptors. `NO_NETWORK` blocks *creation* of new sockets, not reads and writes on sockets already open.
- **Orchestrator-level escapes** — if the JVM user has write access to `/etc/cron.d/` or the Docker socket, those escapes happen outside the syscall filter.
- **Cluster-level visibility gaps** — `jseccomp` is not a replacement for cluster-wide tools like Kubescape or Falco. Those tools provide host-level and cross-container visibility that thread-scoped seccomp cannot offer. The correct model is defence-in-depth: cluster tools observe the container boundary; `jseccomp` enforces policy inside threads that the cluster tools cannot introspect.

`jseccomp` is one layer in a stack, not a total sandbox.

---

*Next up: Part 4: Generating an SBoB for Java*

