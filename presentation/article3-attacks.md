# jseccomp: The Attacks We Actually Stop

> **Series overview:** This is Part 3 of a 4-part series on behavioral security for cloud-native applications.


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

**The attack:** An attacker sends a crafted JNDI payload to a vulnerable logger. The logger deserializes the payload and calls `Runtime.exec()`, which chains into `execve()` to spawn `/bin/sh` or run `touch /tmp/pwned`.

**The syscall sequence:**

```
Thread-1 (worker, processing untrusted input)
  VulnerableLogger.log("${jndi:...cmd=touch,/tmp/pwned}")
    → ProcessBuilder.start()
      → ProcessImpl.forkAndExec()
        → execve("/bin/touch", ["touch", "/tmp/pwned"], ...)
          ← EPERM  ← seccomp filter: NO_EXEC blocks execve()
```

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

---

## Attack 2: Fileless Malware (`memfd_create` + `execveat`)

**The attack:** A more sophisticated attacker avoids `execve` entirely. Instead:

1. Call `memfd_create("payload", MFD_CLOEXEC)` → get an anonymous in-memory file descriptor (no path, no disk entry)
2. Write a full ELF binary into the memfd via `write(fd, elf_bytes, size)`
3. Call `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` → execute the in-memory binary

No file ever touches disk. `ls /proc/self/fd/` shows the fd, but there is no filesystem path for a scanner to find. This technique defeats all disk-based security tooling.

**The syscall sequence:**
```
Thread-1 (worker, attacker has RCE)
  memfd_create("payload\0", MFD_CLOEXEC)
    ← EPERM  ← seccomp filter: NO_EXEC blocks memfd_create()
```

`jseccomp` blocks `memfd_create` in `NO_EXEC` and `PURE_COMPUTE` policies because the standard JVM has no legitimate use for it in worker threads. The attack is stopped at step 1 — before any binary data is even staged.

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

**The attack:** An attacker with arbitrary write primitives (buffer overflow, unsafe memory access, or JNI manipulation) writes raw machine code into the process address space. To execute it, they must mark the target memory region executable. This is typically done either directly during allocation:

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

**Why this is hard to block naively:** The JVM's JIT compiler does exactly this — it allocates heap segments and uses `mprotect` or `mmap` to mark them executable so it can compile native code. If a naive Seccomp filter blocks all `mmap` or `mprotect` calls, the JVM will fail to run.

**How `jseccomp` handles it:** **Dual-Syscall BPF argument inspection**. The library generates BPF instructions that hook *both* `mmap` and `mprotect` syscalls. The filter extracts the `prot` argument (which is the 3rd argument, `args[2]` for both system calls) and performs a bitwise-AND test against `PROT_EXEC` (0x4):

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

**The attack:** `io_uring` was designed for high-throughput I/O but has become a documented security evasion vector. Operations submitted to an `io_uring` ring (reads, writes, accepts, even `execve` via `IORING_OP_EXECVE`) are dispatched from kernel-side worker threads, not the submitting thread. From a Seccomp perspective:

- The submitting thread calls `io_uring_setup()` and `io_uring_enter()` — these are the only visible syscalls
- The actual operations (open, connect, sendmsg, etc.) execute in kernel context and do not generate per-operation seccomp events on the submitting thread

A sophisticated attacker who has already compromised a worker thread can set up an `io_uring` ring and submit file-reads, network connects, and process spawns — operations that would be blocked if called directly — through the ring.

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

> *The mental model from `SECURITY_CONSIDERATIONS.md`:* **eBPF sees the action; Seccomp only sees the ring.** Because Seccomp cannot peer into the shared memory ring buffer, the only safe response is to prevent the ring from being created.

---

## Attack 5: Kernel Module Injection (LPE Vector)

**The attack:** An attacker who has compromised a worker thread seeks local privilege escalation (LPE) to break out of the container. 
A naive security approach might just block direct module-loading syscalls like `init_module` or `finit_module`. However, **an attacker can bypass this via dynamic auto-loading**. 

If the attacker calls `socket(AF_RDS, ...)` (creating a socket using the RDS protocol) or invokes `mount` to attach an obscure filesystem, and the kernel does not currently have that driver loaded, the Linux kernel will **automatically trigger a dynamic modprobe helper** (`kmod`) to search for and load that module from host disk. This immediately exposes the kernel's vulnerable attack surface (e.g. legacy packet parsing bugs) to local exploitation, even if `init_module` itself was blocked. 

**The `jseccomp` response:** Blocking both direct loading and indirect auto-loading.

While `NO_EXEC` blocks the direct injection commands (`init_module`, `finit_module`), `jseccomp`'s **`PURE_COMPUTE`** policy goes much deeper: it blocks the entire `socket` and `mount` syscall families. By completely stripping the thread's ability to initialize sockets or attach mounts, `jseccomp` successfully plugs the dynamic auto-loading loophole at the thread boundary. A thread parsing JSON has **zero** legitimate reasons to create sockets or mount filesystems. Even if the underlying host kernel is highly vulnerable to legacy protocol exploits, the contained JVM thread is physically blocked from initiating the transitions that trigger module loading.

### The Host-Level Counterpart: ModuleJail

This application-level sandboxing mirrors a brilliant emerging trend in host-level hardening: **ModuleJail** (developed by Jasper Nuyens, as featured on OpenNet). 

While `jseccomp` blocks module-loading syscalls *inside the JVM thread*, `ModuleJail` operates at the host OS layer to scan running systems for dormant kernel modules and automatically blacklist them. 

This creates a perfect **Defense-in-Depth sandwich**:
1. **At the Host Layer:** `ModuleJail` locks down the OS kernel, ensuring vulnerable legacy modules can never be loaded system-wide.
2. **At the JVM Layer:** `jseccomp` blocks the syscall channels (`socket` families, `mount`, `init_module`) that an attacker would use to trigger dynamic kernel transitions in the first place.

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

Landlock uses `O_NOFOLLOW` when opening path descriptors — symlinks are rejected (`ELOOP`) to prevent an attacker who controls a symlink target from redirecting a Landlock rule to an unintended path.

---

## The Inherited File Descriptor Caveat

Seccomp `NO_NETWORK` blocks the *creation* of new network connections: `socket()`, `connect()`, `bind()`. It does not block `read()`, `write()`, or `sendmsg()` on *already-open* file descriptors.

If a worker thread inherits an open socket from a previous task (or receives one via `SCM_RIGHTS` before containment is applied), it can still communicate over that socket after containment. `NO_NETWORK` prevents new channels from being opened — it does not isolate pre-existing ones.

The defense: always create a fresh thread pool for contained tasks, never reuse threads that previously held uncontained sockets, and apply process-wide `NO_EXEC` to ensure the base process also can't establish new privileged channels.

---

## The Policy Matrix

| Attack vector | Blocked by | Policy needed |
|---|---|---|
| Shell injection (`execve`) | Seccomp arg-pass | `NO_EXEC` |
| Fileless malware (`memfd_create` + `execveat`) | Seccomp | `NO_EXEC` |
| Shellcode injection (`mmap PROT_EXEC`) | Seccomp BPF arg inspection | `PURE_COMPUTE` |
| io_uring evasion | Seccomp (`io_uring_setup`) | `NO_EXEC` |
| Kernel module injection (`init_module`, `finit_module`) | Seccomp | `NO_EXEC` |
| Network exfiltration (`connect`, `socket`) | Seccomp | `NO_NETWORK` |
| Filesystem snooping (`/etc/passwd`) | Landlock | Custom policy |
| Pivot to docker socket | Landlock | Custom policy |


---

## What jseccomp Does Not Stop

- **ROP/JOP gadget chains** — reusing existing mapped code. Requires ASLR + CFI.
- **In-process heap reads** — a contained thread still shares the JVM heap and can read any object it can reach.
- **Pre-established network channels** — inherited open file descriptors.
- **Orchestrator-level escapes** — if the JVM user has write access to `/etc/cron.d/` or the Docker socket, those escapes happen outside the syscall filter.

`jseccomp` is one defense layer in a stack, not a total sandbox.

---

*Next up: Part 4: Generating an SBoB for Java*

