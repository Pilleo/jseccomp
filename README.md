# mazewall

[![CI](https://github.com/Pilleo/mazewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Pilleo/mazewall/actions/workflows/ci.yml)
[![JitPack](https://jitpack.io/v/Pilleo/mazewall.svg)](https://jitpack.io/#Pilleo/mazewall)

**Per-thread syscall sandboxing for JVM applications — no native code, no root, no restarts.**

> [!NOTE]
> **Pre-Alpha.** Core enforcement and profiling work end-to-end. API is unstable and known issues are actively tracked. If you're evaluating this for your stack or want to contribute, [open a discussion](https://github.com/Pilleo/mazewall/discussions).

---

## The Problem

When Log4Shell hit, the attacker's code ran on the *exact same thread* as the vulnerable logger — a thread that already had `execve` permission because the rest of the JVM needed it.

The same is true for every thread in your JVM today: your XML parser, your YAML importer, your PDF generator, and your authentication service all share the same OS permissions. A compromise in any of them is a compromise of all of them.

Container-level profiles (Docker's `--security-opt seccomp`) can't fix this — they apply one policy to the entire process. **The granularity you need is at the thread pool level.**

## The Solution

mazewall wraps any standard `ExecutorService` and installs a **kernel-enforced syscall filter** for those threads only. The filter is applied via Linux `prctl`/`seccomp` — the same mechanism Docker uses, applied from inside the JVM, without root privileges or native C dependencies. Once installed, no JVM vulnerability can remove it.

```kotlin
val safe = ContainedExecutors.wrap(
    Executors.newSingleThreadExecutor(),
    Policy.NO_EXEC                        // blocks execve, fork, memfd_create, io_uring
)

safe.submit { vulnerableLogger.log(maliciousInput) }
// The kernel intercepts execve() → EPERM.
// No shell is spawned. Throws ContainmentViolationException.
```

That's the whole API for most use cases.

---

## How the Layers Fit Together

mazewall operates in two tiers. Think of it as the difference between the building's outer wall and the locks on the rooms inside:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Host / Container                                                   │
│  ┌──── Docker / Podman (Tier 0) ─────────────────────────────────┐ │
│  │  One Seccomp profile for the entire container process          │ │
│  │                                                                │ │
│  │  ┌─────────── JVM Process ────────────────────────────────┐   │ │
│  │  │                                                         │   │ │
│  │  │  [Tier 1] installOnProcess(NO_EXEC)  ← process-wide    │   │ │
│  │  │  Nothing in this JVM ever spawns a shell               │   │ │
│  │  │                                                         │   │ │
│  │  │  ┌─ HTTP Thread Pool ──┐  ┌─ YAML Import Pool ───────┐ │   │ │
│  │  │  │  [no extra limits]  │  │  [Tier 2]                │ │   │ │
│  │  │  │                     │  │  ✗ execve   ✗ network    │ │   │ │
│  │  │  └─────────────────────┘  │  📁 /data/in only        │ │   │ │
│  │  │                           └──────────────────────────┘ │   │ │
│  │  │  ┌─ PDF Generator Pool ────────────────────────────┐   │   │ │
│  │  │  │  [Tier 2]                                        │   │   │ │
│  │  │  │  ✗ execve   ✗ network   ✗ filesystem writes      │   │   │ │
│  │  │  └─────────────────────────────────────────────────┘   │   │ │
│  │  └─────────────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

| Tier | API | Scope | Purpose |
|---|---|---|---|
| **Tier 1** | `ContainedExecutors.installOnProcess(Policy.NO_EXEC)` | Entire JVM | Global backstop — prevents any thread from ever spawning a child process |
| **Tier 2** | `ContainedExecutors.wrap(executor, policy)` | One thread pool | Surgical restriction — stops data-plane attacks (SSRF, XXE, path traversal) on specific pools |

> [!IMPORTANT]
> **Stack Tier 1 first.** Tier 2 alone does not fully isolate malicious code that can use standard Java concurrency APIs (`CompletableFuture`, virtual threads) to escape to unrestricted sibling threads. See [SECURITY_CONSIDERATIONS.md](docs/internals/SECURITY_CONSIDERATIONS.md) for the complete threat model.

---

## Profiling: Let Your Code Define Its Own Policy

You don't have to guess which syscalls your workload needs. The `:profiler` module observes a workload during a test run and generates the exact `Policy` DSL you need:

```kotlin
val result = Profiler.profile {
    myXmlParser.parse(untrustedInput)   // run it under observation
}

println(result.behavior.toDsl())
// Output:
// Policy.builder()
//     .base(Policy.NO_NETWORK)
//     .allowFsRead("/app/schemas")
//     .allowJvmClasspath()
//     .build()
```

Paste the output, wrap your executor — done. No manual BPF assembly, no trial-and-error deadlocks.

This profiling workflow (observe → generate → enforce) is the foundation of [SBoB (Software Bill of Behavior)](docs/presentation/article.md) — a behavioral contract that travels alongside your application, analogous to an SBOM for composition.

---

## Where to Go Next

| I want to… | Go to |
|---|---|
| Install and write my first policy | [GETTING_STARTED.md](GETTING_STARTED.md) |
| Auto-generate a policy from my workload | [profiler/README.md](profiler/README.md) |
| See it block real CVEs (Log4Shell, SSRF, XXE) | [Demo README](demos/vulnerable-web-app/README.md) |
| Understand the threat model and what it can't stop | [SECURITY_CONSIDERATIONS.md](docs/internals/SECURITY_CONSIDERATIONS.md) |
| Read the deep-dive article series | [Article series](#article-series) |
| Contribute or modify the codebase | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## How It Works (in plain terms)

mazewall uses two Linux kernel features that have been in Docker since 2014:

| Kernel feature | What it does | Docker equivalent |
|---|---|---|
| **Seccomp-BPF** | Blocks specific syscalls per thread | `--security-opt seccomp=profile.json` |
| **Landlock LSM** | Restricts filesystem paths per thread | `--read-only` + bind mounts |

The difference: Docker applies these at the *container* (process) level. mazewall applies them at the *thread* (executor) level, from inside the JVM, without root privileges and without a native C dependency.

Implementation uses the JDK **Foreign Function & Memory API** (JDK 22+) to make the `prctl`/`seccomp` syscalls directly from Kotlin.

Elasticsearch pioneered a process-wide variant of this pattern in the JVM since 2015 (originally configured via `bootstrap.system_call_filter`, now a mandatory, non-configurable startup check). mazewall brings that approach to per-thread granularity, composable with standard Java executor infrastructure.

---

## Built-In Policies

| Policy | Blocks | Typical use |
|---|---|---|
| `Policy.NO_EXEC` | `execve`, `fork`, `memfd_create`, `io_uring_*`, `ptrace` | Process-wide startup lockdown |
| `Policy.NO_NETWORK` | `connect`, `socket`, `sendmsg`, `io_uring_*` | Parsers that need disk but no network |
| `Policy.PURE_COMPUTE_UNSAFE` | All of the above + filesystem writes + `mmap(PROT_EXEC)` | Crypto/image workers |
| `Policy.PURE_COMPUTE` | `PURE_COMPUTE_UNSAFE` + auto-whitelists JVM classpath | Same, without lazy-classload crashes |

Policies are composable via a builder — see [GETTING_STARTED.md](GETTING_STARTED.md#building-a-custom-policy).

---

## Project Modules

| Module | Purpose | Use in production? |
|---|---|---|
| `:enforcer` | Core runtime — zero dependencies beyond Kotlin stdlib | ✅ Yes (pre-alpha) |
| `:profiler` | Developer tool — profiles a workload and generates a minimal policy | 🔬 Dev/test only |
| `:demos:cli-demo` | Interactive CLI exploits showcase | 🚫 Demo only |
| `:demos:vulnerable-app` | Spring Boot CVE demo (Log4Shell, SSRF, XXE…) | 🚫 Demo only |

---

## Current State

The library is actively developed. Core sandboxing (`NO_EXEC`, `NO_NETWORK`, `PURE_COMPUTE`) and the profiler workflow are functional and tested via automated CI. Known issues and open bugs are tracked in [`docs/internals/code_issues_backlog.md`](docs/internals/code_issues_backlog.md).

API and behavior **will change**. If you're evaluating this for production use, follow the repo and check the backlog.

---

## Article Series

Background reading on the kernel mechanics and threat model:

| Part | Title | Focus |
|---|---|---|
| **1** | [Do You Really Know What Your App Is Doing at Runtime?](docs/presentation/article.md) | Seccomp, Landlock, SBoB concepts |
| **2** | [Let Your Code Build Its Own Sandbox](docs/presentation/article2-profiler.md) | Dynamic profiling, USER_NOTIF daemon |
| **3** | [Thread-Scoped JVM Containment: The Mechanics](docs/presentation/article3-enforcement.md) | FFM bridge, GC safepoints, Loom VT |
| **4** | [The Attacks We Actually Stop](docs/presentation/article4-attacks.md) | Log4Shell, fileless malware, io_uring bypass |
| **5** | [Generating an SBoB for Java: What's Missing](docs/presentation/article5-graalvm.md) | Dynamic classloading, GraalVM AOT |
| **6** | [Beyond the Thread: Isolates, WebAssembly, Tooling](docs/presentation/article6-isolates.md) | GraalVM Isolates, WASI, sidecar portals |

---

## License

Apache License 2.0.
