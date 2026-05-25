# Guidelines for AI Coding Agents in mazewall

Welcome, AI Agent. This repository contains **mazewall**, a kernel-enforced, thread-scoped and process-wide sandboxing library for JVM applications using Linux **Seccomp-BPF** and **Landlock LSM** via the JDK **Foreign Function & Memory (FFM) API**.

As an AI agent pair-programming on this project, you are assisting in transitioning this project from a Proof of Concept (PoC) to a production-grade library. The minimum supported JDK is **22** (FFM API finalization); the codebase targets **Java 25 idioms** where applicable. Because this is a security-critical project that directly interfaces with the Linux kernel and manipulates JVM threads, you must adhere strictly to the following rules, constraints, and engineering philosophies.

---

## 🚧 Hard Boundaries

**⚠️ Ask First:**
*   Adding new dependencies.
*   Making breaking API changes.
*   Modifying the core BPF linear scan architecture.

**🚫 Never Do:**
*   Never catch `EPERM` or `EACCES` exceptions without rethrowing or crashing (No silent bypasses).
*   Never block JVM coordination syscalls (`futex`, `clone` with `CLONE_THREAD`, `rt_sigreturn`).
*   Never combine `SECCOMP_FILTER_FLAG_TSYNC` and `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
*   Never use `JAVA_LONG` for 32-bit `sock_filter` fields.

---

## 📓 Code Issues & Discoveries Journal

Whenever you discover a bug, architectural gap, kernel-level nuance, or security vulnerability, you MUST log it in `docs/internals/code_issues_backlog.md`. Do not leave critical insights buried in chat history.

**Format for new findings:**
```markdown
### 🔴 [Severity (High/Medium/Low/Critical)]: [Title]
**Context:** [What you found and why it exists]
**Needed:** [How to fix or prevent it]
```

---

## 📝 Presentation & Output Format

When presenting a fix or creating a PR, use the following format:
*   **🚨 Severity:** [CRITICAL / HIGH / MEDIUM / LOW / ENHANCEMENT]
*   **💡 Issue:** [Description of the vulnerability or bug]
*   **🎯 Impact:** [What happens if triggered, e.g., JVM Deadlock, logic error]
*   **🔧 Fix:** [How it is resolved]
*   **✅ Verification:** [How the fix was tested]

---

## 🔄 Iterative Development & Testing

*   **Step-by-Step Execution:** Do not attempt massive refactors in a single pass. Make changes iteratively and surgically.
*   **Constant Verification:** Test after **each** logical step using the Podman test suite (`podman compose exec mazewall ./gradlew test`). The codebase must remain buildable and tests must pass at every intermediate stage.

---

## 1. Core Engineering Philosophy & Tone

### Zero Hype, Absolute Certainty
*   **No Marketing or Speculative Language:** Avoid promotional, flashy, or hand-wavy descriptions. This library operates at the kernel-user space boundary where errors lead to fatal JVM deadlocks or JVM bypasses.
*   **Rigorous Decision Making:** Every choice must be double and triple checked. A single missed detail can result in catastrophic failure (JVM deadlocks, kernel instability, silent security bypasses).
*   **Honest Limitations:** Every security boundary must be documented with its exact threat model, caveats, and failure modes. If you are not 100% sure about a kernel behavior, JVM internal mechanism, or system call side-effect:
    1.  **Do not guess or assume.**
    2.  Search the codebase, `SECURITY_CONSIDERATIONS.md`, `profiler_design.md`, `containment_design.md`, and Linux manual pages — in that order. These files contain hard-won, project-specific kernel behavior discoveries that man pages do not cover.
    3.  Flag the uncertainty explicitly in comments and discuss it with the developer.
*   **Documentation Split:**
    *   **`/presentation`:** Addressed to general Backend/Software Engineers. Conceptually accessible; no BPF jump tables.
    *   **Core code, KDocs, & design docs:** Highly rigorous. Exact syscall numbers, FFM memory layouts, kernel invariants.
*   **Mandatory Documentation of Findings:** Any new architectural finding, kernel behavior discovery, or security nuance *must* be documented immediately in the appropriate Markdown file. Do not leave critical insights in conversation histories.

---

## 2. Strict Protection Against Unsafe Fallback / Bypass Scenarios

> [!WARNING]
> **CRITICAL SECURITY INSTRUCTION:** AI agents historically tend to implement "fail-safe" or "silent bypass" fallback behavior to make code "just work." **This is strictly unacceptable in a security library.**

*   **Never Implement Silent Bypasses:** Do not catch exceptions silently or downgrade a failed seccomp/Landlock installation to a warning-and-bypass unless that fallback is explicitly configured by the operator.
*   **Fail Closed by Default:** The **default `FallbackBehavior` is `FAIL`** (see `Platform.configuredFallback()` — it returns `FallbackBehavior.FAIL` unless the operator explicitly overrides via `-Dio.mazewall.fallback=WARN_AND_BYPASS` or `IO_MAZEWALL_FALLBACK=WARN_AND_BYPASS`). This is intentional and must not be changed.
*   **No Unconsulted Fallbacks:** Do not write automatic recovery loops or mock environments (like simulating a syscall return value via register manipulation) wit---

## 3. Directory Structure & Technical Delegations

`mazewall` is split into two specialized subprojects. Detailed engineering safety rules, FFM design conventions, and architectural bounds are documented in the respective **child `AGENTS.md` files**:

### A. The `:enforcer` Module (Core Sandbox Engine)
Responsible for production-grade sandboxing using Linux Seccomp-BPF and Landlock LSM through the JDK Foreign Function & Memory (FFM) API.
*   **Key Source Files:** `Policy.kt`, `BpfFilter.kt`, `PureJavaBpfEngine.kt`, `Landlock.kt`, `ContainedExecutors.kt`, `LinuxNative.kt`, `Platform.kt`.
*   **Engineering Rules:**
    > [!IMPORTANT]
    > Before making any changes inside `/enforcer`, you **must** read and adhere to the strict guidelines in **[enforcer/AGENTS.md](file:///home/leanid/Documents/code/java/jseccomp/enforcer/AGENTS.md)**.
    >
    > It covers JVM coordination system calls (never block `futex`, `clone` with `CLONE_THREAD`, etc.), preventing Loom Virtual Thread carrier poisoning, and FFM `errno` capture safety.

### B. The `:profiler` Module (Developer Diagnostic Suite)
Responsible for unprivileged system call profiling and Landlock path discovery using BPF `USER_NOTIF` sockets, progressive testing, and descendant `strace` parsing.
*   **Key Source Files:** `Profiler.kt`, `ProfilerDaemon.kt`, `IterativeProfiler.kt`, `StraceProfiler.kt`, `BobCompiler.kt`, `BillOfBehavior.kt`.
*   **Engineering Rules:**
    > [!IMPORTANT]
    > Before making any changes inside `/profiler`, you **must** read and adhere to the strict guidelines in **[profiler/AGENTS.md](file:///home/leanid/Documents/code/java/jseccomp/profiler/AGENTS.md)**.
    >
    > It covers the critical out-of-process `USER_NOTIF` ACK loop deadlock prevention, Yama `ptrace_scope` configurations, and `strace` log parsing.

---

## 4. Shared-Memory ACE Escape Caveat (The Core Threat Model)

Thread-scoped seccomp is **not** an absolute security boundary against an attacker with Arbitrary Code Execution (ACE) on the sandboxed thread. Because all JVM threads share the same address space and heap, a native memory corruption exploit (e.g., via buffer overflow or FFM `Unsafe` pointer manipulation) on a contained thread can corrupt memory on unrestricted sibling or helper threads to achieve escape.

*   **Mandatory Baseline:** Tier 1 (process-wide `NO_EXEC` baseline, via `ContainedExecutors.installOnProcess`) is an absolute architectural backstop, not an optional recommendation. Stacking thread-scoped Tier 2 containment on top mitigates the blast radius of data-oriented attacks (SSRF, XXE, SQLi), but must never be presented alone as a complete security boundary. Refer to [SECURITY_CONSIDERATIONS.md](file:///home/leanid/Documents/code/java/jseccomp/docs/internals/SECURITY_CONSIDERATIONS.md) for the complete threat matrix.

---

## 5. Testing and Verification Guidelines

*   **Testing is Mandatory:** Any bugfix, behavioral change, or new parameter **must** be accompanied by an automated test.
*   **Running Tests:** Always run using the nested-seccomp OCI profile:
    ```bash
    podman compose up -d
    podman compose exec mazewall ./gradlew test
    ```
*   **Module Check Tasks:** Verify your changes specifically pass module checks before pushing:
    *   `:enforcer:check` (Landlock $\ge 65\%$, LinuxNative $\ge 78\%$, core classes $\ge 80\%$ Jacoco instruction coverage)
    *   `:profiler:check` (Profiler $\ge 60\%$ Jacoco instruction coverage)

---

## 6. Key Design Documents

Before modifying components, read the relevant design document:

| Document                                                                                                                 | Covers                                                                   |
|--------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [containment_design.md](file:///home/leanid/Documents/code/java/jseccomp/docs/internals/containment_design.md)           | BPF scan loops, argument inspections, Landlock ordering, FFM layouts.    |
| [profiler_design.md](file:///home/leanid/Documents/code/java/jseccomp/docs/internals/profiler_design.md)                 | USER_NOTIF architecture, socket SCM_RIGHTS, ACK loop protocol.           |
| [SECURITY_CONSIDERATIONS.md](file:///home/leanid/Documents/code/java/jseccomp/docs/internals/SECURITY_CONSIDERATIONS.md) | Full threat model, ACE escape caveats, K8s custom profiles, Yama scopes. |

