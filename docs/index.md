---
layout: default
---
# Backend Behavioral Sandboxing Series

Welcome to the **Backend Behavioral Sandboxing** article series. While the implementation examples and laboratory configurations are demonstrated using Java/JVM (`mazewall`), the core vulnerabilities, systems engineering challenges, and Linux kernel primitives (Seccomp-BPF, Landlock LSM) apply to all backend runtimes (Go, Node.js, Python, Rust).

This series explores the threat model of modern cloud-native backend applications and guides you through dynamic profiling, thread-level containment, and production-grade sandboxing.

## Read the Series

1. **[Part 1: The Core Threat Model & Attack Vectors](presentation/article.html)**  
   Understanding in-process security boundaries, memory sharing constraints, and standard bypasses.

2. **[Part 2: Dynamic Policy Profiling & Discovery](presentation/article2-profiler.html)**  
   How to profile workloads dynamically to discover their system call and file path dependencies.

3. **[Part 3: Thread-Scoped Containment Mechanics](presentation/article3-enforcement.html)**  
   A deep dive into FFM native bindings, errno safety races, Loom virtual thread carrier poisoning, and runtime coordination whitelists.

4. **[Part 4: Exploit Scenarios & Kernel Blocking](presentation/article4-attacks.html)**  
   Testing containment against shell injection, fileless malware, JIT executable memory, and `io_uring` evasions.

5. **[Part 5: Ahead-of-Time SBoB compilation with GraalVM](presentation/article5-graalvm.html)**  
   Hardening containment using AOT static analysis and removing JIT runtime compilation noise.

6. **[Part 6: Beyond the Thread: Isolates, WebAssembly, and Tooling](presentation/article6-isolates.html)**  
   Achieving heap-level isolation via GraalVM Isolates, instruction-level isolation via WebAssembly, and defining the future developer tooling roadmap.

---

## Getting Started with Mazewall

To inspect the source code or run the PoC sandbox locally:
* **Repository:** [jseccomp on GitHub](https://github.com/leanid/jseccomp)
* **Design Docs:** [Internal Containment Design](internals/containment_design.html) | [Security Considerations](internals/SECURITY_CONSIDERATIONS.html)
