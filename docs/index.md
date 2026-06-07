---
layout: default
---
# Backend Behavioral Sandboxing Series

Welcome to the **Backend Behavioral Sandboxing** article series. While the implementation examples and laboratory configurations are demonstrated using Java/JVM (`mazewall`), the core vulnerabilities, systems engineering challenges, and Linux kernel primitives (Seccomp-BPF, Landlock LSM) apply to all backend runtimes (Go, Node.js, Python, Rust).

This series explores the threat model of modern cloud-native backend applications and guides you through dynamic profiling, thread-level containment, and production-grade sandboxing.

## Project Vision & End Goal

The ultimate goal of this project is to provide developers with easy-to-use, frictionless tools to restrict code execution as much as possible. We aim to enable:
*   **Automatic SBoB:** Easy, automated Software Bill of Behavior (SBoB) generation for self-restraining applications.
*   **Glassbox Architecture:** Trivial sandboxing of the most dangerous parts of code, utilizing secure portals to communicate with isolated components like WebAssembly (WASM), GraalVM Isolates, and out-of-process sidecars.

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
* **Repository:** [jseccomp on GitHub](https://github.com/Pilleo/mazewall)
* **Design Docs:** [Internal Containment Design](internals/containment_design.html) | [Security Considerations](internals/SECURITY_CONSIDERATIONS.html)
