---
layout: default
---
# Mazewall: Behavioral JVM Security Series

Welcome to the **Mazewall** article series. Mazewall is a kernel-enforced, thread-scoped and process-wide sandboxing library for JVM applications using Linux **Seccomp-BPF** and **Landlock LSM** via the JDK **Foreign Function & Memory (FFM) API**.

This series explores the threat model of modern cloud-native Java applications and guides you through dynamic profiling, thread-level containment, and production-grade sandboxing.

## Read the Series

1. **[Part 1: The Core Threat Model & Attack Vectors](presentation/article.html)**  
   Understanding in-process security boundaries, memory sharing constraints, and standard bypasses in the JVM.

2. **[Part 2: Dynamic Policy Profiling & Discovery](presentation/article2-profiler.html)**  
   How to profile JVM workloads dynamically to discover their system call and file path dependencies.

3. **[Part 3: Thread-Scoped JVM Containment Mechanics](presentation/article3-enforcement.html)**  
   A deep dive into FFM errno safety, Loom virtual thread carrier poisoning, and JVM coordination whitelists.

4. **[Part 4: Exploit Scenarios & Kernel Blocking](presentation/article4-attacks.html)**  
   Testing Mazewall against shell injection, fileless malware, JIT executable memory, and `io_uring` evasions.

5. **[Part 5: Ahead-of-Time SBoB compilation with GraalVM](presentation/article5-graalvm.html)**  
   Hardening JVM containment using AOT static analysis and removing JIT runtime compilation noise.

6. **[Part 6: Heap Isolation via GraalVM Isolates](presentation/article6-isolates.html)**  
   Achieving high-density, multi-tenant heap boundaries in the same OS process.

7. **[Part 7: Safe Parsing using WebAssembly Runtimes](presentation/article7-wasm.html)**  
   Eliminating native execution risks by running untrusted parsers in instruction-level Wasm sandboxes.

---

## Getting Started with Mazewall

To inspect the source code or run the PoC sandbox locally:
* **Repository:** [jseccomp on GitHub](https://github.com/leanid/jseccomp)
* **Design Docs:** [Internal Containment Design](internals/containment_design.html) | [Security Considerations](internals/SECURITY_CONSIDERATIONS.html)
