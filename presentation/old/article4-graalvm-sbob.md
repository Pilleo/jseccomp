# Generating an SBoB for Java: Where We Are and What's Missing

> **Series overview:** This is Part 4 of a 4-part series on behavioral security for cloud-native applications. **What this part adds:** the harder problem of *generating* the behavioral contract — the tooling gaps, the Merge Fallacy, and why GraalVM's closed-world model is currently the clearest path to automating it.


Parts 1–3 established the *enforcement* side: what a Software Bill of Behavior (SBoB) is, how the kernel primitives enforce it, and what attacks they concretely stop.

Now the harder question: **how do you actually create the contract?**

This is where honesty is required. The generation tooling is immature, the standards are forming, and the current best path is narrower than you'd like. Let's map it precisely.

---

## Static vs. Dynamic: The Honest Trade-off

The first instinct is static analysis. For an isolated, well-defined library — a pure JSON parser, a cryptography primitive — static analysis works reasonably well. We can analyze bytecode, trace call graphs, and assert that `org.json:json` never calls `java.net.Socket`.

For a full-scale Java application, static analysis runs into a wall. Modern frameworks rely on:
- **Reflection** for dependency injection and dynamic dispatch
- **Dynamic proxies** for AOP (Spring transactions, interceptors)
- **JNI** for native bridge libraries
- **Configuration-driven dispatch** where the active beans depend on environment variables at runtime

A static analyzer cannot definitively determine what a Spring Boot application will do at startup, because the behavior is constructed dynamically from classpath scanning and configuration files. The set of active endpoints, enabled features, and loaded providers isn't known until the context is initialized.

**Dynamic analysis** — observing the application as it runs — avoids these problems but introduces its own: coverage. No test suite exercises every possible state. Kafka consumers, scheduled jobs, error-handling paths, and admin endpoints are routinely absent from integration test coverage.

The conclusion is unavoidable: generating a meaningful SBoB requires combining static analysis, dynamic observation, and manual review. No single approach is sufficient.

---

## The Three-Step Blueprint

Here is the most practical path available today:

### Step 1: Generate Per-Dependency SBoBs

At the library scope, behavioral analysis is tractable. A library has a finite, testable API surface that doesn't depend on the caller's configuration.

The approach: instrument each library through a comprehensive test harness, forcing execution down all branches, while tracing at the syscall level with tools like **Inspektor Gadget** (`trace_exec`, `trace_open` gadgets). The resulting syscall profile is the library's BoB baseline.

To maximize branch coverage of libraries: use feedback-directed fuzzing (**JQF**, **Jazzer**), random test generators (**Randoop**), and evolutionary API fuzzing (**EvoMaster**). The goal is to exercise every code path through the library's public API under adversarial and edge-case inputs.

This generates a per-dependency BoB: *"This JSON parser calls `openat`, `read`, `mmap`, `brk`. It never calls `socket`, `connect`, `execve`, or `memfd_create`."*

### Step 2: Dynamic Coverage for the Application

Layer dynamic observation on top of the library baselines to capture framework-level behavior:

- **Integration tests:** Known business flows under real framework initialization
- **Chaos inputs:** Malformed and unexpected data to exercise error-handling paths
- **Production shadow traffic:** Replay real-world requests in a controlled staging environment against a BoB-instrumented instance
- **API fuzzing:** EvoMaster or similar tools that use evolutionary algorithms to generate complex inputs and maximize endpoint coverage

**Acknowledge the blind spots explicitly.** REST fuzzers don't trigger:
- Kafka/RabbitMQ consumer paths
- Scheduled jobs (`@Scheduled`, Quartz)
- File watchers and inotify-driven processing
- JMX and admin endpoints
- Shutdown hooks

These require dedicated, workload-specific observation campaigns separate from API coverage.

### Step 3: Merge, Then Prune

Combine the library baselines (Step 1) with the application observation profile (Step 2). This merge is where most real-world BoB implementations fail.

---

## The Merge Fallacy

The most common mistake in BoB generation is the naive merge.

If you concatenate the SBoBs of all dependencies, you produce a bloated super-permission set. Consider the AWS SDK. The SDK's BoB correctly declares that it *may* open outbound connections to S3, DynamoDB, SQS, Kinesis, and dozens of other services.

If your application only uses DynamoDB — and the AWS SDK v2 declares access to S3, SQS, Kinesis, and dozens of other services, with well over 100 distinct endpoint configurations — but you naively merged the full SDK SBoB, you have just granted your application permission to connect to all of them. In practice, your DynamoDB-only service might observe three endpoint patterns in production. You have re-introduced exactly the broad, permissive permissions that SBoB was supposed to eliminate.

**A useful SBoB must represent the application's *actual* behavior, not the theoretical maximum behavior of its dependencies.** The merged profile must be aggressively pruned to what dynamic observation actually confirmed.

This pruning is technically hard. It requires correlating library-level call sites with application-level execution paths, then computing which capability grants are reachable given the pruned call graph. This tooling does not exist as a production-ready product today.

---

## The Limits: Lazy Init, Hot Reload, Dynamic Config

Making BoB enforcement practical requires establishing a stable steady-state. Kubernetes readiness probes give a clean boundary: behavior during initialization is broad and complex; after the first successful health check, behavior should be narrow and predictable.

But several common Java patterns break this assumption:

**Lazy initialization:** Deferring startup of heavy components (connection pools, cache warmup) until the first tenant request — potentially hours after startup — means the "steady-state" BoB must still include the initialization-phase behaviors indefinitely. In a strict BoB model, lazy initialization is an anti-pattern.

**Dynamic configuration and hot reload:** Feature flags, runtime config pushes, and hot deploys break the steady-state assumption. If behavior can change arbitrarily without a restart, creating a restrictive static behavioral contract is nearly impossible.

These are real constraints that require architectural discipline. **For the PoC work ahead, the answer is GraalVM** — it sidesteps most of these problems by making the binary static. Standard JIT-compiled applications are the harder next step.

---

## GraalVM: The AOT Paradigm Shift

If standard JIT-compiled JVM applications render static analysis practically useless, **GraalVM Native Image represents a fundamental paradigm shift that restores the feasibility of static analysis.**

Standard Java security is completely reactive: it relies on dynamic observation to see what the application does, which is forever vulnerable to test coverage gaps. GraalVM changes the mathematical model by introducing the **Closed-World Assumption**.

In practice, GraalVM *approximates* a closed world: at compile time, it performs a whole-program points-to analysis that must account for all dynamic features, which the developer explicitly registers via **Reachability Metadata** (`reflect-config.json`, `proxy-config.json`, `jni-config.json`). Unregistered reflection fails at runtime; registered dynamic features are tracked in the call graph. The closed-world assumption applies to *unregistered* code paths — those are provably absent from the binary.

This approximation allows the static native image builder to construct a **provably complete call graph** over the explicitly registered surface of the application. Unreachable code paths are physically removed from the binary via Dead Code Elimination (DCE).

### Dead Code Elimination as a Pruning Mechanism

In a hypothetical future tooling pipeline, GraalVM’s closed-world compilation solves the "Merge Fallacy" mechanically rather than dynamically:

1. **Statically Traced Call-Graphs:** Since the compiler constructs a complete, explicit call graph, static analysis tools can trace exactly which library call sites are reachable from the application entry point.
2. **Deterministic Pruning:** If your application depends on a large library (like the AWS SDK) but only initializes a DynamoDB client, the compiler's AOT analysis statically proves that the Kinesis and S3 clients are unreachable. 
3. **Physical Capability Dropping:** The S3 code paths—and their associated syscall behaviors—are permanently deleted from the final binary. The associated capabilities (e.g. TCP connect permissions to S3 buckets) are mechanically dropped from the SBoB without requiring dynamic observation.

Instead of trying to deduce the application's actual behavior by running incomplete integration tests (which is reactive), GraalVM lets us **mathematically prove** the upper bound of the application's capabilities.

### Leveraging Reachability Metadata

Because the Java ecosystem has heavily standardized around GraalVM's reachability metadata (driven by the Spring Boot and Quarkus native compilation initiatives), an SBoB generation tool does not need to invent dynamic dispatch resolution from scratch. It can directly ingest the application's `reflect-config.json`, `proxy-config.json`, and `jni-config.json` to map the runtime boundaries of dynamic Java features.

**The critical gap to keep front of mind:** DCE gives you a smaller, more auditable binary — but it does not tell you what syscalls that binary actually calls. Reachability metadata tells the compiler what code to *keep*; it does not describe what that code *does* at the kernel level. You still need syscall-level tracing (e.g., Inspektor Gadget, `strace`) to map the final leaf nodes of the call graph to system call numbers. GraalVM makes the static analysis target tractable; it does not replace the tracing step.

### eBPF Profiling: Cleaner Than JIT

Profiling a standard JVM with eBPF-based syscall tracers is extremely noisy. The JIT compiler periodically allocates executable memory segments and patches them during deoptimisation, generating `mmap(PROT_EXEC)` and `mprotect` noise that is difficult to attribute to application-level behaviour. Distinguishing JIT-internal syscalls from application-level ones requires filtering that is currently manual and error-prone.

A GraalVM native binary eliminates this noise almost entirely. The binary behaves more like a standard C executable — startup syscalls are predictable, steady-state syscalls are stable, and there are no ongoing JIT recompilation events.

<details>
<summary><b>🔍 Deep Dive: eBPF Profiling & Debug Symbols</b></summary>

**The dynamic tracing gap:** DWARF debug symbol support in GraalVM Native Image is still maturing. Specifically, **inlined functions flatten the call-stack context**. Because the AOT compiler aggressively inlines hot methods, an inlined function does not appear as a distinct frame in the symbol table. This makes it impossible for an eBPF tool using `uprobes` to map a system call stacktrace back to the original source library that initiated it. You can observe the syscall; attributing it to the exact library-level call site is incredibly hard.

#### The Compiler Mitigation

To build accurate profiling-based SBoBs, developers must instruct the GraalVM compiler to retain frame information. This is accomplished using specific compiler flags during the profiling build:

* **`-H:PreserveFrameInformation`**: Instructs the native image builder to preserve stack trace frame details for all methods, including inlined ones.
* **`-H:-InlineBeforeAnalysis`**: Prevents the optimizer from performing function inlining prior to the points-to call-graph analysis, ensuring that symbols remain distinct and map cleanly to the original libraries.

These flags are intended for profiling builds, not production. They increase binary size and can incur minor performance overheads.

> **Stability caveat:** GraalVM native-image compiler flags (`-H:*`) are not stable public API — they have been renamed or removed between versions. Before relying on these flags, verify their availability against your specific GraalVM version's output of `native-image --expert-options-all`. Do not hardcode them into production CI without a version pin.
</details>

### Control Flow Integrity

GraalVM AOT compilation *positions* native Image binaries to be better candidates for hardware CFI features — **Intel CET (Shadow Stacks, IBT)** and **ARM BTI (Branch Target Identification)** — compared to JIT-compiled JVMs. The JIT compiler's requirement to frequently modify executable memory conflicts fundamentally with the kernel's ability to enforce control flow integrity at that memory; a static binary has no such constraint.

However, as of mid-2025, **GraalVM Native Image does not have documented, first-class Intel CET or ARM BTI support**. Whether a native image binary receives CET/BTI protections depends entirely on the system linker's behaviour — `gcc` or `ld` may emit the required ELF notes (`PT_GNU_PROPERTY`) if the host toolchain supports it, but this is not a GraalVM-controlled, verified feature. Standard OS-level protections (ASLR, NX/DEP, stack canaries via compiler flags) are available and should be explicitly enabled via the linking toolchain. The CET/BTI story for native images is an open engineering area, not a solved one.

---

## The Counter-Argument and Its Limits

The obvious objection: *"Most Java applications don't run on GraalVM Native Image."*

True. GraalVM has real costs: longer build times, more complex debugging (no runtime reflection, more explicit configuration), ecosystem compatibility issues (libraries that don't yet provide reachability metadata), and cold-start trade-offs in some workloads.

These are legitimate engineering objections, not security denialism. Many organizations have rational reasons to stay on JIT-compiled JVMs.

The point is narrower: for the *PoC problem* of "can we generate a high-confidence, pruned SBoB automatically," GraalVM is currently the clearest path because it eliminates the hardest sources of noise. Standard JIT-compiled SBoB generation is the harder next problem — not a reason to abandon the idea, but a reason to sequence the work correctly.

---

## What Comes Next

While the underlying Linux kernel primitives (Seccomp and Landlock) are production-ready, the JVM-level integration in `jseccomp` is entirely experimental and untested. The entire codebase is a research proof-of-concept.


If you are working on:
- Syscall attribution tooling for GraalVM native binaries
- Automated per-dependency SBoB generation using Inspektor Gadget + fuzzing pipelines
...

...the author is interested in collaborating on these engineering challenges.

- **Instrument your CI pipeline with Inspektor Gadget** and start profiling your application's syscall footprint — regardless of whether you run GraalVM. Every application benefits from knowing its actual runtime footprint.
- **Watch and contribute to the emerging Software Bill of Behavior (SBoB) specification:** Visit [billofbehavior.com](https://billofbehavior.com) and follow the open specification work at [github.com/k8sstormcenter/bob](https://github.com/k8sstormcenter/bob).

---

## Where This Series Leaves You

Four articles in, the thesis is simple: behavioral security at the thread level is *possible today* in the JVM using standard Linux kernel primitives, requires no external infrastructure, and blocks real attack classes that container-level profiles miss. The limits are real — ACE bypass via shared heap, safepoint constraints, the Loom carrier problem — and have been stated precisely rather than glossed over.

The generation side (producing the SBoB contract automatically) is harder and less mature. The Merge Fallacy is the central unsolved problem: pruning a dependency's theoretical capability set down to what the application actually uses. GraalVM's closed-world model is the most tractable current approach to this, because DCE does the pruning mechanically rather than requiring runtime observation to cover every code path.

The next concrete engineering steps, in rough priority order:
1. Syscall tracing integration for GraalVM native binaries with stable symbol attribution
2. Per-library SBoB generation pipelines using Inspektor Gadget + fuzzing
3. Tooling to merge and prune dependency SBoBs against observed production footprints
4. An open, machine-readable SBoB schema that runtime enforcement engines can consume directly

None of this is complete. All of it is tractable. If you read this far and disagree with something, the repository is the right place to continue the argument.
