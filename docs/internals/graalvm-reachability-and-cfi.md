# GraalVM Reachability and CFI

### Dead Code Elimination as a Pruning Mechanism

In a hypothetical future tooling pipeline, GraalVM’s closed-world compilation solves the "Merge Fallacy" mechanically rather than dynamically:

1. **Statically Traced Call-Graphs:** Since the compiler constructs a complete, explicit call graph, static analysis tools can trace exactly which library call sites are reachable from the application entry point.
2. **Deterministic Pruning:** If your application depends on a large library (like the AWS SDK) but only initializes a DynamoDB client, the compiler's AOT analysis statically proves that the Kinesis and S3 clients are unreachable. 
3. **Physical Capability Dropping:** The S3 code paths—and their associated syscall behaviors—are permanently deleted from the final binary. The associated capabilities (e.g. TCP connect permissions to S3 buckets) are mechanically dropped from the SBoB without requiring dynamic observation.

Instead of trying to deduce the application's actual behavior by running incomplete integration tests (which is reactive), GraalVM lets us **mathematically prove** the upper bound of the application's capabilities.

### Leveraging Reachability Metadata

Because the Java ecosystem has heavily standardized around GraalVM's reachability metadata (driven by the Spring Boot and Quarkus native compilation initiatives), an SBoB generation tool does not need to invent dynamic dispatch resolution from scratch. It can directly ingest the application's `reflect-config.json`, `proxy-config.json`, and `jni-config.json` to map the runtime boundaries of dynamic Java features.

**The operational gap to acknowledge:** Reachability metadata tells the compiler what code to *keep*. It does not describe what that code *does* at the kernel level. You still need syscall-level tracing to map the final leaf nodes of the call graph to system call numbers; GraalVM simply makes the static analysis target tractable.

### eBPF Profiling: Cleaner Than JIT

Profiling a standard JVM with eBPF-based syscall tracers is extremely noisy. The JIT compiler constantly calls `mmap(PROT_EXEC)`, `mprotect`, and related syscalls to allocate, optimize, and garbage-collect compiled code. Distinguishing JIT-internal syscalls from application-level ones requires filtering that is currently manual and error-prone.

A GraalVM native binary eliminates this noise almost entirely. The binary behaves more like a standard C executable — startup syscalls are predictable, steady-state syscalls are stable, and there are no ongoing JIT recompilation events.

**The dynamic tracing gap:** DWARF debug symbol support in GraalVM Native Image is still maturing. Specifically, **inlined functions flatten the call-stack context**. Because the AOT compiler aggressively inlines hot methods, an inlined function does not appear as a distinct frame in the symbol table. This makes it impossible for an eBPF tool using `uprobes` to map a system call stacktrace back to the original source library that initiated it. You can observe the syscall; attributing it to the exact library-level call site is incredibly hard.

#### The Compiler Mitigation

To build accurate profiling-based SBoBs, developers must instruct the GraalVM compiler to retain frame information. This is accomplished using specific compiler flags during the profiling build:

* **`-H:PreserveFrameInformation`**: Instructs the native image builder to preserve stack trace frame details for all methods, including inlined ones.
* **`-H:-InlineBeforeAnalysis`**: Prevents the optimizer from performing function inlining prior to the points-to call-graph analysis, ensuring that symbols remain distinct and map cleanly to the original libraries.

While these flags slightly increase binary size and can incur minor performance overheads, they are **mandatory** during the profiling and SBoB generation phase to guarantee high-precision system call attribution.

### Control Flow Integrity

GraalVM AOT compilation positions native Image binaries to be better candidates for hardware CFI features — **Intel CET (Shadow Stacks, IBT)** and **ARM BTI (Branch Target Identification)** — compared to JIT-compiled JVMs. The JIT compiler's requirement to frequently modify executable memory conflicts fundamentally with the kernel's ability to enforce control flow integrity at that memory; a static binary has no such constraint.

> [!WARNING]
> **CET/BTI support is not yet production-complete in GraalVM.** As of mid-2025, GraalVM Native Image does not have documented, first-class Intel CET or ARM BTI support. Whether a native image binary receives CET/BTI protections depends entirely on the system linker's behaviour — `gcc` or `ld` may emit the required ELF notes (`PT_GNU_PROPERTY`) if the host toolchain supports it, but this is not a GraalVM-controlled, verified feature. Standard OS-level protections (ASLR, NX/DEP, stack canaries) are available and should be explicitly enabled via the linking toolchain. Treat this as "closer than standard JVM, not yet production-complete."

These features enforce that the CPU only branches to valid, declared targets — making ROP/JOP gadget chains dramatically harder to execute even if an attacker achieves arbitrary write. Standard OS-level protections (ASLR, NX/DEP, stack canaries via compiler flags) are available and should be explicitly enabled via the linking toolchain.

---