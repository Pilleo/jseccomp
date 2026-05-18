# Generating an SBoB for Java: A Blueprint for the Future

In [Part 1](#), we explored the transition from compositional transparency (SBOM) to behavioral transparency (SBoB) and how eBPF makes observing runtime behavior practical. In [Part 2](#), we applied these concepts to the JVM, using Seccomp and Landlock to neutralize threats like fileless malware and shellcode.

Now, we face the operational reality: How do we actually create the Bill of Behavior? Let’s conduct a thought experiment on generating a meaningful SBoB for a real-world Spring Boot application.

## Static vs. Dynamic: The Honest Trade-off

When defining behavior, the first instinct is to rely on static analysis. For isolated, well-defined libraries, static analysis works well. We can analyze a JSON parser's bytecode and confidently assert it never calls `java.net.Socket`.

However, for a full-scale Java application, static analysis faces an uphill battle. Modern frameworks rely heavily on reflection, dynamic proxies, Java Native Interface (JNI), and configuration-driven dispatch. A static analyzer cannot definitively prove what a Spring Boot application will do at runtime because the behavior is constructed dynamically based on classpath scanning and configuration files. 

### The Platform Variability Problem
Even more challenging is the **JVM inconsistency**. Because the SBoB is enforced at the kernel level (syscalls), it is inextricably tied to the underlying runtime. 
*   **JVM Versions:** Different versions of the JVM (e.g., Java 17 vs Java 21) may use entirely different system calls to achieve the same functionality (like memory allocation or thread management). 
*   **Compiler Differences:** The syscall profile of a standard OpenJDK JIT-compiled application will look radically different from a GraalVM Native Image binary.

This means the same library, with the exact same application code, will require different SBoBs depending on the specific VM and compiler version it runs on. A "static" SBoB for a library is therefore an approximation at best.

Conversely, dynamic analysis (observing the application as it runs) suffers from the coverage problem. No test suite exercises every possible state space or error-handling path.

The conclusion is unavoidable: we will likely rely on a combination of static analysis, dynamic observation, and manual review to build a BoB for behavioral security. This is actively developing at the moment, you may see crucial updates at billofbehavior.com

## The Dynamic Generation Blueprint

To generate a pragmatic SBoB for a complex application, we can follow a three-step blueprint:

**Step 1: Generated SBoBs per Dependency**
In a perfect world, library vendors would ship a BoB. In reality, we won't have that anytime soon. Instead, we must generate them ourselves. At the library scope, this is tractable. We need a way to map abstract Java bytecode execution paths to concrete Linux syscall boundaries. 

A practical way to start this "exercise" today is by using tools like **Inspektor Gadget**. By running a library through a harness that forces execution down all branches while tracing with the `trace_exec` or `trace_open` gadgets, you can begin to catalog the resulting syscall profile. This can be combined with existing feedback-directed fuzzing tools like **JQF (Java QuickCheck Foundation)**, random test generators like **Randoop**, or AI-driven generators like **Diffblue Cover**. By isolating this generation at the dependency level, we create a baseline. Without this, trying to trigger every possible branch across a full application to map behavior is unrealistic.

**Step 2: Dynamic Coverage for the App**
We then observe the application's behavior dynamically to capture the framework-level wiring and emergent behavior. This requires a multi-layered approach to maximize coverage:
*   **Integration Tests:** Exercising known business logic.
*   **Chaos Inputs:** Feeding malformed or unexpected data to trigger error-handling paths.
*   **Production Shadow Traffic Recording:** Replaying real-world traffic in a controlled staging environment.
*   **API Fuzzing:** Using tools like **EvoMaster**, which uses evolutionary algorithms to automatically generate test cases. It explores your REST API endpoints, generates complex inputs, and learns from responses to maximize code coverage.

*(It is critical to explicitly acknowledge the blind spots here: REST fuzzers won't trigger asynchronous behaviors driven by Kafka consumers, scheduled background jobs, file watchers, or administrative endpoints. These require dedicated, workload-specific observation.)*

**Step 3: Merge, Then Prune**
We combine the static library SBoBs with the dynamic application profile. However, this step introduces a critical architectural challenge.

## The Merge Fallacy

The most common mistake in defining security capabilities is the naive merge. 

If you simply concatenate the SBoBs of all dependencies, you produce a bloated super-permission set. Consider the AWS SDK. The SDK's static SBoB correctly declares that it *may* open outbound connections to S3, DynamoDB, and SQS. 

If your application only uses the SDK to write to DynamoDB, but you naively merge the SDK's SBoB into your application's profile, you have just granted your application permission to talk to S3 and SQS. You have re-introduced exactly the broad, permissive boundaries that SBoB was supposed to eliminate.

A useful SBoB must represent the application's *actual* behavior, not the theoretical maximum behavior of its dependencies. This means the merged profile must be aggressively pruned.

## Lazy Init, Hot Reload, Dynamic Config — the Honest Limits

To make enforcement practical, we rely on establishing a steady-state. Kubernetes readiness probes give us a clean boundary: there is an initialization phase (where behavior is complex and broad) and a steady-state phase (where behavior should be narrow and predictable).

This model forces us to acknowledge several honest limitations and anti-patterns in modern Java development:

*   **Lazy Initialization:** Deferring the initialization of heavy components (like establishing database connection pools or warming caches) until the first tenant logs in—hours after startup—is fundamentally incompatible with tight steady-state SBoB enforcement. In this model, lazy initialization is an anti-pattern.
*   **Dynamic Configuration:** Hot-reloading configurations, toggling feature flags, or pushing hot deploys break the steady-state assumption. If behavior can change arbitrarily without a restart, creating a restrictive, static behavioral contract is nearly impossible.

These are the current limits of the approach. Adopting strict behavioral contracts requires architectural discipline.

## GraalVM as the Best-Case PoC Platform

If standard JVMs make generating and pruning an SBoB incredibly difficult, where do we prove the concept? **GraalVM Native Image.**

GraalVM is not the only path forward, but it is currently the cleanest platform to prove the concept and the strongest argument for a Proof of Concept (PoC).

**Dead Code Elimination (DCE)**
GraalVM's aggressive Dead Code Elimination is not primarily a security feature, but it meaningfully shrinks the attack surface. More importantly, DCE provides a mechanical basis for pruning the "Merge Fallacy" permissions. If every capability in a library's SBoB carries stacktrace attribution, and GraalVM's compiler statically eliminates the code at the tip of that stacktrace (because your app doesn't use S3), the associated capability can be mechanically, confidently dropped from the final SBoB. While this exact tooling does not exist yet, GraalVM provides the foundational architecture to build it. This is precisely the PoC opportunity.

**Reachability Metadata**
The GraalVM ecosystem has spent years solving the dynamic proxy, reflection, and JNI resolution problem through Reachability Metadata. Instead of reinventing how to trace dynamic behavior, a robust SBoB generation tool can piggyback on this maturity.

**eBPF Visibility via Native Binaries and DWARF Symbols**
Profiling a standard JVM with eBPF is incredibly noisy because of the JIT compiler. The JIT constantly executes syscalls like `mmap` (requesting `PROT_EXEC` memory) and `mprotect` to allocate, optimize, and manage dynamically generated bytecode. A GraalVM native binary bypasses this entirely, acting like a standard, predictable Linux executable. 

While DWARF support in GraalVM is still an emerging area—aligning symbols perfectly with kernel-level eBPF tracing tools remains a complex challenge today—it represents the most promising path toward deep, clean introspection. By treating the application as a static binary, we move closer to the "golden image" of behavioral security.

Furthermore, this AOT (Ahead-of-Time) approach allows the application to fully benefit from hardware-level **Control Flow Integrity (CFI)** features—such as **Intel CET (Shadow Stacks)** and **ARM BTI (Branch Target Identification)**—which are notoriously difficult to implement in dynamic JIT-compiled runtimes that must constantly modify executable memory. GraalVM transforms the JVM from a dynamic moving target into a hardened, static fortress that the CPU can physically protect.

**The Counter-Argument**
The obvious counter-argument is: *"Most Java applications don't run on GraalVM Native Image yet."*

This is true. But the demand for rigorous security is becoming another serious reason to reconsider. Teams that dismiss GraalVM outright are implicitly stating they don't prioritize security hardening. Some engineering organizations will. Those teams are the early adopters and the first customers for this level of behavioral enforcement.
