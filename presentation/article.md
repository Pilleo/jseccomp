Do You Really Know What Your App Is Doing at Runtime?
 
We have become very good at answering one specific supply-chain question:
 
**What is inside this software?**
 
That is what an SBOM (Software Bill of Materials) gives us. It tells us what components, packages, and libraries are packed into an application or container image. That visibility is critical. If a zero-day vulnerability lands in a popular dependency, an SBOM helps us immediately identify our exposure.
 
But the moment software is compromised, composition stops being the most important question. The real question becomes:
 
**What is this software doing right now?**
 
And in many cases, the honest answer is uncomfortable: we don’t really know.
 
An SBOM can tell you that a compression library is present. It cannot tell you that this same library has suddenly started interfering with authentication flows. It can tell you that a logging framework is installed. It cannot tell you that the logger is currently opening outbound network sockets. Composition transparency is valuable, but it is not behavioral transparency.
 
That gap is exactly where a new, emerging concept starts to matter: **BoB—the Bill of Behavior.**
 
*(A quick note on expectations: This article is not a tutorial for fixing your runtime security today. BoB is still emerging, tooling is early, and standards are actively forming. What follows is a picture of where cloud-native security is heading—a direction that is becoming technically feasible and strategically hard to ignore.)*

## From Boundaries to Contracts
 
For the last decade, cloud-native security has relied on boundaries. We wrap applications in containers, put them in namespaces, and apply global security profiles to the entire pod. This "outer shell" approach is valuable, but it is increasingly insufficient against modern, sophisticated attacks.
 
The shift we are seeing today is from **boundaries** to **contracts**.
 
In a boundary-based model, we ask: "Is this container allowed to talk to the internet?" 
In a contract-based model (BoB), we ask: "Is this specific library, at this specific moment, allowed to perform this specific action?"
 
To be precise, BoB is the declaration—the clipboard of expected behaviors. Enforcement is handled by a runtime engine that observes behavior and decides whether to alert, learn, or block. But the industry is rapidly moving toward a world where these pieces interlock: software ships with a behavioral contract, and the runtime knows exactly how to act on it.
 
Without this explicit contract, runtime security is forced into unsatisfying compromises: broad generic rules, noisy anomaly detection, or painstakingly hand-crafted policies that no development team has the time to maintain.

## The Catalyst: Practical Runtime Observation with eBPF
 
For a long time, precise runtime behavioral security was too expensive, too invasive, or too brittle to apply at scale. That changed with eBPF.
 
If BoB is the clipboard, eBPF is the engine that makes the observation practical.
 
At a high level, eBPF gives modern Linux systems a safe, highly performant way to observe and react to what is happening at runtime. Syscalls, process executions, network behaviors, and file accesses become instantly visible and actionable.
 
A useful mental model is this: **eBPF is to the Linux kernel what JavaScript is to the web browser.**
 
It is a programmable extension layer. You don't have to rebuild the entire operating system every time you need a new capability. You inject carefully verified logic into a controlled runtime to observe, measure, and intervene. eBPF turned the OS from a rigid substrate into something security tools can dynamically extend.
 
But it is important to distinguish between **observation** and **enforcement**. While eBPF provides the unprecedented visibility needed to *generate* a Bill of Behavior, enforcement often still relies on standard Linux primitives like Seccomp or Linux Security Modules (LSM) to physically block unauthorized actions.

## The Runtime Security Stack Is Already Here
 
This is no longer a speculative academic exercise. The building blocks are already in production.
 
In the open ecosystem, projects like **Kubescape** are pushing strongly into runtime profiling for Kubernetes workloads. Using eBPF, Kubescape observes how workloads actually behave to build profiles around that behavior. This makes it a natural home for BoB-related ideas and standards, such as the emerging **[Bill of Behavior (BoB) specification](https://github.com/k8sstormcenter/bob)**.
 
On the commercial side, companies like **Oligo Security** have proven that library-level and application-level runtime profiling is directly useful for security operations. By observing what libraries do inside running applications, their platform uses behavioral context to detect suspicious activity.
 
The message is clear: the runtime security stack is already here. What is still missing is a standardized, portable, vendor-supplied way to describe what software is expected to do.

## What BoB Actually Is (and Why Vendor Authorship Matters)
 
If an SBOM is the bill of materials for software composition, a BoB (Bill of Behavior) is its behavioral companion. In practical terms, a BoB captures expected runtime boundaries: network communication, file access, process execution, and Linux capabilities.
 
Today, runtime security forces the end user to infer safe behavior after deployment. Platform engineers watch logs, tune detection rules, silence false positives, and slowly assemble a fragile model of what the software seems to be doing.
 
BoB introduces a different model: the producer of the software should ship the first behavioral contract. 
 
The vendor is the party that actually knows what the software is intended to do, what the test coverage looks like, and which behaviors are essential. Instead of forcing thousands of customers to reverse-engineer the same runtime policy from scratch, the software producer ships a reviewable baseline. This moves runtime security from a "guess" to a **verifiable attestation of intent.**

## The First Step: VEX (Vulnerability Exploitability eXchange)
We are already seeing a "BoB-lite" emerge in the form of **VEX**. While an SBOM tells you a vulnerable library exists on your disk, a VEX document—often generated by runtime tools like **Kubescape** using eBPF—tells you if that library is actually loaded and reachable at runtime. VEX is the industry's first standardized realization that composition is a poor proxy for risk; only behavior matters.

## Beyond "Allow/Deny": Closing the Evasion Loopholes
 
It’s tempting to view BoB simply as a tool to reduce false positives in anomaly detection. And yes, instead of asking a vague statistical question—*"Is this weird?"*—the runtime can ask a concrete one: *"Is this expected behavior for this specific artifact?"*
 
But BoB also addresses the reality of modern syscall evasion. 
 
Traditional security often focuses on blocking `execve` (spawning a shell). But sophisticated attackers don't need a shell. They use **fileless malware**—malicious code that lives entirely in RAM, using Linux features like `memfd_create` to execute binaries that never touch the disk. Because there is no file, traditional disk-based scanning is blind.
 
More advanced attackers use **`io_uring`**, a high-performance asynchronous I/O API. By submitting operations via shared memory rings rather than direct syscalls, they can often "blind" traditional security monitors.
 
A BoB allows us to express fine-grained intent that stops these techniques: *"This application is strictly forbidden from using `memfd_create`, `io_uring_setup`, or mapping executable memory."* We move from blunt "allow/deny" container rules to surgical, intent-based security.

## The Concept of Scopes: When is a Behavior Expected?
 
A Bill of Behavior (BoB) isn't just a flat list of syscalls; to be effective, it must be context-aware. This is where the concept of **Scopes** becomes critical. We can categorize these into two main groups: those that are practically achievable today, and those that remain aspirational.
 
### 1. Lifecycle Scopes (The Pragmatic Path)
The most realistic way to implement Scopes is by aligning with the application's natural lifecycle. This approach is currently being implemented in **Kubescape**:
 
*   **Startup Scope:** Broad permissions needed to load configurations, establish connection pools, and initialize the JIT. This scope ends once the application passes its first health check.
*   **Runtime Scope:** A much narrower "steady-state" set of permissions. This is where the majority of an application's life is spent.
*   **Shutdown Scope:** Permissions required for graceful termination, such as flushing logs or closing connections.
 
By using Kubernetes health checks as a trigger, the runtime engine can automatically "rotate" the active security contract. This provides a clear, automated enforcement boundary that matches how developers already think about their apps.
 
### 2. Granular Scopes (The Experimental Frontier)
Beyond lifecycle phases, we can theoretically define scopes at a much deeper level. While these make for powerful Proofs of Concept (PoC), turning them into stable, production-ready technology faces significant architectural challenges:
 
*   **Process/Thread Scopes:** Restricting behavior based on which specific OS thread is executing (the core of the `jseccomp` experiment).
*   **Module/Library Scopes:** Restricting behavior based on which JAR or package is currently on the stack.
*   **Stacktrace Scopes:** Using the calling context to decide if a syscall is valid (e.g., "Allow `socket()` only if called via the AWS SDK").
 
While these granular scopes represent the "dream" of behavioral security, they often introduce high performance overhead or require deep integration with the language runtime. For now, Lifecycle Scopes remain the most viable path for widespread adoption.

## This Isn’t New—Server-Side Is Just Late
 
If declaring upfront capabilities sounds like a radical shift, it isn’t. In fact, this approach is already the standard in almost every other area of IT.
 
Think about mobile apps. An Android `AndroidManifest.xml` or an iOS Entitlement explicitly declares what the application is allowed to do (access the camera, read contacts, use the network). Web browsers work the same way, explicitly asking for permission before a script can access your location or clipboard. WebAssembly (Wasm) takes this even further, running in a default-deny sandbox where modules cannot touch the network or file system without explicit host capabilities being granted.
 
In this context, server-side Linux containers are the anomaly. BoB is simply bringing capability-based security to the cloud-native server side.

## What You Can Do Today
 
BoB is emerging, not universal. But teams don't have to wait to start adopting a "behavior-aligned" mindset. You can move your architecture in this direction today:
 
*   **Run rootless:** Drop unnecessary Linux capabilities.
*   **Constrain the filesystem:** Use read-only root filesystems and explicitly declare writable locations.
*   **Audit first:** Adopt runtime tooling like Kubescape in audit mode
 
These practices don't replace BoB. They train engineering teams to think in the exact behavioral terms that BoB formalizes.

---

### Next Up: Exploring Kernel Boundaries
 
In Part 2 of this series, we move from theory to practice. We will use a tool designed to block syscalls at the thread level to explore the fundamental principles of kernel-level security. 
 
Using the Java Virtual Machine (JVM) as our laboratory, we will see how to surgically neutralize threats like shellcode injection while maintaining application stability. This hands-on exploration will help you understand the core mechanics that modern security modules (like LSM) rely on to enforce behavioral integrity.
 
**[Read Part 2: Hands-on with Syscall Enforcement](#)** (Coming Soon)
