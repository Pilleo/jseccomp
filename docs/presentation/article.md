# Do You Really Know What Your App Is Doing at Runtime?
![maze_security_walls_new.png](maze_security_walls_new.png)
> **Series overview:** This is Part 1 of our series on behavioral security for cloud-native applications.
 
We have become very good at answering one specific supply-chain question:
 
**What is inside this software?**
 
That is what an [SBOM](https://www.cisa.gov/sbom) (Software Bill of Materials) gives us. It tells us what components, packages, and libraries are packed into an application or container image. That visibility is critical. If a zero-day vulnerability lands in a popular dependency, an SBOM helps us immediately identify our exposure.
 
But the moment software is compromised, composition stops being the most important question. The real question becomes:
 
**What is this software doing right now?**
 
And in many cases, the honest answer is uncomfortable: we don’t really know.
 
An SBOM can tell you that a compression library is present. It cannot tell you that this same library has suddenly started interfering with authentication flows. It can tell you that a logging framework is installed. It cannot tell you that the logger is currently opening outbound network sockets. Composition transparency is valuable, but it is not behavioral transparency.

**1. The Composition View (SBOM)**
```mermaid
graph TD
    A[Container Image] --> B[Dependencies]
    B --> C[log4j.jar]
    B --> D[netty.jar]
```

**2. The Behavioral View (SBoB)**
```mermaid
graph TD
    A[Running Application] -->|Allowed Read| B[ /app/config ]
    A -->|Allowed Connect| C[ API Server ]
    A -.->|Blocked Exec| D[ /bin/sh ]
```

That gap is exactly where a new, emerging concept starts to matter: **SBoB—the Software Bill of Behavior.**

## From Boundaries to Contracts

For the last decade, cloud-native security has relied on **boundaries**—wrapping apps in containers and namespaces, applying a global security profile at the outer shell. 

But for developers, this boundary model has a fundamental blind spot: it treats the runtime like an **open field surrounded by a perimeter fence**. The internal "walls" (your code's modules and architecture) are structurally present, but provide zero physical enforcement. If an attacker achieves [Arbitrary Code Execution (ACE)](https://en.wikipedia.org/wiki/Arbitrary_code_execution) inside the application, they can wander freely within the fence, exfiltrate data, or execute payload code. 

```mermaid
graph LR
    subgraph Field ["Boundary Model (Open Field)"]
        Attacker1((Attacker)) -->|Access Any System Resource| Sys1[Sensitive Files: /etc/passwd]
        Attacker1 -->|Access Any Process| Shell1[System Shell]
    end

    subgraph Maze ["Contract Model (Runtime Maze)"]
        Attacker2((Attacker)) -.->|Blocked by Landlock| Sys2[Sensitive Files: /etc/passwd]
        Attacker2 -.->|Blocked by Seccomp| Shell2[System Shell]
        Attacker2 -->|Allowed Path| DB2[(Application Database)]
    end
```

The shift to **contracts** (SBoB) turns the OS from a passive boundary fence into an **active runtime maze**.

Every legitimate path through your code becomes a corridor; every system call, filesystem path, or socket access is a locked gate. Under this contract:
1. **The Sandbox is a Maze:** An attacker who compromises a worker [thread](https://www.baeldung.com/cs/process-vs-thread) cannot wander to forbidden system calls or sensitive files—they are physically blocked by the nearest wall (e.g., [Seccomp](https://docs.docker.com/engine/security/seccomp/) or [Landlock](https://landlock.io/)).
2. **The OS Enforces the Logic:** The kernel actively verifies that execution strictly matches the application's expected topology.

We move from asking *"Is this container allowed to talk to the internet?"* to *"Is this specific library, at this specific millisecond, allowed to perform this specific system call?"*

*(A quick note on scope: SBoB is still emerging, tooling is early, and standards are actively forming. What follows is a picture of where cloud-native security is heading — a direction that is becoming technically feasible and strategically hard to ignore.)*

## The Catalyst: Practical Runtime Observation with eBPF
 
For a long time, precise runtime behavioral security was too expensive, too invasive, or too brittle to apply at scale. That changed with [eBPF](https://ebpf.io/what-is-ebpf/).
 
If the SBoB is the clipboard, eBPF is the engine that makes the observation practical.
 
At a high level, eBPF gives modern Linux systems a safe, highly performant way to observe and react to what is happening at runtime. Syscalls, process executions, network behaviors, and file accesses become instantly visible and actionable.

A common mental model for backend developers is this: **eBPF is to the Linux kernel what JavaScript is to the web browser** — a sandboxed, event-driven programmability layer. The critical disanalogy: eBPF programs are **statically verified by the kernel before execution** — non-terminating loops and unsafe memory accesses are rejected at load time. It attaches to kernel events (system calls, file opens, network activity) without requiring custom kernel modules. eBPF turned the OS from a rigid substrate into something security tools can dynamically extend.

But it is important to distinguish between **observation** and **enforcement**. While eBPF provides the visibility needed to generate and enforce a Bill of Behavior, physical enforcement often relies on a different set of core Linux primitives. This distinction is critical because of a fundamental architectural trade-off: **Privilege.** 

While eBPF-based enforcement (like BPF-LSM) is extremely powerful, it requires high system privileges (`CAP_SYS_ADMIN` or `CAP_BPF`). In contrast, Seccomp and Landlock are designed to be **unprivileged**, allowing a standard application to "self-restrict" its own capabilities (once `PR_SET_NO_NEW_PRIVS` is set) without needing root access or cluster-level agents. This makes them the ideal "fast path" for developer-driven security.

```mermaid
graph TD
    UserSpace[User Space: Application] -->|1. Issues Syscall| SyscallEntry[Kernel: Syscall Entry]
    
    subgraph Kernel ["Linux Kernel Boundary"]
        SyscallEntry -->|2. Evaluate| Seccomp{Seccomp Filter}
        Seccomp -->|Denied| EPERM[Return EPERM / Kill Thread]
        Seccomp -->|3. Allowed| Landlock{Landlock LSM}
        
        Landlock -->|Denied| EACCES[Return EACCES]
        Landlock -->|4. Allowed| Exec[Syscall Execution]
        
        Exec -->|5. Trigger Hook| eBPF[eBPF Tracepoint / kprobe]
    end
    
    eBPF -.->|6. Async Event| Logs[User Space: Security Logs / Alerts]
    Exec -->|7. Return Value| UserSpace
```

## This Isn't New—Server-Side Is Just Late
 
If declaring upfront capabilities sounds like a radical shift, it isn't. In fact, this approach is already the standard in almost every other area of IT.
 
Think about mobile apps. An Android `AndroidManifest.xml` or an iOS Entitlement explicitly declares what the application is allowed to do (access the camera, read contacts, use the network). Web browsers work the same way, explicitly asking for permission before a script can access your location or clipboard. WebAssembly (Wasm) takes this even further, running in a default-deny sandbox where modules cannot touch the network or file system without explicit host capabilities being granted.
 
In this context, server-side Linux containers are the anomaly. SBoB is simply bringing capability-based security to the cloud-native server side.

## The Primitives: How SBoB Is Enforced

If SBoB is the declaration of intent, the Linux kernel provides three primary mechanisms to turn that intent into a hard boundary:

```mermaid
graph TD
    subgraph Unprivileged ["Unprivileged (Self-Restriction)"]
        Seccomp[Seccomp<br/>Scope: Syscall Numbers & Registers]
        Landlock[Landlock<br/>Scope: Filesystem Paths & TCP Ports]
    end

    subgraph Privileged ["Privileged (Root / CAP_SYS_ADMIN Required)"]
        BPF_LSM[BPF-LSM / AppArmor / SELinux<br/>Scope: Deep Kernel Hooks & Global Policies]
    end
```

### 1. Seccomp (Secure Computing)
Seccomp is the industry's "fast path" for blocking system calls. It is fast, unprivileged (via `NoNewPrivileges`), and extremely reliable. While Seccomp-BPF uses strictly constrained **Classic BPF (cBPF)** bytecode rather than the full eBPF instruction set, it remains the most widely deployed syscall filter in the world. However, it is "path-blind"—it sees the system call being made, but it cannot easily inspect the file paths or network addresses involved.
*   **Where you use it today:** You are likely using it right now. Modern web browsers like **Chrome** and **Firefox** use Seccomp to sandbox their renderer processes, ensuring that a compromised tab cannot escape to the rest of your system. Podman/Docker also apply a default Seccomp profile to every container to block high-risk operations.

### 2. Landlock
Landlock is a Linux Security Module designed specifically for unprivileged sandboxing. It provides the path-aware filesystem access control that Seccomp lacks. It operates at the inode level — after the kernel has fully resolved the path — which means it avoids the TOCTOU (time-of-check/time-of-use) race that makes pointer-based path inspection in Seccomp unreliable. An application can declare constraints dynamically (e.g., "This thread can only read from `/app/data`").
*  **Kernel & ABI Version Nuances:** Landlock degrades gracefully based on the kernel's supported ABI level (ABI v1-v3 for filesystem rules, ABI v4 for TCP limits). As of Linux Kernel 6.7, Landlock has begun expanding into networking, allowing threads to restrict themselves to specific **TCP ports** for `bind` and `connect` operations. While it currently lacks the deep IP-level or endpoint visibility of BPF-LSM, it provides a powerful, unprivileged "port-level" restrictor. However, for production systems, you must explicitly account for these kernel dependencies, as older LTS kernels (like 5.15 or 6.1) will silently ignore newer ABI features (like network filtering).

### 3. [Linux Security Modules (LSM)](https://www.redhat.com/en/topics/linux/what-is-selinux)
LSMs like AppArmor, SELinux, and the modern **BPF-LSM** provide the deepest level of security. They hook into the kernel at a very granular level, allowing for complex, context-aware rules.
*   **The Trade-off:** Unlike Seccomp or Landlock, managing LSMs usually requires high privileges (`root` or `CAP_MAC_ADMIN`). This makes them ideal for platform-level security (like Android's application sandbox or Kubernetes Pod Security Standards) but harder for individual developers to use for "self-restriction."

By combining these primitives, we move from blunt "allow/deny" container rules to surgical, intent-based security.

## The Runtime Security Stack Is Already Here
 
This is no longer a speculative academic exercise. The building blocks are already in production.
 
In the open ecosystem, projects like **Kubescape** are pushing strongly into runtime profiling for Kubernetes workloads. Using eBPF, Kubescape observes how workloads actually behave to build profiles around that behavior. This makes it a natural home for SBoB-related ideas and standards, such as the emerging **[Software Bill of Behavior specification](https://github.com/k8sstormcenter/bob)**.
 
On the commercial side, companies like **Oligo Security** have proven that library-level and application-level runtime profiling is directly useful for security operations. By observing what libraries do inside running applications, their platform uses behavioral context to detect suspicious activity.
 
The message is clear: the runtime security stack is already here. What is still missing is a standardized, portable, vendor-supplied way to describe what software is expected to do.

## What SBoB Actually Is (and Why Vendor Authorship Matters)
 
If an SBOM is the bill of materials for software composition, an SBoB (Software Bill of Behavior) is its behavioral companion. In practical terms, an SBoB captures expected runtime boundaries: network communication, file access, process execution, and Linux capabilities.
 
Today, runtime security forces the end user to infer safe behavior after deployment. Platform engineers watch logs, tune detection rules, silence false positives, and slowly assemble a fragile model of what the software seems to be doing.
 
SBoB introduces a different model: the producer of the software should ship the first behavioral contract. 
 
The vendor is the party that actually knows what the software is intended to do, what the test coverage looks like, and which behaviors are essential. Instead of forcing thousands of customers to reverse-engineer the same runtime policy from scratch, the software producer ships a reviewable baseline. This moves runtime security from a "guess" to a **verifiable attestation of intent.**

## The First Step: [VEX (Vulnerability Exploitability eXchange)](https://cyclonedx.org/capabilities/vex/)
We are already seeing a "SBoB-lite" emerge in the form of **VEX**. While an SBOM tells you a vulnerable library exists on your disk, a VEX document tells you if that library is actually loaded and reachable at runtime. VEX can be generated through multiple means — runtime observation (tools like Kubescape contribute behavioral evidence via eBPF), static analysis, or manual attestation. Regardless of how it is produced, VEX is the industry's first standardized realization that composition is a poor proxy for risk; only behavior matters.

## Beyond "Allow/Deny": Closing the Evasion Loopholes
 
It’s tempting to view SBoB simply as a tool to reduce false positives in anomaly detection. And yes, instead of asking a vague statistical question—*"Is this weird?"*—the runtime can ask a concrete one: *"Is this expected behavior for this specific artifact?"*
 
But SBoB also addresses the reality of modern syscall evasion. 
 
Traditional security often focuses on blocking `execve` (spawning a shell). But sophisticated attackers don't need a shell. They use **fileless malware**—malicious code that lives entirely in RAM, using Linux features like [`memfd_create`](https://sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/) to execute binaries that never touch the disk. Because there is no file, traditional disk-based scanning is blind.
 
More advanced attackers use [**`io_uring`**](https://unixism.net/loti/), a high-performance asynchronous I/O API. By submitting operations via shared memory rings rather than direct syscalls, they can often "blind" traditional security monitors.
 
An SBoB allows us to express fine-grained intent that stops these techniques: *"This application is strictly forbidden from using `memfd_create`, `io_uring_setup`, or mapping executable memory"* (note that blocking executable memory mapping is only possible in Ahead-of-Time runtimes like GraalVM, as explained in Part 5).

## The Concept of Scopes: When is a Behavior Expected?
 
A Software Bill of Behavior (SBoB) isn't just a flat list of syscalls; to be effective, it must be context-aware. This is where the concept of **Scopes** becomes critical. We can categorize these into two main groups: those that are practically achievable today, and those that remain aspirational.
 
### 1. Lifecycle Scopes (The Pragmatic Path)
The most realistic way to implement Scopes is by aligning with the application's natural lifecycle. This approach is currently being implemented in **Kubescape**:
 
*   **Startup Scope:** Broad permissions needed to load configurations, establish connection pools, and initialize the JIT. This scope ends once the application passes its first health check.
*   **Runtime Scope:** A much narrower "steady-state" set of permissions. This is where the majority of an application's life is spent.
*   **Shutdown Scope:** Permissions required for graceful termination, such as flushing logs or closing connections.
 
By using Kubernetes health checks as a trigger, the runtime engine can automatically "rotate" the active security contract. This provides a clear, automated enforcement boundary that matches how developers already think about their apps.
 
> [!NOTE]  
> **The Monotonicity Constraint:** In-process, unprivileged self-sandboxing via Seccomp and Landlock is strictly **monotonic**—you can only stack filters to *restrict* capabilities, never restore them. Therefore, a transition from the `Runtime` scope to the `Shutdown` scope cannot regain dropped privileges (such as network socket creation or filesystem access). Any action required during Shutdown must remain allowed during the Runtime phase. Privileged host-level agents (like Kubescape utilizing eBPF + LSM) do not have this limitation, as they operate outside the sandboxed process.

```mermaid
stateDiagram-v2
    [*] --> Startup
    
    Startup --> Runtime : Health Check Passes
    Runtime --> Shutdown : SIGTERM Received
    Shutdown --> [*]
    
    note right of Startup
        Broad Permissions:
        - Classloading
        - JIT Compilation
        - Open Config Files
    end note
    
    note right of Runtime
        Restricted Permissions:
        - Read-only DB queries
        - Active connections
        - Block new processes
    end note
    
    note right of Shutdown
        Cleanup Permissions:
        - Flush logs
        - Close sockets
    end note
```

### 2. Granular Scopes (The Experimental Frontier)
Beyond lifecycle phases, we can theoretically define scopes at a much deeper level. While these make for powerful Proofs of Concept (PoC), turning them into stable, production-ready technology faces significant architectural challenges:
 
*   **[Process/Thread](https://www.baeldung.com/cs/process-vs-thread) Scopes:** Restricting behavior based on which specific OS thread is executing (the core of the `mazewall` experiment).
*   **Module/Library Scopes:** Restricting behavior based on which JAR or package is currently on the stack.
*   **Stacktrace Scopes:** Using the calling context to decide if a syscall is valid (e.g., "Allow `socket()` only if called via the AWS SDK").
 
While these granular scopes represent the "dream" of behavioral security, they often introduce high performance overhead or require deep integration with the language runtime. For now, Lifecycle Scopes remain the most viable path for widespread adoption.

## What You Can Do Today
 
SBoB is emerging, not universal. But teams don't have to wait to start adopting a "behavior-aligned" mindset. You can move your architecture in this direction today:
 
*   **Run rootless:** Drop unnecessary Linux capabilities.
*   **Constrain the filesystem:** Use read-only root filesystems and explicitly declare writable locations.
*   **Audit first:** Adopt runtime tooling like Kubescape in audit mode
 
These practices don't replace SBoB. They train engineering teams to think in the exact behavioral terms that SBoB formalizes.

---

### Next Up: Let Your Code Build Its Own Sandbox
 
In Part 2 of this series, we move from theory to practice. We will introduce **mazewall**, a newly developed experimental Proof-of-Concept library designed to translate SBoB concepts into active JVM thread sandboxing, and demonstrate the dynamic profiling workflow that allows the application to automatically trace and define its own required system permissions.
 
**[Read Part 2: Let Your Code Build Its Own Sandbox: Introducing Mazewall](article2-profiler.md)**
