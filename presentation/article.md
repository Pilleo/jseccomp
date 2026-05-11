Do You Really Know What Your App Is Doing at Runtime?
 
We have become very good at answering one specific supply-chain question:
 
What is inside this software?
 
That is what an SBOM (Software Bill of Materials) gives us. It tells us what components, packages, and libraries are packed into an application or container image. That visibility is critical. If a zero-day vulnerability lands in a popular dependency, an SBOM helps us immediately identify our exposure.
 
But the moment software is compromised, composition stops being the most important question. The real question becomes:
 
What is this software doing right now?
 
And in many cases, the honest answer is uncomfortable: we don’t really know.
 
An SBOM can tell you that a compression library is present. It cannot tell you that this same library has suddenly started interfering with authentication flows. It can tell you that a logging framework is installed. It cannot tell you that the logger is currently opening outbound network sockets. Composition transparency is valuable, but it is not behavioral transparency.
 
That gap is exactly where a new, emerging concept starts to matter: BoB—the Bill of Behavior.
 
(A quick note on expectations: This article is not a tutorial for fixing your runtime security today. BoB is still emerging, tooling is early, and standards are actively forming. What follows is a picture of where cloud-native security is heading—a direction that is becoming technically feasible and strategically hard to ignore.)
The Bouncer and the Clipboard
 
A simple analogy helps explain the shift.
 
Imagine your Kubernetes cluster is a nightclub. Your software components—the libraries, frameworks, and microservices—are the visitors inside. Some are expected to talk to each other. Some are expected to write to the filesystem. Some are allowed near the cash register. Most are not.
 
In this analogy, your runtime security layer is the bouncer.
 
And BoB is the clipboard the bouncer carries—the exact list of what each visitor is allowed to do.
 
    The web service is allowed to talk to the database.
 
    The logger is allowed to write to /var/log.
 
    The image-processing library is absolutely not allowed to spawn a shell.
 
    The JSON parser is not allowed to make external API calls.
 
To be precise, the clipboard and the bouncer are separate pieces of the architecture. BoB is the declaration. Enforcement is handled by a runtime engine that observes behavior and decides whether to alert, learn, or block. But the industry is rapidly moving toward a world where these pieces interlock: software ships with a behavioral contract, and the runtime knows exactly how to act on it.
 
Without this explicit contract, runtime security is forced into unsatisfying compromises: broad generic rules, noisy anomaly detection, or painstakingly hand-crafted policies that no development team has the time to maintain.
The Catalyst: How eBPF Changed the Game
 
For a long time, precise runtime behavioral security was too expensive, too invasive, or too brittle to apply at scale. That changed with eBPF.
 
If BoB is the clipboard, eBPF is what made the bouncer practical.
 
At a high level, eBPF gives modern Linux systems a safe, highly performant way to observe and react to what is happening at runtime. Syscalls, process executions, network behaviors, and file accesses become instantly visible and actionable.
 
A useful mental model is this: eBPF is to the Linux kernel what JavaScript is to the web browser.
 
It is a programmable extension layer. You don't have to rebuild the entire operating system every time you need a new capability. You inject carefully verified logic into a controlled runtime to observe, measure, and intervene. eBPF turned the OS from a rigid substrate into something security tools can dynamically extend.
The Runtime Security Stack Is Already Here
 
This is no longer a speculative academic exercise. The building blocks are already in production.
 
In the open ecosystem, projects like Kubescape are pushing strongly into runtime profiling for Kubernetes workloads. Using eBPF, Kubescape observes how workloads actually behave to build profiles around that behavior. This makes it a natural home for BoB-related ideas and standards.
 
On the commercial side, companies like Oligo Security have proven that library-level and application-level runtime profiling is directly useful for security operations. By observing what libraries do inside running applications, their platform uses behavioral context to detect suspicious activity.
 
The distinction here is important:
 
    Oligo proves the technical and commercial value of behavioral runtime profiling as a product.
 
    Kubescape (alongside the emerging BoB specifications from the cloud-native community) points toward an open, portable behavioral artifact that can travel with the software itself.
 
(Other tools like Tetragon, Falco, KubeArmor, Upwind, and Sweet Security also tackle adjacent parts of this space—observation, policy enforcement, and anomaly detection).
 
The message is clear: the runtime security stack is already here. What is still missing is a standardized, portable, vendor-supplied way to describe what software is expected to do.
What BoB Actually Is (and Why Vendor Authorship Matters)
 
If an SBOM is the bill of materials for software composition, a BoB (Bill of Behavior) is its behavioral companion.
 
In practical terms, a BoB captures expected runtime boundaries: network communication, file access, process execution, and Linux capabilities.
 
But the most revolutionary aspect of BoB isn't just that this profile exists. It is who authors it.
 
Today, runtime security forces the end user to infer safe behavior after deployment. Platform engineers watch logs, tune detection rules, silence false positives, and slowly assemble a fragile model of what the software seems to be doing.
 
BoB flips the script: The producer of the software should ship the first behavioral contract.
 
The vendor is the only party that actually knows what the software is intended to do, what the test coverage looks like, which behaviors are essential, and how those behaviors change across releases. Instead of forcing thousands of customers to reverse-engineer the same runtime policy from scratch, the software producer ships a reviewable baseline.
This Isn’t New—Server-Side Is Just Late
 
If declaring upfront capabilities sounds like a radical shift, it isn’t. In fact, this approach is already the standard in almost every other area of IT.
 
Think about mobile apps. An Android AndroidManifest.xml or an iOS Entitlement explicitly declares what the application is allowed to do (access the camera, read contacts, use the network). Web browsers work the same way, explicitly asking for permission before a script can access your location or clipboard. WebAssembly (Wasm) takes this even further, running in a default-deny sandbox where modules cannot touch the network or file system without explicit host capabilities being granted.
 
In this context, server-side Linux containers are the anomaly. For years, we have simply packaged software into images and let it run with whatever broad permissions the container orchestration platform allowed.
 
BoB is simply bringing capability-based security to the cloud-native server side, complete with vendor attribution.
More Than Just Better Anomaly Detection
 
It’s tempting to view BoB simply as a tool to reduce false positives in anomaly detection. And yes, instead of asking a vague statistical question—*"Is this weird?"*—the runtime can ask a concrete one: "Is this expected behavior for this specific artifact?"
 
But BoB also matters at supply-chain time.
 
If a vendor attests, “This is how our software behaves,” and your staging environment observes something materially different, you have a powerful signal. It might indicate packaging drift, tampering, or a compromised dependency acting outside its intended scope. BoB doesn't just answer if software is vulnerable; it answers if the software is behaving like the software you thought you deployed.
 
"But couldn't AI just learn normal behavior?"
 
AI will certainly play a role in inferring baselines. But purely learned, black-box models are opaque, difficult to review, hard to compare across environments, and impossible to treat as a contract. BoB makes runtime behavior explicit, reviewable, attributable, and portable. In security, a verifiable contract beats an opaque model every time.
What You Can Do Today
 
BoB is emerging, not universal. But teams don't have to wait to start adopting a "proto-BoB" mindset. You can move your architecture in a behavior-aligned direction today:
 
    Run rootless: Drop unnecessary Linux capabilities.
 
    Constrain the filesystem: Use read-only root filesystems and explicitly declare writable locations.
 
    Map the network: Enforce strict outbound network controls and map exactly which external systems a service is supposed to talk to.
 
    Draw boundaries: Separate startup behavior from steady-state behavior wherever possible, using readiness probes as practical enforcement boundaries.
 
    Audit first: Adopt runtime tooling in audit mode before moving toward strict blocking.
 
These practices don't replace BoB. They train engineering teams to think in the exact behavioral terms that BoB formalizes.
Next Up: The JVM Thought Experiment
 
In Part 2 of this series, we are going to move from theory to a concrete thought experiment: applying BoB to the Java Virtual Machine (JVM).
 
Java applications are notoriously complex at runtime. They rely heavily on reflection, dynamic proxies, classloading, JVM agents, and framework lifecycle magic. This dynamic nature makes them an incredibly interesting challenge for any behavioral contract.
 
We will explore what it would actually take to generate a meaningful BoB for a real Spring Boot application, why static analysis alone isn't enough, and why platforms like GraalVM might make this seemingly impossible task surprisingly tractable.
Final Thought
 
SBOM gave us composition transparency. BoB is the beginning of behavioral transparency.
 
eBPF made the runtime observable. Tooling has proven that this visibility translates into real security value. BoB is the missing link that turns that value into a portable, vendor-supplied part of the software supply chain.