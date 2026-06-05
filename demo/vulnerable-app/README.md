# Mazewall Real-World CVE Exploitation Demo

This subproject demonstrates `mazewall`'s kernel-level security guarantees by running automated attacks against a Spring Boot application that has inherited real-world vulnerabilities from its dependencies.

## Vulnerability Matrix

| Attack Vector | Vulnerability | CVE / Link | Impact | Mazewall Protection (Standard JVM) |
|---------------|---------------|------------|--------|---------------------|
| **Log4Shell** | Log4j 2.14.1 | [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | RCE (Data-plane) | `Policy.NO_NETWORK` (Trapped) |
| **SnakeYAML** | SnakeYAML 2.3 | [CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471) | Deserialization RCE | Tier 1 `NO_EXEC` (Shell blocked, exfiltration possible via Thread-Hopping) |
| **XStream**   | XStream 1.4.17 | [CVE-2021-39144](https://nvd.nist.gov/vuln/detail/CVE-2021-39144) | Deserialization RCE | Tier 1 `NO_EXEC` (Shell blocked, exfiltration possible via Thread-Hopping) |
| **XXE**       | DocumentBuilder | [XXE Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) | File Exfiltration | Landlock Path Restriction (Trapped) |
| **SSRF**      | RestTemplate | [SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) | Internal Network Scanning | `Policy.NO_NETWORK` (Trapped) |
| **SSTI**      | Thymeleaf 3.x | [SSTI RCE](https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability) | Template Manipulation RCE | Tier 1 `NO_EXEC` (Shell blocked, exfiltration possible via Thread-Hopping) |
| **Zip Slip**  | ZipInputStream | [Zip Slip](https://snyk.io/research/zip-slip-vulnerability) | Arbitrary File Write | Landlock Path Restriction (Trapped) |
| **SQLi**      | JdbcTemplate | [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) | Database Compromise | *Out of Scope (Data-plane)* |

### ⚠️ The "Thread-Hopping" Exfiltration Caveat
Notice the distinction in the matrix above. For **Untrusted Data** attacks (SSRF, XXE, Log4Shell's initial JNDI lookup), Mazewall intercepts the synchronous system calls on the worker thread, providing absolute protection.

However, for attacks that grant **Arbitrary Code Execution (Java logic)** such as SnakeYAML or Thymeleaf SSTI, the attacker can use standard Java concurrency APIs like `CompletableFuture.runAsync(...)` to execute their payload on the global `ForkJoinPool`. 

Because those global threads were spawned at startup, they only inherited the process-wide **Tier 1 (`NO_EXEC`)** policy. 
1. **The Attacker CANNOT spawn a shell** (Blocked by Tier 1).
2. **The Attacker CAN exfiltrate data** by reading files or opening network sockets (Bypassing Tier 2).

This demonstrates that on a standard JIT JVM, thread-scoped containment is a highly effective shield for trusted code, but it is not a complete cage for malicious code. For absolute isolation of untrusted logic, **GraalVM Isolates** or **Wasm** are required.

## Prerequisites

- **Linux Kernel 6.2+** (required for Landlock support)
- **Podman** (preferred) or Docker with `compose` support
- **JDK 22+** (if building locally)

## Quick Start

The easiest way to execute the entire real-world CVE exploitation demo is to run our fully-automated orchestration script in the root directory:

```bash
# Execute the complete automated exploitation, report generation, and teardown
./run_vulnerable_app_demo.sh
```

This single script will build the application, start the Podman/Docker Compose environment, wait for both services to be healthy and active, run all 11 exploits against both instances, generate the Markdown verification report (`demo/vulnerable-app/report.md`), output a beautiful color-coded console summary, and cleanly terminate the OCI containers on exit.

---

## Manual Execution (Step-by-Step)

If you prefer to perform each step manually:

### 1. Build the Application
```bash
./gradlew :demo:vulnerable-app:bootJar
```

### 2. Start the Environment
This starts two instances of the same application:
- **Unprotected** (`http://localhost:8082`): Standard JVM, no Mazewall filters.
- **Protected** (`http://localhost:8081`): Scoped Mazewall filters applied to vulnerable threads.

```bash
podman compose -f demo/vulnerable-app/compose.yml up -d
```

### 3. Run Automated Exploits
Run the python exploit suite to see Mazewall in action:

```bash
# Run exploits against the unprotected instance (Expected: All succeed)
python3 exploits/run_all.py http://localhost:8082

# Run exploits against the protected instance (Expected: All RCE/IO blocked)
python3 exploits/run_all.py http://localhost:8081
```

### 4. Verify Functionality
Ensure that Mazewall hasn't broken the legitimate features of the application:

```bash
python3 exploits/health_check.py http://localhost:8081
```

### 5. Generate Comparison Report
Capture results into JSON and generate a Markdown summary:

```bash
python3 exploits/run_all.py http://localhost:8082 > unprotected.json
python3 exploits/run_all.py http://localhost:8081 > protected.json
python3 exploits/verify_results.py unprotected.json protected.json demo/vulnerable-app/report.md
```

## How It Works

The demo uses **Scoped Bean Protection**. Instead of locking down the entire Spring Boot process (which would break the embedded Tomcat), we wrap specific `ExecutorService` beans that handle untrusted parsing:

```kotlin
@Bean
fun importExecutor(): ExecutorService =
    ContainedExecutors.wrap(
        Executors.newFixedThreadPool(4),
        Policy.builder()
            .base(Policy.NO_NETWORK)
            .allowMmapExec()
            .allowFsRead("/app/data") // Landlock restriction
            .allowJvmClasspath()
            .build()
    )
```

In the controllers, we simply submit the vulnerable task to the protected executor:

```kotlin
@PostMapping("/import/yaml")
fun importYaml(@RequestBody body: String): String {
    return yamlImportService.import(body) // This runs inside the sandbox
}
```

When a malicious payload (like a SnakeYAML RCE gadget) attempts to call `Runtime.exec()`, the kernel intercepts the `execve` system call and returns `EPERM`. Mazewall catches this, logs the violation, and ensures the JVM thread remains stable.

## Future Improvements

As the core `mazewall:enforcer` library matures (specifically addressing the `OPENAT` and `PROT_EXEC` linkage issues logged in the backlog), this demo will be upgraded to demonstrate tighter constraints:

1.  **Stricter Base Policies:** We will transition the executors from `Policy.NO_NETWORK` to `Policy.PURE_COMPUTE` or `Policy.PURE_COMPUTE_UNSAFE`. This will prove that Mazewall can block advanced kernel exploitation primitives (like arbitrary `ioctl`, `mount`, or `prctl` manipulations) beyond just blocking shell execution and network access.
2.  **Simplified Configuration:** The verbose boilerplate (e.g., manually appending `.allowMmapExec()`) will be removed, proving that the built-in presets handle JVM-native linking operations safely by default.
3.  **Lazy Classloading Verification:** A dedicated endpoint will be added to force the JVM to load heavy, uninitialized libraries *inside* the strict sandbox, verifying that `allowJvmClasspath()` seamlessly permits legitimate JVM mechanics while blocking malicious path traversals.
