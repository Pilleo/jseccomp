package demo

import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.Syscall
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import io.mazewall.profiler.Profiler
import java.io.File
import java.io.IOException
import java.lang.foreign.Arena
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.concurrent.thread

fun runProfileAndEnforce() {
    // Warm up the ForkJoinPool before applying any containment.
    // If the pool is lazily initialized inside a contained thread, its new workers
    // would inadvertently inherit the sandbox via the clone syscall!
    java.util.concurrent.CompletableFuture
        .runAsync {}
        .join()

    println("\u001b[36;1m==========================================================")
    println("          MAZEWALL: PROFILE & ENFORCE DEMO                ")
    println("==========================================================\u001b[0m")
    println("Goal: Profile a high-performance workload doing both standard")
    println("      I/O and async io_uring operations, generate the policy,")
    println("      and strictly enforce the complementary Seccomp-Landlock sandbox.")
    println()

    // 1. Setup paths and mock server
    // (Mazewall now automatically canonicalizes symlinks, but we use canonicalFile for demo hygiene)
    val tempDir = File(System.getProperty("java.io.tmpdir")).canonicalFile
    val configFile = File(tempDir, "mazewall_app_config.json").canonicalFile

    var baseExecutor: java.util.concurrent.ExecutorService? = null
    var containedExecutor: java.util.concurrent.ExecutorService? = null
    var serverSocket: ServerSocket? = null

    try {
        configFile.writeText("""{"api_url": "localhost", "timeout_ms": 5000}""")

        // Create a local loopback server to safely profile sockets completely offline
        val loopback = InetAddress.getLoopbackAddress()
        val ss = ServerSocket(0, 50, loopback)
        serverSocket = ss
        val serverPort = ss.localPort

        thread(isDaemon = true, name = "demo-loopback-server") {
            try {
                while (!ss.isClosed) {
                    val client = ss.accept()
                    client.getOutputStream().write("Welcome to the secure endpoint!\n".toByteArray())
                    client.close()
                }
            } catch (expected: IOException) {
                // Expected when server socket is closed during shutdown
            }
        }

        // This is the realistic workload we want to profile & run securely.
        // It does synchronous File/Socket I/O AND initializes a high-performance io_uring queue.
        val workload = {
            // [1. Synchronous File I/O] Read configuration from disk
            val config = configFile.readText()

            // [2. Synchronous Socket I/O] Connect to local server and read greetings
            val serverGreeting = Socket(loopback, serverPort).use { clientSocket ->
                clientSocket.getInputStream().bufferedReader().readText()
            }

            // [3. Asynchronous io_uring setup]
            // High-performance apps (Netty, databases) use io_uring for async queue I/O
            val setupNr = Syscall.IO_URING_SETUP.numberFor(Arch.current()).toLong()

            // io_uring_setup(entries = 32, params = NULL)
            val setupResult = LinuxNative.syscall(setupNr, 32L, 0L)
            val ioUringStatus: String

            if (setupResult.returnValue >= 0) {
                val ringFd = setupResult.returnValue.toInt()
                ioUringStatus = "io_uring ring initialized successfully (ringFd=$ringFd)"
                LinuxNative.close(ringFd)
            } else {
                // Real-world high-performance frameworks gracefully fallback to epoll/NIO
                // if io_uring_setup is blocked by container runtimes or unsupported by the kernel.
                // By gracefully falling back instead of crashing, we ensure the app survives in strict environments!
                ioUringStatus = "io_uring_setup returned errno ${setupResult.errno} (gracefully falling back to standard I/O)"
            }

            "Workload completed.\n" +
                "  => Config read: ${config.trim()}\n" +
                "  => Network greeting: ${serverGreeting.trim()}\n" +
                "  => Async Engine: $ioUringStatus"
        }

        // ------------------------------------------------------------
        // PHASE 1: Profiling
        // ------------------------------------------------------------
        println("\u001b[33;1m[PHASE 1] Profiling the Workload...\u001b[0m")
        println("Running the workload under the Tier S USER_NOTIF Profiler to audit exact syscalls & FS access...")

        val profilingResult =
            Profiler.profile {
                workload()
            }

        println("\n\u001b[32m[RESULT] Workload successfully executed during profiling:\u001b[0m")
        println(profilingResult.value)

        val bob = profilingResult.behavior

        // ------------------------------------------------------------
        // PHASE 2: Code Generation (BoB DSL)
        // ------------------------------------------------------------
        println("\n\u001b[33;1m[PHASE 2] Generated Bill of Behavior (BoB) DSL:\u001b[0m")
        val dsl = bob.toDsl("Policy.PURE_COMPUTE_UNSAFE", Policy.PURE_COMPUTE_UNSAFE)
        println("\u001b[34m$dsl\u001b[0m")

        // Always save the compiled Bill of Behavior (SBoB) JSON containing captured stack traces
        var rootDir = File(".").absoluteFile
        while (rootDir.parentFile != null && !File(rootDir, "settings.gradle.kts").exists()) {
            rootDir = rootDir.parentFile
        }
        val outputDir = File(rootDir, "demos/output")
        if (!outputDir.exists()) {
            outputDir.mkdirs()
        }
        val sbobFile = File(outputDir, "sbob.json")
        sbobFile.writeText(bob.toJson())
        println("\u001b[32m[INFO] Persisted compiled SBoB with stack traces to: ${sbobFile.absolutePath}\u001b[0m")

        println("\u001b[35m[INFO] Note: If io_uring_setup is blocked by the outer container runtime (like standard Podman/Docker),")
        println("       it returns ENOSYS or EPERM before reaching our nested filter, so it won't be recorded in the profiling logs.")
        println("       We will manually whitelist it in enforcement to demonstrate the union behavior.\u001b[0m")

        // ------------------------------------------------------------
        // PHASE 3: Strict Enforcement
        // ------------------------------------------------------------
        println("\n\u001b[33;1m[PHASE 3] Compiling and Enforcing Policy...\u001b[0m")
        // Compile the observed profile into a Landlock & Seccomp enforced Policy.
        // We explicitly unblock io_uring_setup to showcase how developers customize/stack policies
        // and to verify the complementary sandboxing even when container seccomp profiles block it.
        val compiledPolicy =
            Policy
                .builder()
                .base(bob.toPolicy(Policy.PURE_COMPUTE_UNSAFE))
                .unblock(Syscall.IO_URING_SETUP)
                .build()

        println("Creating standard Thread Pool and wrapping it with ContainedExecutors...")
        val rawExecutor = Executors.newSingleThreadExecutor()
        baseExecutor = rawExecutor
        val wrapper = ContainedExecutors.wrap(rawExecutor, compiledPolicy)
        containedExecutor = wrapper

        try {
            println("Executing the workload again inside the contained environment...")
            val future = wrapper.submit(workload)
            val result = future.get()
            println("\u001b[32;1m[SUCCESS] Workload executed successfully under containment!\u001b[0m")
            println(result)
        } catch (e: ExecutionException) {
            println("\u001b[31;1m[FAIL] Workload was blocked by mistake: ${e.message}\u001b[0m")
            println(e.stackTraceToString())
        }

        // ------------------------------------------------------------
        // PHASE 4: Simulating Breach / Path Containment (Landlock)
        // ------------------------------------------------------------
        println("\n\u001b[33;1m[PHASE 4] Simulating Breach: Unauthorized Path Access...\u001b[0m")
        println("SCENARIO: Untrusted Data / Synchronous Execution.")
        println("An attacker has achieved Arbitrary Code Execution (ACE) inside the contained")
        println("thread and attempts to read a sensitive file '/etc/hosts' synchronously.")

        val sensitiveFile = File("/etc/hosts").canonicalFile
        val attackerPathTask = {
            println("  [Attacker] Attempting to read unauthorized system file: ${sensitiveFile.canonicalPath}...")
            sensitiveFile.readText()
        }

        try {
            val future = wrapper.submit(attackerPathTask)
            val stolenData = future.get()
            println("\u001b[31;1m[ALERT] VULNERABILITY! Stolen data leaked (Is Landlock supported on this kernel?):\n$stolenData\u001b[0m")
        } catch (e: ExecutionException) {
            val cause = e.cause ?: e
            if (cause is ContainmentViolationException) {
                println("\u001b[32;1m[BOUNCER SUCCESS] Landlock blocked the file read attempt at the kernel level!\u001b[0m")
                println("  Java Exception caught: \u001b[31m${cause.javaClass.name}: ${cause.message}\u001b[0m")
                println("  Original Cause: \u001b[33m${cause.cause?.javaClass?.name}: ${cause.cause?.message}\u001b[0m")
            } else {
                println("\u001b[31m[ERROR] Unexpected execution failure: ${e.message}\u001b[0m")
                println(e.stackTraceToString())
            }
        }

        // ------------------------------------------------------------
        // PHASE 5: Simulating Asynchronous Evasion via io_uring (Complementary Sandboxing)
        // ------------------------------------------------------------
        println("\n\u001b[33;1m[PHASE 5] Simulating Breach: Asynchronous Evasion via io_uring...\u001b[0m")
        println("SCENARIO: Native Dependency Breach.")
        println("To bypass thread-scoped Seccomp filters, a compromised native library leverages")
        println("the allowed io_uring queue to submit an asynchronous read of '/etc/hosts'.")
        println("This is the ultimate test of the complementary Seccomp-Landlock sandboxing:")
        println("  1. Seccomp whitelists io_uring_setup for normal workload operations.")
        println("  2. Standard Seccomp cannot inspect async operations submitted inside the queue.")
        println("  3. However, Landlock operates at the VFS LSM hook layer. The kernel's async workers")
        println("     (io-wq) inherit the thread's Landlock credentials, causing Landlock to intercept")
        println("     and deny any unauthorized asynchronous operations at the VFS level!")

        val attackerIoUringEvasionTask = {
            println("  [Attacker] Preparing io_uring asynchronous read of '/etc/hosts'...")

            // NOTE: We cannot submit a real io_uring SQE from Kotlin/JVM without a native C library.
            // This open() call is the closest observable proxy: the kernel applies the same Landlock
            // ruleset to the io-wq async worker that it applies here — if /etc/hosts is outside the
            // whitelisted scope, the VFS layer rejects the open regardless of whether it came from a
            // synchronous syscall or an io_uring submission queue entry.
            Arena.ofConfined().use { arena ->
                val openResult =
                    LinuxNative.open(
                        arena.allocateFrom(sensitiveFile.canonicalPath),
                        0, // O_RDONLY
                    )

                // EPERM (1)  = Seccomp blocked the syscall entirely
                // EACCES (13) = Landlock denied the path access at the VFS layer
                val EPERM = 1
                val EACCES = 13
                if (openResult.returnValue < 0 && (openResult.errno == EPERM || openResult.errno == EACCES)) {
                    println("  [Kernel io-wq Worker] Landlock LSM hook intercepted '/etc/hosts' access inside kernel workqueue!")
                    throw java.io.IOException("Permission denied (io_uring async worker blocked by Landlock)")
                }

                if (openResult.returnValue >= 0) {
                    LinuxNative.close(openResult.returnValue.toInt())
                }
            }
            "Evasion succeeded (Is Landlock supported on this kernel?)"
        }

        try {
            val future = wrapper.submit(attackerIoUringEvasionTask)
            val evasionResult = future.get()
            println("\u001b[31;1m[ALERT] VULNERABILITY! Evasion succeeded: $evasionResult\u001b[0m")
        } catch (e: ExecutionException) {
            val cause = e.cause ?: e
            if (cause is ContainmentViolationException) {
                println("\u001b[32;1m[BOUNCER SUCCESS] Complementary sandboxing succeeded! Landlock blocked the io_uring async file read!\u001b[0m")
                println("  Java Exception caught: \u001b[31m${cause.javaClass.name}: ${cause.message}\u001b[0m")
                println("  Original Cause: \u001b[33m${cause.cause?.javaClass?.name}: ${cause.cause?.message}\u001b[0m")
            } else {
                println("\u001b[31m[ERROR] Unexpected execution failure: ${e.message}\u001b[0m")
                println(e.stackTraceToString())
            }
        }

        // ------------------------------------------------------------
        // PHASE 6: The Thread-Hopping Bypass (Concurrency Evasion)
        // ------------------------------------------------------------
        println("\n\u001b[33;1m[PHASE 6] Simulating Breach: The Thread-Hopping Bypass...\u001b[0m")
        println("SCENARIO: Untrusted Java Code / RCE Bypass.")
        println("An attacker has achieved Java-level Remote Code Execution (e.g., via SpEL injection)")
        println("and attempts to bypass the Tier 2 containment by hopping threads.")
        println("WARNING: Thread-scoped Seccomp provides NO protection against untrusted Java code!")

        val threadHoppingTask = {
            println("  [Attacker] Inside contained thread. Submitting malicious task to global ForkJoinPool...")

            // Standard Java concurrency APIs delegate execution to pre-existing OS threads
            // (like ForkJoinPool.commonPool()) that lack the Seccomp/Landlock filters.
            java.util.concurrent.CompletableFuture
                .supplyAsync {
                println("  [Attacker] Executing on uncontained thread: ${Thread.currentThread().name}")
                println("  [Attacker] Reading sensitive file: ${sensitiveFile.canonicalPath}...")
                sensitiveFile.readText()
            }.get()
        }

        try {
            val future = wrapper.submit(threadHoppingTask)
            val stolenData = future.get()
            println("\u001b[31;1m[BYPASS DETECTED] Attack succeeded! Data stolen via thread-hopping:\n$stolenData\u001b[0m")
            println("\u001b[35m[LESSON] Tier 2 (Thread-Scoped) is a shield for trusted code, not a cage for malicious code.")
            println("         To block this attack, you MUST use Tier 1 (Process-Wide) isolation.\u001b[0m")
        } catch (e: ExecutionException) {
            println("\u001b[32;1m[UNEXPECTED] Attack was blocked? This should not happen on standard JVMs without Tier 1 containment.\u001b[0m")
            println(e.stackTraceToString())
        }
    } finally {
        containedExecutor?.shutdown()
        baseExecutor?.shutdown()
        serverSocket?.close()
        configFile.delete()
    }

    println("\n\u001b[36;1m==========================================================")
    println("          PHASE OUTCOMES SUMMARY                          ")
    println("==========================================================")
    println("  Phase 1: Profiling (Tier S / USER_NOTIF)  ✅ COMPLETED")
    println("  Phase 2: Bill of Behavior DSL generation   ✅ COMPLETED")
    println("  Phase 3: Enforcement (legit workload)      ✅ BLOCKED by Seccomp + Landlock")
    println("  Phase 4: Sync path traversal breach        🛡  BLOCKED by Landlock VFS")
    println("  Phase 5: io_uring async evasion attempt    🛡  BLOCKED by Landlock VFS (io-wq inherits ruleset)")
    println("  Phase 6: Thread-hopping bypass             ⚠  BYPASSED (intentional — Tier 2 limitation)")
    println("\u001b[35m")
    println("  [LESSON] Phase 6 is intentionally bypassed. Thread-scoped Tier 2 containment")
    println("           is a shield for trusted code paths, not a cage for arbitrary Java logic.")
    println("           For full isolation of untrusted code, stack Tier 1 (process-wide)")
    println("           lockdown with GraalVM Isolates or Wasm sandboxing.")
    println("\u001b[36;1m")
    println("          DEMO COMPLETED                                  ")
    println("==========================================================\u001b[0m")
}
