package demo.vulnapp

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class VulnAppApplication

fun main(args: Array<String>) {
    // Apply process-wide Tier 1 baseline BEFORE Spring Boot starts.
    // If we wait for ApplicationReadyEvent, global thread pools (like ForkJoinPool)
    // are already spawned and will not inherit the Seccomp filter, leaving us
    // vulnerable to the CompletableFuture thread-hopping bypass!
    if (System.getenv("MAZEWALL_ENABLED") == "true" || System.getProperty("mazewall.enabled") == "true") {
        println("[MAZEWALL] Initializing process-wide NO_EXEC baseline at JVM startup to prevent thread-hopping bypasses.")
        ContainedExecutors.installOnProcess(
            Policy.builder()
                .base(Policy.NO_EXEC)
                .allowMmapExec()
                .build()
        )
    }

    System.setProperty("org.springframework.boot.logging.LoggingSystem", "none")
    System.setProperty("log4j2.formatMsgNoLookups", "false")
    System.setProperty("log4j2.enableJndiLookup", "true")
    System.setProperty("log4j2.enableJndiLdap", "true")
    System.setProperty("log4j2.enableJndi", "true")
    runApplication<VulnAppApplication>(*args)
}
