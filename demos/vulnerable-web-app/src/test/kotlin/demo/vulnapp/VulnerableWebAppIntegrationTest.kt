package demo.vulnapp

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.nio.file.Paths
import java.util.concurrent.TimeUnit

/**
 * Integration test that uses Testcontainers to orchestrate the vulnerable web app environment
 * and runs the automated exploit suite to verify Mazewall protection.
 *
 * This replaces the legacy 'scripts/run_vulnerable_app_demo.sh'.
 */
@Testcontainers
class VulnerableWebAppIntegrationTest {

    companion object {
        private val projectRoot = Paths.get("../..").toAbsolutePath().normalize()
        private val mapper = ObjectMapper()

        @Container
        @JvmStatic
        private val unprotected: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("mazewall-unprotected", false)
                .withFileFromPath("demos/vulnerable-web-app/build/libs/vulnerable-app.jar", projectRoot.resolve("demos/vulnerable-web-app/build/libs/vulnerable-app.jar"))
                .withFileFromPath("Dockerfile", projectRoot.resolve("demos/vulnerable-web-app/Containerfile"))
        ).withExposedPorts(8080)
            .withEnv("MAZEWALL_ENABLED", "false")
            .waitingFor(Wait.forHttp("/template"))

        @Container
        @JvmStatic
        private val protected: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("mazewall-protected", false)
                .withFileFromPath("demos/vulnerable-web-app/build/libs/vulnerable-app.jar", projectRoot.resolve("demos/vulnerable-web-app/build/libs/vulnerable-app.jar"))
                .withFileFromPath("Dockerfile", projectRoot.resolve("demos/vulnerable-web-app/Containerfile"))
        ).withExposedPorts(8081)
            .withEnv("MAZEWALL_ENABLED", "true")
            .withEnv("MAZEWALL_PROFILE", "true")
            .withEnv("SERVER_PORT", "8081")
            .waitingFor(Wait.forHttp("/template"))
            .withCreateContainerCmdModifier { cmd ->
                // Apply the seccomp profile for nested sandboxing support
                cmd.hostConfig?.withSecurityOpts(listOf("seccomp=" + projectRoot.resolve("infra/dev/podman-seccomp.json")))
            }
    }

    @Test
    fun `verify exploits are blocked on protected instance and succeed on unprotected`() {
        val unprotectedUrl = "http://${unprotected.host}:${unprotected.getMappedPort(8080)}"
        val protectedUrl = "http://${protected.host}:${protected.getMappedPort(8081)}"

        println("Testing unprotected instance at $unprotectedUrl")
        val unprotectedResults = runExploits(unprotectedUrl, unprotected.containerId)

        println("Testing protected instance at $protectedUrl")
        val protectedResults = runExploits(protectedUrl, protected.containerId)

        assertExploitsSucceeded(unprotectedResults, "unprotected")
        assertExploitsBlocked(protectedResults, "protected")
    }

    private fun runExploits(baseUrl: String, containerId: String): JsonNode {
        val exploitScript = projectRoot.resolve("exploits/run_all.py").toFile()

        // Detect container engine (prefer podman, fallback to docker)
        val engine = if (System.getenv("MAZEWALL_CONTAINER_ENGINE") != null) {
            System.getenv("MAZEWALL_CONTAINER_ENGINE")
        } else {
            try {
                ProcessBuilder("podman", "--version").start().waitFor()
                "podman"
            } catch (e: Exception) {
                "docker"
            }
        }

        val process = ProcessBuilder("python3", exploitScript.absolutePath, baseUrl)
            .apply {
                environment()["MAZEWALL_CONTAINER_ENGINE"] = engine
                environment()["MAZEWALL_UNPROTECTED_CONTAINER"] = containerId
                environment()["MAZEWALL_PROTECTED_CONTAINER"] = containerId
            }
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()

        val output = process.inputStream.bufferedReader().readText()
        val finished = process.waitFor(2, TimeUnit.MINUTES)

        if (!finished) {
            process.destroyForcibly()
            throw RuntimeException("Exploit script timed out")
        }

        return try {
            mapper.readTree(output)
        } catch (e: Exception) {
            throw RuntimeException("Failed to parse exploit results. Output was:\n$output", e)
        }
    }

    private fun assertExploitsSucceeded(results: JsonNode, label: String) {
        val failed = mutableListOf<String>()
        results.fields().forEach { (key, node) ->
            if (!node.get("succeeded").asBoolean()) {
                failed.add(key)
            }
        }
        assertTrue(failed.isEmpty(), "Exploits failed on $label instance: $failed")
    }

    private fun assertExploitsBlocked(results: JsonNode, label: String) {
        val succeeded = mutableListOf<String>()
        val outOfScope = setOf("08_sqli") // Mazewall doesn't block data-plane SQLi

        results.fields().forEach { (key, node) ->
            if (node.get("succeeded").asBoolean() && !outOfScope.contains(key)) {
                succeeded.add(key)
            }
        }
        assertTrue(succeeded.isEmpty(), "Exploits succeeded on $label instance (should have been blocked): $succeeded")
    }
}
