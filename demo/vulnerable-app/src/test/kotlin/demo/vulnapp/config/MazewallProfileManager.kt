package demo.vulnapp.config

import io.mazewall.profiler.BillOfBehavior
import io.mazewall.profiler.Profiler
import java.nio.file.Files
import java.nio.file.Paths
import java.util.concurrent.CopyOnWriteArrayList
import java.util.logging.Logger
import jakarta.annotation.PreDestroy
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Collects [Profiler.ProfilerExecutorWrapper] instances from all service beans and compiles
 * a unified [BillOfBehavior] on application shutdown. Only active when
 * `mazewall.profile=true` — must match the gate on [MazewallTestProfileConfig].
 */
@Component
@ConditionalOnProperty(name = ["mazewall.profile"], havingValue = "true")
class MazewallProfileManager {
    private val logger = Logger.getLogger(MazewallProfileManager::class.java.name)
    private val wrappers = CopyOnWriteArrayList<Profiler.ProfilerExecutorWrapper>()

    fun register(wrapper: Profiler.ProfilerExecutorWrapper) {
        wrappers.add(wrapper)
        logger.info("Registered ProfilerExecutorWrapper to SBoB compilation pool.")
    }

    fun generateSbob(): BillOfBehavior {
        var merged = BillOfBehavior()
        for (wrapper in wrappers) {
            merged += wrapper.compileBillOfBehavior()
        }
        return merged
    }

    fun resolveSbobPath(configuredPath: String?): String {
        if (configuredPath != null && configuredPath != "/app/sbob.json") {
            return configuredPath
        }
        // Try to locate host workspace root via settings.gradle.kts
        var current = java.io.File(".").absoluteFile
        while (current.parentFile != null) {
            if (java.io.File(current, "settings.gradle.kts").exists()) {
                val hostOutputDir = java.io.File(current, "demo/output")
                if (!hostOutputDir.exists()) {
                    hostOutputDir.mkdirs()
                }
                return java.io.File(hostOutputDir, "sbob.json").absolutePath
            }
            current = current.parentFile
        }

        // If not on host, check if /app/output/ is writeable (container volume mapping)
        val containerOutputDir = java.io.File("/app/output")
        if (containerOutputDir.exists() && containerOutputDir.canWrite()) {
            return java.io.File(containerOutputDir, "sbob.json").absolutePath
        }

        // Check if /app/ is writeable
        val containerAppDir = java.io.File("/app")
        if (containerAppDir.exists() && containerAppDir.canWrite()) {
            return java.io.File(containerAppDir, "sbob.json").absolutePath
        }

        // Absolute fallback to local working directory
        return "./sbob.json"
    }

    fun saveSbobToFile(pathStr: String) {
        val merged = generateSbob()
        val path = Paths.get(pathStr)
        try {
            val parent = path.parent
            if (parent != null) {
                Files.createDirectories(parent)
            }
            Files.writeString(path, merged.toJson())
            logger.info("Successfully compiled and saved SBoB JSON to: $pathStr")

            val stacktracesPathStr = pathStr.replace(".json", "_stacktraces.json")
            val stacktracesPath = Paths.get(stacktracesPathStr)
            Files.writeString(stacktracesPath, merged.toStackTracesJson())
            logger.info("Successfully compiled and saved SBoB stacktraces JSON to: $stacktracesPathStr")
        } catch (e: Exception) {
            logger.severe("Failed to save SBoB or stacktraces to $pathStr: ${e.message}")
        }
    }

    @PreDestroy
    fun onShutdown() {
        // Only trigger auto-save if we actually have registered wrappers (i.e. we are in profiling mode)
        if (wrappers.isNotEmpty()) {
            val configuredPath = System.getProperty("mazewall.sbob.path")
            val pathStr = resolveSbobPath(configuredPath)
            logger.info("Spring Application context shutting down. Automatically compiling SBoB to $pathStr...")
            saveSbobToFile(pathStr)

            logger.info("Terminating profiling executors...")
            for (wrapper in wrappers) {
                try {
                    wrapper.shutdown()
                } catch (e: Exception) {
                    // Suppress
                }
            }
        }
    }
}
