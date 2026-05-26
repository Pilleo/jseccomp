package demo.vulnapp.config

import io.mazewall.profiler.BillOfBehavior
import io.mazewall.profiler.Profiler
import io.mazewall.profiler.engine.TraceEvent
import java.nio.file.Files
import java.nio.file.Paths
import java.util.concurrent.CopyOnWriteArrayList
import java.util.logging.Logger
import jakarta.annotation.PreDestroy
import org.springframework.stereotype.Component

@Component
class MazewallProfileManager {
    private val logger = Logger.getLogger(MazewallProfileManager::class.java.name)
    private val wrappers = CopyOnWriteArrayList<Profiler.ProfilerExecutorWrapper>()

    fun register(wrapper: Profiler.ProfilerExecutorWrapper) {
        wrappers.add(wrapper)
        logger.info("Registered ProfilerExecutorWrapper to SBoB compilation pool.")
    }

    fun generateSbob(): String {
        var merged = BillOfBehavior()
        for (wrapper in wrappers) {
            merged += wrapper.compileBillOfBehavior()
        }
        return merged.toJson()
    }

    fun generateStackTracesJson(): String {
        val allEvents = mutableListOf<TraceEvent>()
        for (wrapper in wrappers) {
            allEvents.addAll(wrapper.recentLogs)
        }
        
        val sb = java.lang.StringBuilder()
        sb.append("[\n")
        val entries = allEvents.filter { it.stackTrace != null }.distinctBy { event ->
            "${event.syscallName}:${event.paths.sorted().joinToString(",")}:${event.stackTrace.hashCode()}"
        }
        
        sb.append(entries.joinToString(",\n") { event ->
            val eventSb = java.lang.StringBuilder()
            eventSb.append("  {\n")
            eventSb.append("    \"syscall\": \"${event.syscallName}\",\n")
            eventSb.append("    \"paths\": [\n")
            val pathsEscaped = event.paths.map { "      \"${escapeJson(it)}\"" }
            eventSb.append(pathsEscaped.joinToString(",\n"))
            eventSb.append("\n    ],\n")
            eventSb.append("    \"args\": [${event.args.joinToString(", ")}],\n")
            eventSb.append("    \"stackTrace\": [\n")
            val tracesEscaped = event.stackTrace!!.map { "      \"${escapeJson(it)}\"" }
            eventSb.append(tracesEscaped.joinToString(",\n"))
            eventSb.append("\n    ]\n")
            eventSb.append("  }")
            eventSb.toString()
        })
        sb.append("\n]")
        return sb.toString()
    }

    private fun escapeJson(str: String): String {
        return str.replace("\\", "\\\\").replace("\"", "\\\"")
    }

    fun saveSbobToFile(pathStr: String) {
        val json = generateSbob()
        val path = Paths.get(pathStr)
        try {
            val parent = path.parent
            if (parent != null) {
                Files.createDirectories(parent)
            }
            Files.writeString(path, json)
            logger.info("Successfully compiled and saved SBoB JSON to: $pathStr")

            val stacktracesJson = generateStackTracesJson()
            val stacktracesPathStr = pathStr.replace(".json", "_stacktraces.json")
            val stacktracesPath = Paths.get(stacktracesPathStr)
            Files.writeString(stacktracesPath, stacktracesJson)
            logger.info("Successfully compiled and saved SBoB stacktraces JSON to: $stacktracesPathStr")
        } catch (e: Exception) {
            logger.severe("Failed to save SBoB or stacktraces to $pathStr: ${e.message}")
        }
    }

    @PreDestroy
    fun onShutdown() {
        // Only trigger auto-save if we actually have registered wrappers (i.e. we are in profiling mode)
        if (wrappers.isNotEmpty()) {
            val pathStr = System.getProperty("mazewall.sbob.path") ?: "/app/sbob.json"
            logger.info("Spring Application context shutting down. Automatically compiling SBoB to $pathStr...")
            saveSbobToFile(pathStr)
        }
    }
}
