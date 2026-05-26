package io.mazewall

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * A lightweight parser for Software Bill of Behavior (SBoB) JSON files.
 * This class is designed to be used in production environments to load
 * profiling results without requiring the heavy `mazewall:profiler` module.
 */
object SbobParser {
    /**
     * Parses a Bill of Behavior from a Path pointing to an SBoB JSON file
     * and applies it to a base policy.
     */
    fun parseToPolicy(
        path: Path,
        base: Policy = Policy.PURE_COMPUTE,
    ): Policy {
        return parseJsonToPolicy(Files.readString(path), base)
    }

    /**
     * Parses a Bill of Behavior from a JSON input stream and applies it to a base policy.
     */
    fun parseToPolicy(
        stream: InputStream,
        base: Policy = Policy.PURE_COMPUTE,
    ): Policy {
        val content = stream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        return parseJsonToPolicy(content, base)
    }

    /**
     * Parses an SBoB JSON string and generates a [Policy].
     */
    fun parseJsonToPolicy(
        json: String,
        base: Policy = Policy.PURE_COMPUTE,
    ): Policy {
        val opens = parseJsonStringArray(json, "opens")
        val fsWritePaths = parseJsonStringArray(json, "fsWritePaths")
        val syscallNames = parseJsonStringArray(json, "syscalls")

        val mappedSyscalls =
            syscallNames
                .mapNotNull { name ->
                    try {
                        Syscall.valueOf(name.uppercase())
                    } catch (ignored: Exception) {
                        null
                    }
                }.toSet()

        val builder = Policy.builder().base(base)

        if (base.mode == Policy.Mode.DENY_LIST) {
            val toUnblock =
                mappedSyscalls.filter { base.syscalls.contains(it) }
            builder.unblock(*toUnblock.toTypedArray())
        } else {
            builder.allow(*mappedSyscalls.toTypedArray())
        }

        val prunedOpens = pruneSubpaths(opens)
        val prunedWrites = pruneSubpaths(fsWritePaths)

        for (path in prunedOpens) builder.allowFsRead(path)
        for (path in prunedWrites) builder.allowFsWrite(path)

        return builder.build()
    }

    private fun pruneSubpaths(paths: Set<String>): Set<String> {
        if (paths.size <= 1) return paths

        val parsedPaths = paths.map { Paths.get(it).toAbsolutePath().normalize() }
        val result = mutableListOf<Path>()

        for (path in parsedPaths) {
            val hasParent =
                parsedPaths.any { other ->
                    other != path && path.startsWith(other)
                }
            if (!hasParent) {
                result.add(path)
            }
        }
        return result.map { it.toString() }.toSet()
    }

    private fun parseJsonStringArray(
        json: String,
        key: String,
    ): Set<String> {
        val index = json.indexOf("\"$key\"")
        val openBracket = if (index != -1) json.indexOf("[", index) else -1
        val closeBracket = if (openBracket != -1) json.indexOf("]", openBracket) else -1

        if (closeBracket != -1) {
            val arrayContent = json.substring(openBracket + 1, closeBracket)
            if (arrayContent.isNotBlank()) {
                return parseStringArrayContent(arrayContent)
            }
        }
        return emptySet()
    }

    private fun parseStringArrayContent(arrayContent: String): Set<String> {
        val result = mutableSetOf<String>()
        val regex = "\"([^\"\\\\]|\\\\.)*\"".toRegex()
        for (match in regex.findAll(arrayContent)) {
            val value = match.value
            val contentOnly = value.substring(1, value.length - 1)
            val unescaped = contentOnly.replace("\\\"", "\"").replace("\\\\", "\\")
            result.add(unescaped)
        }
        return result
    }
}
