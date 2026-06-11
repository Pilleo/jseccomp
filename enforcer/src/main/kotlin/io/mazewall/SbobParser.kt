package io.mazewall

import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
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
        base: Policy<*> = Policy.PURE_COMPUTE_UNSAFE,
    ): Policy<*> {
        return parseJsonToPolicy(Files.readString(path), base)
    }

    /**
     * Parses a Bill of Behavior from a JSON input stream and applies it to a base policy.
     */
    fun parseToPolicy(
        stream: InputStream,
        base: Policy<*> = Policy.PURE_COMPUTE_UNSAFE,
    ): Policy<*> {
        val content = stream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        return parseJsonToPolicy(content, base)
    }

    /**
     * Parses an SBoB JSON string and generates a [Policy].
     */
    fun parseJsonToPolicy(
        json: String,
        base: Policy<*> = Policy.PURE_COMPUTE_UNSAFE,
    ): Policy<*> {
        val arrays = extractStringArrays(json)
        val opens = arrays["opens"] ?: emptySet()
        val fsWritePaths = arrays["fsWritePaths"] ?: emptySet()
        val syscallNames = arrays["syscalls"] ?: emptySet()

        val mappedSyscalls =
            syscallNames
                .mapNotNull { name ->
                    try {
                        Syscall.valueOf(name.uppercase())
                    } catch (ignored: IllegalArgumentException) {
                        null
                    }
                }.toSet()

        @Suppress("UNCHECKED_CAST")
        val builder = Policy.builder().base(base as Policy<PolicyScope>)

        if (base.defaultAction == SeccompAction.ACT_ALLOW) {
            val toUnblock =
                mappedSyscalls.filter { base.syscallActions.containsKey(it) }
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

        val sortedPaths = paths.map { Paths.get(it).toAbsolutePath().normalize() }.sorted()
        val result = mutableListOf<Path>()
        var currentParent: Path? = null

        for (path in sortedPaths) {
            if (currentParent == null || !path.startsWith(currentParent)) {
                result.add(path)
                currentParent = path
            }
        }
        return result.map { it.toString() }.toSet()
    }

    private fun extractStringArrays(json: String): Map<String, Set<String>> {
        val result = mutableMapOf<String, Set<String>>()
        val tokenizer = JsonTokenizer(json)
        tokenizer.skipWhitespace()

        if (tokenizer.pos < json.length && json[tokenizer.pos] == '{') {
            tokenizer.pos++
            while (tokenizer.pos < json.length) {
                tokenizer.skipWhitespace()
                if (tokenizer.pos < json.length && json[tokenizer.pos] == '}') {
                    tokenizer.pos++
                    break
                }
                val key = tokenizer.parseString()
                tokenizer.skipWhitespace()
                if (tokenizer.pos < json.length && json[tokenizer.pos] == ':') {
                    tokenizer.pos++
                    tokenizer.skipWhitespace()
                    if (key != null && tokenizer.pos < json.length && json[tokenizer.pos] == '[') {
                        result[key] = tokenizer.parseStringArray()
                    } else {
                        tokenizer.skipValue()
                    }
                }
                tokenizer.skipWhitespace()
                if (tokenizer.pos < json.length && json[tokenizer.pos] == ',') {
                    tokenizer.pos++
                }
            }
        }
        return result
    }

    private class JsonTokenizer(
        val json: String,
    ) {
        var pos = 0

        fun skipWhitespace() {
            while (pos < json.length && json[pos].isWhitespace()) pos++
        }

        fun parseString(): String? {
            if (pos >= json.length || json[pos] != '"') return null
            pos++
            val sb = StringBuilder()
            while (pos < json.length) {
                val c = json[pos]
                if (c == '"') {
                    pos++
                    return sb.toString()
                }
                if (c == '\\') {
                    handleEscapeSequence(sb)
                } else {
                    sb.append(c)
                }
                pos++
            }
            return null
        }

        private fun handleEscapeSequence(sb: StringBuilder) {
            pos++
            if (pos < json.length) {
                val esc = json[pos]
                when (esc) {
                    '"', '\\', '/' -> sb.append(esc)
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    else -> sb.append(esc)
                }
            }
        }

        fun skipValue() {
            skipWhitespace()
            if (pos >= json.length) return
            when (json[pos]) {
                '"' -> parseString()
                '[' -> skipArray()
                '{' -> skipObject()
                else -> skipPrimitive()
            }
        }

        private fun skipArray() {
            pos++
            while (pos < json.length) {
                skipWhitespace()
                if (pos < json.length && json[pos] == ']') {
                    pos++
                    break
                }
                skipValue()
                skipWhitespace()
                if (pos < json.length && json[pos] == ',') pos++
            }
        }

        private fun skipObject() {
            pos++
            while (pos < json.length) {
                skipWhitespace()
                if (pos < json.length && json[pos] == '}') {
                    pos++
                    break
                }
                parseString() // skip key
                skipWhitespace()
                if (pos < json.length && json[pos] == ':') pos++
                skipValue()
                skipWhitespace()
                if (pos < json.length && json[pos] == ',') pos++
            }
        }

        private fun skipPrimitive() {
            while (pos < json.length && !json[pos].isWhitespace() && json[pos] != ',' && json[pos] != '}' && json[pos] != ']') pos++
        }

        fun parseStringArray(): Set<String> {
            val set = mutableSetOf<String>()
            if (pos >= json.length || json[pos] != '[') return set
            pos++
            while (pos < json.length) {
                skipWhitespace()
                if (pos < json.length && json[pos] == ']') {
                    pos++
                    break
                }
                if (pos < json.length && json[pos] == '"') {
                    val str = parseString()
                    if (str != null) set.add(str)
                } else {
                    skipValue()
                }
                skipWhitespace()
                if (pos < json.length && json[pos] == ',') pos++
            }
            return set
        }
    }
}
