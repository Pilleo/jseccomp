package io.mazewall.profiler

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mazewall.Policy
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.profiler.engine.TraceEvent
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

private val mapper = jacksonObjectMapper()

private class BillOfBehaviorDto(
    val opens: Set<String> = emptySet(),
    val fsWritePaths: Set<String> = emptySet(),
    val syscalls: Set<String> = emptySet(),
    val execs: Set<String> = emptySet(),
    val stackProfile: List<StackProfileEntryDto> = emptyList(),
)

private class StackProfileEntryDto(
    val syscall: String,
    val paths: List<String> = emptyList(),
    val args: List<Long> = emptyList(),
    val stackTrace: List<String> = emptyList(),
)

/**
 * An immutable record of what kernel-level operations were observed during a
 * profiling run. This is the raw output of the [Profiler] — completely decoupled
 * from any [io.mazewall.Policy].
 *
 * Field naming follows the [Software Bill of Behavior (SBoB) spec draft v0.0.1](https://billofbehavior.com/bob/docs/drafts/spec-v0.0.1/):
 * - [opens]   → SBoB §4.6 `opens`
 * - [execs]   → SBoB §4.5 `execs`
 * - [syscalls] → non-standard extension; all intercepted syscall names
 *
 * ## Absent vs Explicit-Empty
 * Per SBoB §5.4, absent (null) means "unconstrained / not observed" and
 * explicit empty (emptySet()) means "observed zero activity". This class
 * always returns empty sets (never null), because a completed profiling run
 * with zero observations is a valid, meaningful result: the operation touched
 * nothing in that category.
 *
 * ## Stack profiles
 * [stackProfile] captures per-syscall JVM stack traces on a best-effort basis.
 * The worker thread is frozen in the kernel during USER_NOTIF; its Java stack
 * is stable at that moment. Frames are Java-only — no kernel frames are available.
 * This is a precursor to the SBoB stack-profile extension (spec-stackprofile-v0.0.1,
 * not yet published). The encoding will align to OTel Profiles when that extension
 * stabilises.
 *
 * ## Composability
 * Use [plus] to merge two bills from separate profiling runs into a single policy.
 */
data class BillOfBehavior(
    /**
     * Filesystem paths opened for read (open/openat/openat2 with O_RDONLY, stat,
     * readlink, etc.). Maps to SBoB §4.6 `opens` with `flags` indicating read access.
     */
    val opens: Set<String> = emptySet(),
    /**
     * Filesystem paths opened for write, created, or mutated (O_WRONLY, O_RDWR,
     * O_CREAT, O_TRUNC, mkdir, rmdir, rename, chmod, chown, etc.).
     * Maps to SBoB §4.6 `opens` with write-mode flags.
     *
     * ## Design decision: conservative write-path discovery
     * When [io.mazewall.profiler.iterative.IterativeProfiler] catches an AccessDeniedException from Landlock, the
     * exception does not reliably carry the access mode that was denied. Rather than
     * guessing, the profiler conservatively adds the denied path to BOTH [opens] and
     * [fsWritePaths]. This guarantees convergence at the cost of slightly over-permissive
     * Landlock rules — correct for a profiling tool whose goal is discovery, not enforcement.
     */
    val fsWritePaths: Set<String> = emptySet(),
    /**
     * All syscall names intercepted during the run. A superset of what any
     * specific base [io.mazewall.Policy] would block — the caller decides which subset matters
     * via [toPolicy].
     */
    val syscalls: Set<Syscall> = emptySet(),
    /**
     * Child processes spawned (execve/execveat paths). Maps to SBoB §4.5 `execs`.
     */
    val execs: Set<String> = emptySet(),
    /**
     * Per-syscall JVM stack traces captured at the moment the kernel paused the
     * worker thread for USER_NOTIF. The worker thread is blocked in-kernel and its
     * Java stack is frozen at that point — traces are accurate for Java frames.
     *
     * May be empty if profiling was done via IterativeProfiler (Tier A),
     * which does not use USER_NOTIF.
     *
     * Keyed by [TraceEvent] identity; multiple events for the same syscall name
     * may produce different stack entries if triggered from different call sites.
     */
    val stackProfile: Map<TraceEvent, List<Array<StackTraceElement>>> = emptyMap(),
) {
    /**
     * Compiles this bill of behavior into a [io.mazewall.Policy] starting from [base].
     *
     * Only syscalls that are **actually blocked** by [base] are unblocked —
     * syscalls observed but absent from the base block-list are ignored.
     * This is the correct filter: if a syscall was observed but the base
     * policy never blocked it, calling unblock() on it would be a no-op
     * at best and a footgun if the base policy changes later.
     *
     * All [opens] paths are granted read access; all [fsWritePaths] paths
     * are granted write access.
     */
    fun toPolicy(base: Policy = Policy.PURE_COMPUTE_UNSAFE): Policy {
        val builder = Policy.builder().base(base)
        if (base.defaultAction == io.mazewall.core.SeccompAction.ACT_ALLOW) {
            val toUnblock = syscalls.filter { !base.isSyscallAllowed(it) }
            builder.unblock(*toUnblock.toTypedArray())
        } else {
            builder.allow(*syscalls.toTypedArray())
        }
        val prunedOpens = pruneSubpaths(opens)
        val prunedWrites = pruneSubpaths(fsWritePaths)
        for (path in prunedOpens) builder.allowFsRead(path)
        for (path in prunedWrites) builder.allowFsWrite(path)
        return builder.build()
    }

    /**
     * Emits a copy-pasteable Kotlin DSL snippet that reproduces the compiled policy.
     * [basePolicyName] is used as the string label in the emitted code.
     */
    fun toDsl(
        basePolicyName: String = "Policy.PURE_COMPUTE_UNSAFE",
        base: Policy = Policy.PURE_COMPUTE_UNSAFE,
    ): String {
        val sb = StringBuilder()
        sb.append("val policy = Policy.builder()\n")
        sb.append("    .base($basePolicyName)\n")

        val (methodName, list) =
            if (base.defaultAction == io.mazewall.core.SeccompAction.ACT_ALLOW) {
                ".unblock" to syscalls.filter { !base.isSyscallAllowed(it) }.sortedBy { it.name }
            } else {
                ".allow" to syscalls.sortedBy { it.name }
            }

        if (list.isNotEmpty()) {
            sb.append("    $methodName(\n")
            sb.append(list.joinToString(",\n") { "        Syscall.${it.name}" })
            sb.append("\n    )\n")
        }
        val prunedOpens = pruneSubpaths(opens)
        val prunedWrites = pruneSubpaths(fsWritePaths)
        for (path in prunedOpens.sorted()) sb.append("    .allowFsRead(\"$path\")\n")
        for (path in prunedWrites.sorted()) sb.append("    .allowFsWrite(\"$path\")\n")
        sb.append("    .build()")
        return sb.toString()
    }

    private fun pruneSubpaths(paths: Set<String>): Set<String> {
        if (paths.size <= 1) return paths

        val parsedPaths = paths.map { Paths.get(it).toAbsolutePath().normalize() }.distinct()
        val result = mutableListOf<Path>()

        for (path in parsedPaths) {
            val hasChild = parsedPaths.any { other ->
                other != path && other.startsWith(path)
            }
            if (!hasChild) {
                result.add(path)
            }
        }
        return result.map { it.toString().replace('\\', '/') }.toSet()
    }

    /**
     * Merges two bills of behavior (union of all observations).
     * Useful for compiling a single policy across multiple profiling runs
     * covering different code paths of the same application.
     */
    operator fun plus(other: BillOfBehavior): BillOfBehavior {
        val mergedStackProfile = stackProfile.toMutableMap()
        for ((event, traces) in other.stackProfile) {
            val existing = mergedStackProfile[event] ?: emptyList()
            val mergedTraces = (existing + traces).distinctBy { it.toList() }
            mergedStackProfile[event] = mergedTraces
        }

        return BillOfBehavior(
            opens = opens + other.opens,
            fsWritePaths = fsWritePaths + other.fsWritePaths,
            syscalls = syscalls + other.syscalls,
            execs = execs + other.execs,
            stackProfile = mergedStackProfile,
        )
    }

    /**
     * Returns a new [BillOfBehavior] where paths matching the given [BaselinePathProfile]
     * are excluded from [opens], [fsWritePaths], and [execs].
     */
    fun filterPaths(profile: BaselinePathProfile): BillOfBehavior {
        return BillOfBehavior(
            opens = opens.filterNot { profile.matches(it) }.toSet(),
            fsWritePaths = fsWritePaths.filterNot { profile.matches(it) }.toSet(),
            syscalls = syscalls,
            execs = execs.filterNot { profile.matches(it) }.toSet(),
            stackProfile = stackProfile.filterKeys { event ->
                event.paths.none { profile.matches(it) }
            },
        )
    }

    /**
     * Serializes this Bill of Behavior into a clean SBoB JSON string.
     */
    fun toJson(): String {
        val prunedOpens = pruneSubpaths(opens).sorted().toSet()
        val prunedWrites = pruneSubpaths(fsWritePaths).sorted().toSet()
        val sortedSyscalls = syscalls.sortedBy { it.name }.map { it.name }.toSet()
        val sortedExecs = execs.sorted().toSet()

        val stackEntries = stackProfile.entries.sortedBy { it.key.syscallName }
        val stackProfileDtos = stackEntries.flatMap { (event, tracesList) ->
            tracesList.map { frames ->
                StackProfileEntryDto(
                    syscall = event.syscallName,
                    paths = event.paths,
                    args = event.args.toList(),
                    stackTrace = frames.map { it.toString() },
                )
            }
        }

        val dto = BillOfBehaviorDto(
            opens = prunedOpens,
            fsWritePaths = prunedWrites,
            syscalls = sortedSyscalls,
            execs = sortedExecs,
            stackProfile = stackProfileDtos,
        )

        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(dto)
    }

    /**
     * Serializes only the stackTrace data into a beautifully formatted JSON array.
     */
    fun toStackTracesJson(): String {
        val stackEntries = stackProfile.entries.sortedBy { it.key.syscallName }
        val stackProfileDtos = stackEntries.flatMap { (event, tracesList) ->
            tracesList.map { frames ->
                StackProfileEntryDto(
                    syscall = event.syscallName,
                    paths = event.paths,
                    args = event.args.toList(),
                    stackTrace = frames.map { it.toString() },
                )
            }
        }
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(stackProfileDtos)
    }

    companion object {
        /**
         * Parses a Bill of Behavior from a Path pointing to an SBoB JSON file.
         */
        fun fromFile(path: Path): BillOfBehavior {
            return fromJson(Files.readString(path))
        }

        /**
         * Parses a Bill of Behavior from a JSON input stream.
         */
        fun fromStream(stream: InputStream): BillOfBehavior {
            val content = stream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
            return fromJson(content)
        }

        /**
         * Parses a Bill of Behavior from an SBoB JSON string.
         */
        fun fromJson(json: String): BillOfBehavior {
            val dto = mapper.readValue(json, BillOfBehaviorDto::class.java)

            val mappedSyscalls = dto.syscalls
                .mapNotNull { name ->
                try {
                    Syscall.valueOf(name.uppercase())
                } catch (ignored: Exception) {
                    null
                }
            }.toSet()

            val stackProfile = mutableMapOf<TraceEvent, MutableList<Array<StackTraceElement>>>()
            for (entry in dto.stackProfile) {
                val event = TraceEvent(
                    pid = 0,
                    syscallName = entry.syscall,
                    args = entry.args.map { it }.toLongArray(),
                    paths = entry.paths,
                )
                val frames = entry.stackTrace.map { parseStackTraceElement(it) }.toTypedArray()
                stackProfile.getOrPut(event) { mutableListOf() }.add(frames)
            }

            return BillOfBehavior(
                opens = dto.opens,
                fsWritePaths = dto.fsWritePaths,
                syscalls = mappedSyscalls,
                execs = dto.execs,
                stackProfile = stackProfile,
            )
        }

        /**
         * Parses a string produced by [StackTraceElement.toString].
         *
         * Format (all optional segments in brackets):
         * ```
         * [classLoaderName/][moduleName[@version]/]className.methodName(fileName[:lineNumber])
         * ```
         *
         * Examples:
         * - `io.mazewall.Profiler.profile(Profiler.kt:152)`
         * - `java.base/java.lang.Thread.run(Thread.java:1583)`
         * - `app/io.mazewall@1.0/io.mazewall.Profiler.profile(Profiler.kt:152)`
         * - `Native Method` / `Unknown Source` inside parens
         *
         * A regex is not used: the optional classloader, module, and version segments create
         * ambiguous group boundaries (e.g., `foo/bar` could be classloader+class or module+class)
         * that are more clearly disambiguated by the sequential string decomposition below.
         */
        @Suppress("ComplexMethod", "CyclomaticComplexMethod", "MagicNumber", "ReturnCount") // justified by format above
        private fun parseStackTraceElement(str: String): StackTraceElement {
            val openParen = str.indexOf('(')
            val closeParen = str.lastIndexOf(')')
            if (openParen == -1 || closeParen == -1 || closeParen < openParen) {
                return StackTraceElement("Unknown", "unknown", null, -1)
            }

            val beforeParen = str.substring(0, openParen)
            val insideParen = str.substring(openParen + 1, closeParen)

            val lastDot = beforeParen.lastIndexOf('.')
            if (lastDot == -1) {
                return StackTraceElement("Unknown", beforeParen, null, -1)
            }
            val methodName = beforeParen.substring(lastDot + 1)
            val remaining = beforeParen.substring(0, lastDot)

            val slashes = remaining.split('/')
            val className = slashes.last()

            val (classLoaderName, moduleName, moduleVersion) = when {
                slashes.size > 2 -> {
                    val cl = slashes[0]
                    val mod = slashes[1]
                    val atIdx = mod.indexOf('@')
                    if (atIdx != -1) {
                        Triple(cl, mod.substring(0, atIdx), mod.substring(atIdx + 1))
                    } else {
                        Triple(cl, mod, null)
                    }
                }
                slashes.size == 2 -> {
                    val first = slashes[0]
                    val atIdx = first.indexOf('@')
                    if (atIdx != -1) {
                        Triple(null, first.substring(0, atIdx), first.substring(atIdx + 1))
                    } else {
                        if (first.startsWith("java.") || first.startsWith("jdk.")) {
                            Triple(null, first, null)
                        } else {
                            Triple(first, null, null)
                        }
                    }
                }
                else -> Triple(null, null, null)
            }

            val (fileName, lineNumber) = when (insideParen) {
                "Native Method" -> null to -2
                "Unknown Source" -> null to -1
                else -> {
                    val colon = insideParen.lastIndexOf(':')
                    if (colon != -1) {
                        insideParen.substring(0, colon) to insideParen.substring(colon + 1).toIntOrNull()
                    } else {
                        insideParen to -1
                    }
                }
            }

            return StackTraceElement(
                classLoaderName,
                moduleName,
                moduleVersion,
                className,
                methodName,
                fileName,
                lineNumber ?: -1,
            )
        }
    }
}
