package io.contained.profiler

data class TraceEvent(
    val pid: Int,
    val syscallName: String,
    val args: LongArray,
    val paths: List<String>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TraceEvent) return false
        if (syscallName != other.syscallName) return false
        if (!args.contentEquals(other.args)) return false
        if (paths != other.paths) return false
        return true
    }

    override fun hashCode(): Int {
        var result = syscallName.hashCode()
        result = 31 * result + args.contentHashCode()
        result = 31 * result + paths.hashCode()
        return result
    }
}
