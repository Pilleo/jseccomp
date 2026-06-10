package io.mazewall

import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.stringPattern
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class PolicyCombinePropertyTest {
    // Generator for valid absolute Linux paths
    private val pathArb = Arb.stringPattern("/[a-z]{1,5}(/[a-z]{1,5})?")

    private val policyArb = arbitrary {
        val reads = Arb.list(pathArb, 0..3).bind()
        val writes = Arb.list(pathArb, 0..3).bind()
        val enforce = Arb.boolean().bind()

        val builder = Policy.builder()
        reads.forEach { builder.allowFsRead(it) }
        writes.forEach { builder.allowFsWrite(it) }
        // If we force enforce, we need at least one path to avoid the "collapse to empty" warning turning into a hard block
        if (enforce && reads.isEmpty() && writes.isEmpty()) {
            builder.allowFsRead("/default")
        }
        builder.build()
    }

    @Test
    fun `combining policies correctly intersects landlock paths`() =
        runBlocking {
        // We will generate 3 random policies and combine them.
        checkAll(policyArb, policyArb, policyArb) { p1, p2, p3 ->
            val combined = Policy.combine(p1, p2, p3)

            // If none of the policies enforce landlock, the combined shouldn't (unless one has paths)
            val expectedEnforce = p1.enforceLandlock || p2.enforceLandlock || p3.enforceLandlock
            combined.enforceLandlock shouldBe expectedEnforce

            // For paths, if ANY policy has paths, the result must be an intersection.
            // If the intersection is empty but Landlock is enforced, it means they contradicted.
            // This is a complex property to assert mathematically without duplicating the exact logic,
            // so we assert a core invariant: ANY path allowed in the combined policy MUST be allowed
            // (or have a parent allowed) in ALL input policies that defined read paths.

            val inputsWithReads = listOf(p1, p2, p3).filter { it.allowedFsReadPaths.isNotEmpty() }

            if (inputsWithReads.isNotEmpty()) {
                combined.allowedFsReadPaths.forEach { combinedPath ->
                    inputsWithReads.forEach { inputPolicy ->
                        val isAllowed = inputPolicy.allowedFsReadPaths.any { inputPath ->
                            isParentOrEqual(inputPath, combinedPath)
                        }
                        isAllowed shouldBe true
                    }
                }
            }
        }
    }

    private fun isParentOrEqual(
        parent: String,
        child: String,
    ): Boolean {
        if (parent == child) return true
        val parentWithSlash = if (parent.endsWith("/")) parent else "$parent/"
        return child.startsWith(parentWithSlash)
    }
}
