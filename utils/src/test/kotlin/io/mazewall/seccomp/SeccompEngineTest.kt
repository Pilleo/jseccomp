package io.mazewall.seccomp

import io.mazewall.Policy
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SeccompEngineTest {

    @Test
    fun `default installOnProcess throws UnsupportedOperationException`() {
        val dummyEngine = object : SeccompEngine {
            override fun install(policy: Policy) {
                // No-op
            }
            override val isSupported: Boolean
                get() = true
        }

        val emptyPolicy = Policy.Builder().build()

        val exception = assertFailsWith<UnsupportedOperationException> {
            dummyEngine.installOnProcess(emptyPolicy)
        }

        assertEquals("Global process containment is not supported by this engine.", exception.message)
    }
}
